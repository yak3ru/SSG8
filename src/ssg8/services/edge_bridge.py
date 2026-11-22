"""Local-only, opt-in Edge extension bridge.

The bridge is deliberately not a proxy, a firewall, or an OS policy manager.
It accepts website attempts from an explicitly installed Edge extension and
hands them to the SSG8 GUI thread for existing event/decision processing.

Only a sanitized URL origin is passed into the application. No paths, searches,
credentials or request bodies are collected.
"""
from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from queue import Empty, Full, Queue
from urllib.parse import urlsplit

HOST = "127.0.0.1"
PORT = 48765
MAX_BODY_BYTES = 2048
MAX_QUEUE = 256


def website_origin(value: object) -> str | None:
    """Validate HTTP(S) navigation and drop private URL components."""
    if not isinstance(value, str) or len(value) > 2048:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        # Do not collect credentials, path or query strings.
        if parsed.username or parsed.password:
            return None
        port = parsed.port
    except ValueError:
        return None
    host = parsed.hostname
    if any(ch.isspace() for ch in host):
        return None
    # IPv6 hosts need square brackets around the address.
    if ":" in host:
        host = f"[{host}]"
    suffix = f":{port}" if port is not None else ""
    return f"{parsed.scheme}://{host}{suffix}/"


def extension_origin(value: str | None) -> bool:
    """Only respond to Chromium extension requests, not ordinary websites."""
    if not value or not value.startswith("chrome-extension://"):
        return False
    identifier = value.removeprefix("chrome-extension://")
    return bool(identifier) and identifier.isalnum() and len(identifier) <= 64


class EdgeBridge:
    """HTTP receiver with a thread-safe inbound queue and read-only status."""

    def __init__(self, host: str = HOST, port: int = PORT) -> None:
        self.host = host
        self.port = port
        self.attempts: Queue[str] = Queue(maxsize=MAX_QUEUE)
        self._token = secrets.token_urlsafe(28)
        self._enabled = False
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def set_website_enabled(self, enabled: bool) -> None:
        with self._lock:
            self._enabled = bool(enabled)

    def is_website_enabled(self) -> bool:
        with self._lock:
            return self._enabled

    def pop_attempt(self) -> str | None:
        try:
            return self.attempts.get_nowait()
        except Empty:
            return None

    def start(self) -> None:
        if self._server is not None:
            return
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return  # Avoid leaking URLs to console logs.

            def _headers(self, status: int, origin: str | None = None) -> None:
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                if origin and extension_origin(origin):
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")
                    self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                    self.send_header("Access-Control-Allow-Headers", "Content-Type, X-SSG8-Token")
                self.end_headers()

            def _reply(self, status: int, data: dict, origin: str | None = None) -> None:
                output = json.dumps(data).encode("utf-8")
                self._headers(status, origin)
                self.wfile.write(output)

            def _verified_origin(self) -> str | None:
                value = self.headers.get("Origin")
                return value if extension_origin(value) else None

            def do_OPTIONS(self) -> None:  # noqa: N802
                origin = self._verified_origin()
                self._headers(204 if origin else 403, origin)

            def do_GET(self) -> None:  # noqa: N802
                origin = self._verified_origin()
                if self.path != "/status" or not origin:
                    self._reply(403, {"error": "Forbidden"})
                    return
                self._reply(200, {
                    "online": True,
                    "website_enabled": owner.is_website_enabled(),
                    "token": owner._token,
                }, origin)

            def do_POST(self) -> None:  # noqa: N802
                origin = self._verified_origin()
                if self.path != "/attempt" or not origin:
                    self._reply(403, {"error": "Forbidden"})
                    return
                if not secrets.compare_digest(
                    self.headers.get("X-SSG8-Token", ""), owner._token
                ):
                    self._reply(403, {"error": "Invalid session"}, origin)
                    return
                length_text = self.headers.get("Content-Length", "")
                if not length_text.isdigit() or not 0 < int(length_text) <= MAX_BODY_BYTES:
                    self._reply(413, {"error": "Invalid request size"}, origin)
                    return
                try:
                    body = json.loads(self.rfile.read(int(length_text)))
                    target = website_origin(body.get("url"))
                except (ValueError, AttributeError, TypeError):
                    target = None
                if target is None:
                    self._reply(400, {"error": "Invalid URL"}, origin)
                    return
                try:
                    owner.attempts.put_nowait(target)
                except Full:
                    self._reply(429, {"error": "Busy"}, origin)
                    return
                self._reply(202, {"accepted": True}, origin)

        server = ThreadingHTTPServer((self.host, self.port), Handler)
        server.daemon_threads = True
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, daemon=True, name="SSG8EdgeBridge"
        )
        self._thread.start()

    def stop(self) -> None:
        server, self._server = self._server, None
        if server is not None:
            server.shutdown()
            server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
