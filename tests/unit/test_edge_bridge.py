"""Read-only local Edge bridge tests; no GUI or Windows dependency."""
from __future__ import annotations

import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from ssg8.services.edge_bridge import EdgeBridge, extension_origin, website_origin

ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"


def request(url: str, *, origin: str | None = ORIGIN, method: str = "GET", token: str = "", body: dict | None = None):
    headers = {}
    if origin is not None:
        headers["Origin"] = origin
    if token:
        headers["X-SSG8-Token"] = token
    payload = None
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(url, data=payload, method=method, headers=headers)
    try:
        with urlopen(req, timeout=3) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.loads(error.read())


def test_url_sanitization_removes_path_query_and_fragment():
    assert website_origin("https://youtube.com/watch?v=secret#section") == "https://youtube.com/"
    assert website_origin("http://127.0.0.1:8080/private?x=abc") == "http://127.0.0.1:8080/"
    assert website_origin("file:///etc/hosts") is None
    assert website_origin("https://user:password@example.com/") is None
    assert website_origin("not a URL") is None
    assert website_origin("https://example.com:bad/") is None


def test_extension_origin_validated():
    assert extension_origin(ORIGIN)
    assert not extension_origin("https://evil.test")
    assert not extension_origin("chrome-extension://ab/c")


def test_bridge_status_attempt_and_recovery():
    bridge = EdgeBridge(port=0)
    bridge.start()
    # ephemeral test socket ensures no collision with real SSG8
    port = bridge._server.server_address[1]
    root = f"http://127.0.0.1:{port}"
    try:
        code, data = request(root + "/status")
        assert code == 200 and data["online"] and not data["website_enabled"]
        assert data["token"]
        bridge.set_website_enabled(True)
        assert request(root + "/status")[1]["website_enabled"] is True
        assert request(root + "/status", origin="https://hostile.site")[0] == 403
        assert request(root + "/attempt", method="POST", body={"url": "https://x.test"})[0] == 403
        assert request(root + "/attempt", method="POST", token=data["token"], body={"url": "file:///bad"})[0] == 400
        assert request(root + "/attempt", method="POST", token=data["token"], body={"url": "https://youtube.com/watch?v=secret"})[0] == 202
        assert bridge.pop_attempt() == "https://youtube.com/"
        assert bridge.pop_attempt() is None
        bridge.set_website_enabled(False)
        assert request(root + "/status")[1]["website_enabled"] is False
    finally:
        bridge.stop()
