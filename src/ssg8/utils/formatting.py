"""Small formatting helpers shared across SSG8."""

from __future__ import annotations

from datetime import datetime

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"


def format_timestamp(value: datetime) -> str:
    """Return ``value`` formatted for display in tables and log rows."""
    return value.strftime(TIMESTAMP_FORMAT)


def pluralise(count: int, singular: str, plural: str | None = None) -> str:
    """Return ``count`` followed by a correctly pluralised noun."""
    if count == 1:
        return f"{count} {singular}"
    return f"{count} {plural or singular + 's'}"


def format_bytes(size: int) -> str:
    """Return a compact human readable file size, for example ``1.4 MB``."""
    value = float(max(0, size))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def shorten_path(path: str, limit: int = 54) -> str:
    """Shorten a long filesystem path for display, keeping its tail."""
    if len(path) <= limit:
        return path
    keep = limit - 3
    return "..." + path[-keep:]
