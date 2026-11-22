"""Validation helpers for user supplied interface configuration."""

from __future__ import annotations

import re

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def normalise_domain(value: str) -> str:
    """Return a bare domain: no scheme, no path, no trailing slash."""
    domain = value.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix) :]
    domain = domain.split("/", 1)[0].split("?", 1)[0]
    domain = domain.rstrip(".")
    return domain


def validate_domain(value: str) -> str | None:
    """Return an error message for an invalid domain, or ``None`` if valid."""
    if not value.strip():
        return "Enter a website domain."
    domain = normalise_domain(value)
    if len(domain) > 253:
        return "The domain is too long (253 characters maximum)."
    if not DOMAIN_PATTERN.match(domain):
        return "Enter a valid domain, for example example.com"
    return None


def validate_application_name(value: str) -> str | None:
    """Return an error message for an invalid application name."""
    name = value.strip()
    if not name:
        return "Enter an application name."
    if len(name) > 80:
        return "The application name is too long (80 characters maximum)."
    return None


def validate_application_path(value: str) -> str | None:
    """Return an error message for an invalid executable path."""
    path = value.strip()
    if not path:
        return "Enter the executable path."
    if len(path) > 260:
        return "The path is too long (260 characters maximum)."
    return None
