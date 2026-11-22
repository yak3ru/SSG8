"""Configurable protection policy and its validation.

The policy only affects how SSG8 evaluates requests submitted to it. It is
stored in a local JSON file and never changes Windows security settings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
from typing import Any

SUBDOMAIN_INCLUDE = "include"
SUBDOMAIN_EXACT = "exact"
SUBDOMAIN_MODES: tuple[str, ...] = (SUBDOMAIN_INCLUDE, SUBDOMAIN_EXACT)
SUBDOMAIN_LABELS: dict[str, str] = {
    SUBDOMAIN_INCLUDE: "Rule also matches subdomains",
    SUBDOMAIN_EXACT: "Exact host name only",
}

UNKNOWN_FILE_REVIEW = "review"
UNKNOWN_FILE_ALLOW = "allow"
UNKNOWN_FILE_BLOCK = "block"
UNKNOWN_FILE_ACTIONS: tuple[str, ...] = (
    UNKNOWN_FILE_ALLOW,
    UNKNOWN_FILE_REVIEW,
    UNKNOWN_FILE_BLOCK,
)
UNKNOWN_FILE_LABELS: dict[str, str] = {
    UNKNOWN_FILE_ALLOW: "Allow unknown file types",
    UNKNOWN_FILE_REVIEW: "Flag unknown file types for review",
    UNKNOWN_FILE_BLOCK: "Block unknown file types",
}

MIN_FILE_SIZE_MB = 1
MAX_FILE_SIZE_MB = 4096
DEFAULT_FILE_SIZE_MB = 256

DEFAULT_BLOCKED_EXTENSIONS: tuple[str, ...] = (
    ".bat",
    ".cmd",
    ".com",
    ".cpl",
    ".exe",
    ".hta",
    ".jar",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".pif",
    ".ps1",
    ".reg",
    ".scr",
    ".vbs",
    ".wsf",
)

_EXTENSION_PATTERN = re.compile(r"^\.[a-z0-9][a-z0-9+_-]{0,11}$")


@dataclass(frozen=True, slots=True)
class ProtectionSettings:
    """Policy values used by the download and website engines."""

    max_file_size_mb: int = DEFAULT_FILE_SIZE_MB
    subdomain_matching: str = SUBDOMAIN_INCLUDE
    unknown_file_action: str = UNKNOWN_FILE_REVIEW
    blocked_extensions: tuple[str, ...] = field(
        default=DEFAULT_BLOCKED_EXTENSIONS
    )

    @property
    def max_file_size_bytes(self) -> int:
        return self.max_file_size_mb * 1024 * 1024


def normalise_extensions(values: str | tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Return a sorted, unique, lower-case extension tuple.

    ``.EXE, .exe .scr`` becomes ``(".exe", ".scr")``. Invalid fragments are
    dropped; :func:`extension_errors` reports them separately.
    """
    if isinstance(values, str):
        raw = re.split(r"[\s,;]+", values)
    else:
        raw = list(values)

    cleaned: set[str] = set()
    for item in raw:
        extension = str(item).strip().lower()
        if not extension:
            continue
        if not extension.startswith("."):
            extension = "." + extension
        if _EXTENSION_PATTERN.match(extension):
            cleaned.add(extension)
    return tuple(sorted(cleaned))


def extension_errors(values: str | tuple[str, ...] | list[str]) -> str | None:
    """Return an error message when any extension entry is invalid."""
    if isinstance(values, str):
        raw = re.split(r"[\s,;]+", values)
    else:
        raw = list(values)

    for item in raw:
        extension = str(item).strip().lower()
        if not extension:
            continue
        if not extension.startswith("."):
            extension = "." + extension
        if not _EXTENSION_PATTERN.match(extension):
            return (
                f"'{item.strip()}' is not a valid extension. "
                "Use entries such as .exe or .ps1"
            )
    return None


def validate_settings(settings: ProtectionSettings) -> str | None:
    """Return a human readable error when ``settings`` is invalid."""
    if not isinstance(settings.max_file_size_mb, int):
        return "The maximum file size must be a whole number of megabytes."
    if not MIN_FILE_SIZE_MB <= settings.max_file_size_mb <= MAX_FILE_SIZE_MB:
        return (
            f"The maximum file size must be between {MIN_FILE_SIZE_MB} and "
            f"{MAX_FILE_SIZE_MB} MB."
        )
    if settings.subdomain_matching not in SUBDOMAIN_MODES:
        return "Choose a valid subdomain matching mode."
    if settings.unknown_file_action not in UNKNOWN_FILE_ACTIONS:
        return "Choose a valid behaviour for unknown file types."
    if not settings.blocked_extensions:
        return "Configure at least one prohibited extension."
    return None


def with_updates(settings: ProtectionSettings, **changes: Any) -> ProtectionSettings:
    """Return a copy of ``settings`` with validated changes applied."""
    return replace(settings, **changes)


def settings_from_dict(raw: Any) -> tuple[ProtectionSettings, list[str]]:
    """Build settings from persisted JSON, falling back per invalid field."""
    defaults = ProtectionSettings()
    errors: list[str] = []
    if not isinstance(raw, dict):
        return defaults, ["Protection settings are not a JSON object; defaults used."]

    values: dict[str, Any] = {}
    size = raw.get("max_file_size_mb")
    if isinstance(size, int) and not isinstance(size, bool):
        values["max_file_size_mb"] = size
    elif size is not None:
        errors.append("Stored maximum file size is invalid; default used.")

    subdomains = raw.get("subdomain_matching")
    if subdomains in SUBDOMAIN_MODES:
        values["subdomain_matching"] = subdomains
    elif subdomains is not None:
        errors.append("Stored subdomain policy is invalid; default used.")

    unknown = raw.get("unknown_file_action")
    if unknown in UNKNOWN_FILE_ACTIONS:
        values["unknown_file_action"] = unknown
    elif unknown is not None:
        errors.append("Stored unknown-file policy is invalid; default used.")

    extensions = raw.get("blocked_extensions")
    if isinstance(extensions, list) and all(isinstance(item, str) for item in extensions):
        if extension_errors(extensions) is None and normalise_extensions(extensions):
            values["blocked_extensions"] = normalise_extensions(extensions)
        else:
            errors.append("Stored prohibited extensions are invalid; defaults used.")
    elif extensions is not None:
        errors.append("Stored prohibited extensions are invalid; defaults used.")

    settings = ProtectionSettings(**values)
    message = validate_settings(settings)
    if message:
        errors.append(message)
        return defaults, errors
    return settings, errors


def settings_to_dict(settings: ProtectionSettings) -> dict[str, Any]:
    return {
        "max_file_size_mb": settings.max_file_size_mb,
        "subdomain_matching": settings.subdomain_matching,
        "unknown_file_action": settings.unknown_file_action,
        "blocked_extensions": list(settings.blocked_extensions),
    }
