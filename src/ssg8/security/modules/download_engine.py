"""Download protection engine: read-only file metadata and policy checks.

The engine inspects only the file the user explicitly selects inside SSG8. It
opens the file read-only to compute a SHA-256 digest, and never executes,
opens, copies, moves, modifies or deletes it. It is not antivirus software.
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
from collections.abc import Callable
from pathlib import Path

from ssg8.security.decisions import ProtectionAction, ProtectionRule
from ssg8.security.engine import ProtectionModule
from ssg8.security.policies import (
    UNKNOWN_FILE_ALLOW,
    UNKNOWN_FILE_BLOCK,
    ProtectionSettings,
)
from ssg8.utils.formatting import format_bytes

HASH_CHUNK_SIZE = 64 * 1024

# Ordinary file types that the default policy accepts without review.
KNOWN_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".7z", ".avi", ".bmp", ".bz2", ".c", ".cfg", ".cpp", ".cs", ".css",
        ".csv", ".doc", ".docx", ".flac", ".gif", ".gz", ".h", ".heic", ".htm",
        ".html", ".ico", ".ini", ".java", ".jpeg", ".jpg", ".json", ".log",
        ".md", ".mkv", ".mov", ".mp3", ".mp4", ".odp", ".ods", ".odt", ".ogg",
        ".pdf", ".png", ".pptx", ".py", ".rar", ".rtf", ".sql", ".svg", ".tar",
        ".toml", ".tsv", ".txt", ".wav", ".webm", ".webp", ".xlsx", ".xml",
        ".xz", ".yaml", ".yml", ".zip",
    }
)


class DownloadEngine(ProtectionModule):
    """Inspect one explicitly selected file and apply the download policy."""

    module_id = "download"
    label = "Download Protection"

    def __init__(self, settings_provider: Callable[[], ProtectionSettings]) -> None:
        self._settings_provider = settings_provider

    def evaluate(self, file_path: str, known_hashes: frozenset[str] = frozenset()):
        settings = self._settings_provider()

        if not isinstance(file_path, str) or not file_path.strip():
            return self.decision(
                ProtectionAction.REVIEW,
                "",
                "Select a file to inspect.",
                metadata={"policy": "invalid-input"},
            )

        try:
            path = Path(file_path.strip())
            is_file = path.is_file()
        except OSError as exc:
            return self.decision(
                ProtectionAction.REVIEW,
                file_path,
                f"The selected path could not be read: {exc}",
                metadata={"policy": "filesystem-error"},
            )

        if not is_file:
            exists = path.exists()
            return self.decision(
                ProtectionAction.REVIEW,
                str(path),
                (
                    "The selected path is a folder, not a file."
                    if exists
                    else "The selected file does not exist."
                ),
                metadata={"policy": "invalid-target"},
            )

        try:
            size = os.path.getsize(path)
        except OSError as exc:
            return self.decision(
                ProtectionAction.REVIEW,
                str(path),
                f"The file size could not be read: {exc}",
                metadata={"policy": "filesystem-error"},
            )

        extension = path.suffix.lower()
        mime, _encoding = mimetypes.guess_type(path.name)
        metadata = {
            "path": str(path),
            "name": path.name,
            "size": format_bytes(size),
            "size_bytes": str(size),
            "extension": extension or "(none)",
            "mime": mime or "unknown",
            "sha256": "",
        }

        oversized = size > settings.max_file_size_bytes

        # Hash read-only, and only when the file is inside the inspection limit.
        if not oversized:
            try:
                metadata["sha256"] = _sha256(path)
            except OSError as exc:
                metadata["policy"] = "filesystem-error"
                return self.decision(
                    ProtectionAction.REVIEW,
                    str(path),
                    f"The file could not be read for hashing: {exc}",
                    metadata=metadata,
                )
        else:
            metadata["sha256"] = "not computed (over the size limit)"

        digest = metadata["sha256"]

        if extension in settings.blocked_extensions:
            metadata["policy"] = "blocked-extension"
            return self.decision(
                ProtectionAction.BLOCK,
                str(path),
                f"File type '{extension}' is prohibited by the current policy.",
                rule=ProtectionRule(
                    "download_extension",
                    extension,
                    ProtectionAction.BLOCK,
                    f"Prohibited extension: {extension}",
                ),
                metadata=metadata,
            )

        if oversized:
            metadata["policy"] = "oversized"
            return self.decision(
                ProtectionAction.REVIEW,
                str(path),
                (
                    f"File size {format_bytes(size)} exceeds the configured inspection "
                    f"limit of {settings.max_file_size_mb} MB."
                ),
                metadata=metadata,
            )

        if digest and digest in known_hashes:
            metadata["policy"] = "duplicate-hash"
            return self.decision(
                ProtectionAction.REVIEW,
                str(path),
                "This file is a duplicate of a SHA-256 inspected earlier in this session.",
                metadata=metadata,
            )

        if extension not in KNOWN_FILE_EXTENSIONS:
            metadata["policy"] = f"unknown-type-{settings.unknown_file_action}"
            label = extension or "no extension"
            if settings.unknown_file_action == UNKNOWN_FILE_ALLOW:
                return self.decision(
                    ProtectionAction.ALLOW,
                    str(path),
                    f"File type {label} is unknown, and the policy allows unknown types.",
                    metadata=metadata,
                )
            if settings.unknown_file_action == UNKNOWN_FILE_BLOCK:
                return self.decision(
                    ProtectionAction.BLOCK,
                    str(path),
                    f"File type {label} is unknown, and the policy blocks unknown types.",
                    metadata=metadata,
                )
            return self.decision(
                ProtectionAction.REVIEW,
                str(path),
                f"File type {label} is unknown and requires review.",
                metadata=metadata,
            )

        metadata["policy"] = "allowed-by-policy"
        return self.decision(
            ProtectionAction.ALLOW,
            str(path),
            (
                "File type and size pass the current inspection policy. "
                "This is a policy result, not a malware verdict."
            ),
            metadata=metadata,
        )


def _sha256(path: Path) -> str:
    """Return the SHA-256 hex digest of ``path``, reading it read-only."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()
