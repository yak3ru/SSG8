"""JSON persistence for protection rules and policy settings.

Files live beside ``preferences.json`` in the per-user application data folder:

``website_rules.json``, ``application_rules.json`` and
``protection_settings.json``.

Writes are atomic (temporary file, then replace) and every read validates its
input. A missing or corrupted file never stops SSG8 from starting; the store
records a readable error and falls back to empty rules or defaults.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from ssg8.core.app_state import APPLICATION_POLICIES, WEBSITE_LIST_TYPES
from ssg8.core.models import ApplicationEntry, WebsiteEntry
from ssg8.security.policies import (
    ProtectionSettings,
    settings_from_dict,
    settings_to_dict,
)
from ssg8.utils.validation import normalise_domain, validate_domain


def default_data_root() -> Path:
    """Return the per-user SSG8 data folder."""
    base = os.environ.get("LOCALAPPDATA")
    root = Path(base) if base else Path.home() / ".ssg8"
    return root / "SSG8"


class ProtectionStore:
    """Load and save the internal protection configuration."""

    def __init__(self, root: Path | None = None) -> None:
        self._root = Path(root) if root is not None else default_data_root()
        self._errors: list[str] = []

    # --- locations ---------------------------------------------------------

    @property
    def root(self) -> Path:
        return self._root

    @property
    def website_path(self) -> Path:
        return self._root / "website_rules.json"

    @property
    def application_path(self) -> Path:
        return self._root / "application_rules.json"

    @property
    def settings_path(self) -> Path:
        return self._root / "protection_settings.json"

    def errors(self) -> tuple[str, ...]:
        return tuple(self._errors)

    # --- websites ----------------------------------------------------------

    def load_websites(self) -> list[WebsiteEntry]:
        raw = self._read_json(self.website_path, "website rules")
        if raw is None:
            return []
        if not isinstance(raw, list):
            self._errors.append("Website rules file is not a JSON list; ignored.")
            return []

        entries: list[WebsiteEntry] = []
        seen: set[tuple[str, str]] = set()
        for index, item in enumerate(raw):
            entry = self._parse_website(item, index)
            if entry is None:
                continue
            key = (entry.domain.casefold(), entry.list_type)
            if key in seen:
                continue
            seen.add(key)
            entries.append(entry)
        return entries

    def save_websites(self, entries: list[WebsiteEntry]) -> bool:
        payload = [
            {
                "domain": entry.domain,
                "list_type": entry.list_type,
                "added": entry.added.isoformat(timespec="seconds"),
            }
            for entry in entries
        ]
        return self._write_json(self.website_path, payload, "website rules")

    def _parse_website(self, item: Any, index: int) -> WebsiteEntry | None:
        if not isinstance(item, dict):
            self._errors.append(f"Website rule {index + 1} is not an object; skipped.")
            return None
        domain = item.get("domain")
        list_type = item.get("list_type", "block")
        if not isinstance(domain, str) or validate_domain(domain) is not None:
            self._errors.append(f"Website rule {index + 1} has an invalid domain; skipped.")
            return None
        if list_type not in WEBSITE_LIST_TYPES:
            self._errors.append(
                f"Website rule {index + 1} has an invalid list type; skipped."
            )
            return None
        added = self._parse_timestamp(item.get("added"), "Website rule", index)
        return WebsiteEntry(
            domain=normalise_domain(domain), added=added, list_type=list_type
        )

    # --- applications ------------------------------------------------------

    def load_applications(self) -> list[ApplicationEntry]:
        raw = self._read_json(self.application_path, "application rules")
        if raw is None:
            return []
        if not isinstance(raw, list):
            self._errors.append("Application rules file is not a JSON list; ignored.")
            return []

        entries: list[ApplicationEntry] = []
        seen: set[tuple[str, str, str]] = set()
        for index, item in enumerate(raw):
            entry = self._parse_application(item, index)
            if entry is None:
                continue
            key = (entry.name.casefold(), entry.path.casefold(), entry.policy)
            if key in seen:
                continue
            seen.add(key)
            entries.append(entry)
        return entries

    def save_applications(self, entries: list[ApplicationEntry]) -> bool:
        payload = [
            {
                "name": entry.name,
                "path": entry.path,
                "policy": entry.policy,
                "added": entry.added.isoformat(timespec="seconds"),
            }
            for entry in entries
        ]
        return self._write_json(self.application_path, payload, "application rules")

    def _parse_application(self, item: Any, index: int) -> ApplicationEntry | None:
        if not isinstance(item, dict):
            self._errors.append(
                f"Application rule {index + 1} is not an object; skipped."
            )
            return None
        name = item.get("name")
        path = item.get("path", "")
        policy = item.get("policy", "block")
        if not isinstance(name, str) or not name.strip() or len(name) > 80:
            self._errors.append(
                f"Application rule {index + 1} has an invalid name; skipped."
            )
            return None
        if not isinstance(path, str) or len(path) > 260:
            self._errors.append(
                f"Application rule {index + 1} has an invalid path; skipped."
            )
            return None
        if policy not in APPLICATION_POLICIES:
            self._errors.append(
                f"Application rule {index + 1} has an invalid policy; skipped."
            )
            return None
        added = self._parse_timestamp(item.get("added"), "Application rule", index)
        return ApplicationEntry(
            name=name.strip(), path=path.strip(), added=added, policy=policy
        )

    # --- settings ----------------------------------------------------------

    def load_settings(self) -> ProtectionSettings:
        raw = self._read_json(self.settings_path, "protection settings")
        if raw is None:
            return ProtectionSettings()
        settings, errors = settings_from_dict(raw)
        self._errors.extend(errors)
        return settings

    def save_settings(self, settings: ProtectionSettings) -> bool:
        return self._write_json(
            self.settings_path, settings_to_dict(settings), "protection settings"
        )

    # --- internals ---------------------------------------------------------

    def _read_json(self, path: Path, label: str) -> Any | None:
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self._errors.append(f"Could not read {label}: {exc}")
            return None

    def _write_json(self, path: Path, payload: Any, label: str) -> bool:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(path.name + ".tmp")
            temporary.write_text(
                json.dumps(payload, indent=2) + "\n", encoding="utf-8"
            )
            temporary.replace(path)
            return True
        except OSError as exc:  # pragma: no cover - filesystem dependent
            self._errors.append(f"Could not save {label}: {exc}")
            print(f"SSG8: could not save {label}: {exc}", file=sys.stderr)
            return False

    def _parse_timestamp(self, value: Any, label: str, index: int) -> datetime:
        if value is None:
            return datetime.now()
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value)
            except ValueError:
                pass
        self._errors.append(
            f"{label} {index + 1} has an invalid timestamp; current time used."
        )
        return datetime.now()
