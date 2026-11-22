"""Local, non-sensitive preference storage for SSG8.

Preferences are written to a JSON file inside the user's local application
data folder. A plain file is used deliberately: no Windows registry keys are
created or modified.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, Signal

DEFAULTS: dict[str, Any] = {
    "confirm_before_delete": True,
    "show_demo_notices": True,
    "record_navigation": True,
}

SETTING_LABELS: dict[str, str] = {
    "confirm_before_delete": "Confirm before removing configuration entries",
    "show_demo_notices": "Show demonstration notices",
    "record_navigation": "Record navigation in application events",
}


def default_preferences_path() -> Path:
    """Return the per-user preferences file location."""
    base = os.environ.get("LOCALAPPDATA")
    root = Path(base) if base else Path.home() / ".ssg8"
    return root / "SSG8" / "preferences.json"


class Preferences(QObject):
    """Typed access to the small set of user preferences SSG8 stores."""

    changed = Signal(str)

    def __init__(self, path: Path | None = None, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._path = path or default_preferences_path()
        self._values: dict[str, Any] = dict(DEFAULTS)
        self._load_errors: list[str] = []
        self._load()

    @property
    def path(self) -> Path:
        return self._path

    def get(self, key: str) -> bool:
        return bool(self._values.get(key, DEFAULTS.get(key, False)))

    def set(self, key: str, value: bool) -> None:
        if key not in DEFAULTS:
            raise KeyError(f"Unknown preference: {key}")
        if self.get(key) == bool(value):
            return
        self._values[key] = bool(value)
        self._save()
        self.changed.emit(key)

    def reset(self) -> None:
        self._values = dict(DEFAULTS)
        self._save()
        for key in DEFAULTS:
            self.changed.emit(key)

    def load_errors(self) -> tuple[str, ...]:
        return tuple(self._load_errors)

    # --- persistence -------------------------------------------------------

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            self._load_errors.append(f"Could not read preferences: {exc}")
            return
        if not isinstance(raw, dict):
            self._load_errors.append("Preferences file is not a JSON object; defaults used.")
            return
        for key in DEFAULTS:
            if key in raw and isinstance(raw[key], bool):
                self._values[key] = raw[key]

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._path.with_suffix(".tmp")
            temporary.write_text(json.dumps(self._values, indent=2) + "\n", encoding="utf-8")
            temporary.replace(self._path)
        except OSError as exc:  # pragma: no cover - defensive, filesystem dependent
            self._load_errors.append(f"Could not save preferences: {exc}")
            print(f"SSG8: could not save preferences: {exc}", file=sys.stderr)
