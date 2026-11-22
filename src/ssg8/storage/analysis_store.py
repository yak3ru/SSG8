"""Local JSON persistence for Phase 5 analysis records.

Files live beside the protection files in ``%LOCALAPPDATA%\\SSG8``:

``security_findings.json``, ``security_alerts.json``,
``security_incidents.json`` and ``analysis_settings.json``.

Writes are atomic and reads validate every record. Missing or corrupted files
never stop SSG8 from starting; invalid records are skipped and reported through
:meth:`AnalysisStore.errors`.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ssg8.security.analysis.models import SecurityAlert, SecurityIncident, ThreatFinding
from ssg8.security.analysis.rules import (
    AnalysisSettings,
    settings_from_dict,
    settings_to_dict,
)
from ssg8.storage.protection_store import default_data_root

MAX_FINDINGS = 500
MAX_ALERTS = 500
MAX_INCIDENTS = 200


class AnalysisStore:
    """Load and save findings, alerts, incidents and analysis settings."""

    def __init__(self, root: Path | None = None) -> None:
        self._root = Path(root) if root is not None else default_data_root()
        self._errors: list[str] = []

    @property
    def root(self) -> Path:
        return self._root

    @property
    def findings_path(self) -> Path:
        return self._root / "security_findings.json"

    @property
    def alerts_path(self) -> Path:
        return self._root / "security_alerts.json"

    @property
    def incidents_path(self) -> Path:
        return self._root / "security_incidents.json"

    @property
    def settings_path(self) -> Path:
        return self._root / "analysis_settings.json"

    def errors(self) -> tuple[str, ...]:
        return tuple(self._errors)

    # --- findings ----------------------------------------------------------

    def load_findings(self) -> list[ThreatFinding]:
        return self._load_records(
            self.findings_path, "security findings", ThreatFinding, MAX_FINDINGS
        )

    def save_findings(self, findings: list[ThreatFinding]) -> bool:
        return self._save_records(
            self.findings_path, "security findings", findings[-MAX_FINDINGS:]
        )

    # --- alerts ------------------------------------------------------------

    def load_alerts(self) -> list[SecurityAlert]:
        return self._load_records(
            self.alerts_path, "security alerts", SecurityAlert, MAX_ALERTS
        )

    def save_alerts(self, alerts: list[SecurityAlert]) -> bool:
        return self._save_records(
            self.alerts_path, "security alerts", alerts[-MAX_ALERTS:]
        )

    # --- incidents ---------------------------------------------------------

    def load_incidents(self) -> list[SecurityIncident]:
        return self._load_records(
            self.incidents_path, "security incidents", SecurityIncident, MAX_INCIDENTS
        )

    def save_incidents(self, incidents: list[SecurityIncident]) -> bool:
        return self._save_records(
            self.incidents_path, "security incidents", incidents[-MAX_INCIDENTS:]
        )

    # --- settings ----------------------------------------------------------

    def load_settings(self) -> AnalysisSettings:
        raw = self._read_json(self.settings_path, "analysis settings")
        if raw is None:
            return AnalysisSettings()
        settings, errors = settings_from_dict(raw)
        self._errors.extend(errors)
        return settings

    def save_settings(self, settings: AnalysisSettings) -> bool:
        return self._write_json(
            self.settings_path, settings_to_dict(settings), "analysis settings"
        )

    # --- internals ---------------------------------------------------------

    def _load_records(self, path: Path, label: str, record_type, limit: int) -> list[Any]:
        raw = self._read_json(path, label)
        if raw is None:
            return []
        if not isinstance(raw, list):
            self._errors.append(f"{label.capitalize()} file is not a JSON list; ignored.")
            return []

        records: list[Any] = []
        seen: set[str] = set()
        for index, item in enumerate(raw):
            try:
                record = record_type.from_dict(item)
            except (ValueError, TypeError) as exc:
                self._errors.append(f"{label.capitalize()} record {index + 1} skipped: {exc}")
                continue
            if record.id in seen:
                self._errors.append(
                    f"{label.capitalize()} record {index + 1} has a duplicate id; skipped."
                )
                continue
            seen.add(record.id)
            records.append(record)
        return records[-limit:]

    def _save_records(self, path: Path, label: str, records: list[Any]) -> bool:
        return self._write_json(path, [record.to_dict() for record in records], label)

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
        except (OSError, TypeError, ValueError) as exc:  # pragma: no cover - filesystem
            self._errors.append(f"Could not save {label}: {exc}")
            print(f"SSG8: could not save {label}: {exc}", file=sys.stderr)
            return False
