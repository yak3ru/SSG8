"""Incident management for related SSG8 findings and alerts.

An incident groups records that share a target, module set and detection
window. Unrelated patterns stay in separate incidents. Repeated analysis of
the same pattern updates the existing incident instead of opening duplicates.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

from PySide6.QtCore import QObject, Signal

from ssg8.security.analysis.models import (
    IncidentNote,
    IncidentStatus,
    RiskLevel,
    SecurityAlert,
    SecurityIncident,
    ThreatFinding,
)
from ssg8.storage.analysis_store import AnalysisStore

ACTIVE_STATUSES = (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)
NOTE_LIMIT = 500


class IncidentManager(QObject):
    """Create, investigate and persist security incidents."""

    changed = Signal()

    def __init__(
        self,
        store: AnalysisStore,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = store
        self._incidents: list[SecurityIncident] = store.load_incidents()
        self._sequence = _highest_sequence(self._incidents)

    @property
    def store(self) -> AnalysisStore:
        return self._store

    def all_incidents(self) -> tuple[SecurityIncident, ...]:
        return tuple(self._incidents)

    def incidents(
        self,
        *,
        status: IncidentStatus | None = None,
        level: RiskLevel | None = None,
        search: str = "",
        limit: int | None = None,
    ) -> tuple[SecurityIncident, ...]:
        """Return incidents newest first, optionally filtered."""
        text = search.strip().casefold()
        results: list[SecurityIncident] = []
        for incident in reversed(self._incidents):
            if status is not None and incident.status is not status:
                continue
            if level is not None and incident.level is not level:
                continue
            if (
                text
                and text not in incident.title.casefold()
                and text not in incident.summary.casefold()
                and text not in incident.id.casefold()
            ):
                continue
            results.append(incident)
            if limit is not None and len(results) >= limit:
                break
        return tuple(results)

    def find(self, incident_id: str) -> SecurityIncident | None:
        return next(
            (incident for incident in self._incidents if incident.id == incident_id),
            None,
        )

    def attach(
        self,
        finding: ThreatFinding,
        alert: SecurityAlert | None,
        *,
        window_minutes: int = 30,
    ) -> tuple[SecurityIncident, bool]:
        """Attach a finding (and optional alert) to a related incident."""
        group_key = _group_key(finding)
        cutoff = finding.last_seen - timedelta(minutes=window_minutes)
        related = next(
            (
                incident
                for incident in reversed(self._incidents)
                if incident.group_key == group_key
                and incident.status in ACTIVE_STATUSES
                and incident.updated_at >= cutoff
            ),
            None,
        )

        if related is not None:
            updated = replace(
                related,
                updated_at=max(related.updated_at, finding.last_seen),
                level=_stronger_level(related.level, finding.level),
                score=max(related.score, finding.score),
                alert_ids=_append_unique(related.alert_ids, alert.id if alert else ""),
                finding_ids=_append_unique(related.finding_ids, finding.id),
                module_ids=tuple(sorted(set(related.module_ids) | set(finding.module_ids))),
                summary=_summary(related.title, len(set(related.finding_ids) | {finding.id})),
            )
            self._replace(updated)
            return updated, False

        title = _incident_title(finding)
        incident = SecurityIncident(
            id=self._next_id(),
            group_key=group_key,
            title=title,
            summary=_summary(title, 1),
            level=finding.level,
            score=finding.score,
            created_at=finding.last_seen,
            updated_at=finding.last_seen,
            alert_ids=(alert.id,) if alert is not None else (),
            finding_ids=(finding.id,),
            module_ids=finding.module_ids,
            status=IncidentStatus.OPEN,
        )
        self._incidents.append(incident)
        self._save()
        self.changed.emit()
        return incident, True

    # --- lifecycle ---------------------------------------------------------

    def start_investigation(self, incident_id: str) -> bool:
        return self._set_status(
            incident_id, IncidentStatus.INVESTIGATING, {IncidentStatus.OPEN}
        )

    def resolve(self, incident_id: str) -> bool:
        return self._set_status(
            incident_id,
            IncidentStatus.RESOLVED,
            {IncidentStatus.OPEN, IncidentStatus.INVESTIGATING},
        )

    def close(self, incident_id: str) -> bool:
        return self._set_status(
            incident_id,
            IncidentStatus.CLOSED,
            {
                IncidentStatus.OPEN,
                IncidentStatus.INVESTIGATING,
                IncidentStatus.RESOLVED,
            },
        )

    def set_severity(self, incident_id: str, level: RiskLevel) -> bool:
        incident = self.find(incident_id)
        if incident is None or incident.status is IncidentStatus.CLOSED:
            return False
        if incident.level is level:
            return False
        self._replace(replace(incident, level=level, updated_at=datetime.now()))
        return True

    def add_note(self, incident_id: str, text: str) -> bool:
        incident = self.find(incident_id)
        note = text.strip()
        if incident is None or incident.status is IncidentStatus.CLOSED:
            return False
        if not note or len(note) > NOTE_LIMIT:
            return False
        notes = incident.notes + (IncidentNote(datetime.now(), note),)
        self._replace(replace(incident, notes=notes[-100:], updated_at=datetime.now()))
        return True

    def count_by_status(self) -> dict[IncidentStatus, int]:
        counts = {status: 0 for status in IncidentStatus}
        for incident in self._incidents:
            counts[incident.status] += 1
        return counts

    # --- internals ---------------------------------------------------------

    def _set_status(
        self, incident_id: str, status: IncidentStatus, allowed: set[IncidentStatus]
    ) -> bool:
        incident = self.find(incident_id)
        if incident is None or incident.status not in allowed:
            return False
        self._replace(replace(incident, status=status, updated_at=datetime.now()))
        return True

    def _replace(self, incident: SecurityIncident) -> None:
        for index, existing in enumerate(self._incidents):
            if existing.id == incident.id:
                self._incidents[index] = incident
                self._save()
                self.changed.emit()
                return

    def _next_id(self) -> str:
        self._sequence += 1
        return f"INC-{self._sequence:04d}"

    def _save(self) -> None:
        self._store.save_incidents(self._incidents)


def _group_key(finding: ThreatFinding) -> str:
    if len(finding.module_ids) > 1:
        return "modules:" + ",".join(sorted(finding.module_ids))
    return f"{','.join(sorted(finding.module_ids))}:{finding.target.casefold()}"


def _incident_title(finding: ThreatFinding) -> str:
    target = finding.target.strip()
    if target and target.casefold() != "multiple targets":
        return f"{finding.title}: {target}"
    return finding.title


def _summary(title: str, count: int) -> str:
    return (
        f"{title}. {count} related SSG8 analysis finding(s) grouped in this "
        "incident. The records describe internal policy activity, not confirmed "
        "malware, unauthorized access or a real cyberattack."
    )


def _stronger_level(first: RiskLevel, second: RiskLevel) -> RiskLevel:
    return first if first.rank >= second.rank else second


def _append_unique(values: tuple[str, ...], value: str) -> tuple[str, ...]:
    if not value or value in values:
        return values
    return values + (value,)


def _highest_sequence(incidents: list[SecurityIncident]) -> int:
    highest = 0
    for incident in incidents:
        suffix = incident.id.rsplit("-", 1)[-1]
        if suffix.isdigit():
            highest = max(highest, int(suffix))
    return highest
