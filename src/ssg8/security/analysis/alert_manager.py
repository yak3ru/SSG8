"""Security alert lifecycle management.

Alerts are only created from findings produced by the SSG8 analyzer. An alert
is never fabricated to populate the interface, and a finding can own at most
one alert.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QObject, Signal

from ssg8.security.analysis.models import (
    AlertStatus,
    RiskLevel,
    SecurityAlert,
    ThreatFinding,
)
from ssg8.storage.analysis_store import AnalysisStore


class SecurityAlertManager(QObject):
    """Create, transition, filter and persist security alerts."""

    changed = Signal()

    def __init__(
        self,
        store: AnalysisStore,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._store = store
        self._alerts: list[SecurityAlert] = store.load_alerts()
        self._sequence = _highest_sequence(self._alerts)

    @property
    def store(self) -> AnalysisStore:
        return self._store

    def all_alerts(self) -> tuple[SecurityAlert, ...]:
        return tuple(self._alerts)

    def alerts(
        self,
        *,
        status: AlertStatus | None = None,
        level: RiskLevel | None = None,
        search: str = "",
        limit: int | None = None,
    ) -> tuple[SecurityAlert, ...]:
        """Return alerts newest first, optionally filtered."""
        text = search.strip().casefold()
        results: list[SecurityAlert] = []
        for alert in reversed(self._alerts):
            if status is not None and alert.status is not status:
                continue
            if level is not None and alert.level is not level:
                continue
            if (
                text
                and text not in alert.title.casefold()
                and text not in alert.description.casefold()
                and text not in alert.target.casefold()
                and text not in alert.id.casefold()
            ):
                continue
            results.append(alert)
            if limit is not None and len(results) >= limit:
                break
        return tuple(results)

    def find(self, alert_id: str) -> SecurityAlert | None:
        return next((alert for alert in self._alerts if alert.id == alert_id), None)

    def create_for_finding(
        self, finding: ThreatFinding
    ) -> tuple[SecurityAlert | None, bool]:
        """Create one alert for ``finding`` unless it already has one."""
        if finding.alert_id:
            existing = self.find(finding.alert_id)
            if existing is not None:
                return existing, False
        for alert in self._alerts:
            if alert.finding_id == finding.id:
                return alert, False

        now = datetime.now()
        alert = SecurityAlert(
            id=self._next_id(),
            title=finding.title,
            description=finding.description,
            level=finding.level,
            score=finding.score,
            module_id=finding.module_id,
            target=finding.target,
            finding_id=finding.id,
            created_at=now,
            updated_at=now,
            status=AlertStatus.NEW,
        )
        self._alerts.append(alert)
        self._save()
        self.changed.emit()
        return alert, True

    def acknowledge(self, alert_id: str) -> bool:
        return self._transition(alert_id, AlertStatus.ACKNOWLEDGED, {AlertStatus.NEW})

    def resolve(self, alert_id: str) -> bool:
        return self._transition(
            alert_id,
            AlertStatus.RESOLVED,
            {AlertStatus.NEW, AlertStatus.ACKNOWLEDGED},
        )

    def dismiss(self, alert_id: str) -> bool:
        return self._transition(
            alert_id,
            AlertStatus.DISMISSED,
            {AlertStatus.NEW, AlertStatus.ACKNOWLEDGED},
        )

    def count_by_status(self) -> dict[AlertStatus, int]:
        counts = {status: 0 for status in AlertStatus}
        for alert in self._alerts:
            counts[alert.status] += 1
        return counts

    # --- internals ---------------------------------------------------------

    def _transition(
        self, alert_id: str, target: AlertStatus, allowed: set[AlertStatus]
    ) -> bool:
        for index, alert in enumerate(self._alerts):
            if alert.id != alert_id:
                continue
            if alert.status not in allowed:
                return False
            self._alerts[index] = SecurityAlert(
                id=alert.id,
                title=alert.title,
                description=alert.description,
                level=alert.level,
                score=alert.score,
                module_id=alert.module_id,
                target=alert.target,
                finding_id=alert.finding_id,
                created_at=alert.created_at,
                updated_at=datetime.now(),
                status=target,
            )
            self._save()
            self.changed.emit()
            return True
        return False

    def _next_id(self) -> str:
        self._sequence += 1
        return f"ALR-{self._sequence:04d}"

    def _save(self) -> None:
        self._store.save_alerts(self._alerts)


def _highest_sequence(alerts: list[SecurityAlert]) -> int:
    highest = 0
    for alert in alerts:
        suffix = alert.id.rsplit("-", 1)[-1]
        if suffix.isdigit():
            highest = max(highest, int(suffix))
    return highest
