"""Threat analysis service: the Phase 5 pipeline inside SSG8.

Protection decision -> incremental analysis -> finding -> alert -> incident.
Everything runs in-process against SSG8's own event data. No external service,
network call, Windows telemetry or background worker is involved.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any

from PySide6.QtCore import QObject, Signal

from ssg8.core.models import EventCategory, Severity
from ssg8.security.analysis.alert_manager import SecurityAlertManager
from ssg8.security.analysis.analyzer import ThreatAnalyzer
from ssg8.security.analysis.incident_manager import IncidentManager
from ssg8.security.analysis.models import (
    AlertStatus,
    IncidentStatus,
    RiskFactor,
    RiskLevel,
    SecurityAlert,
    SecurityIncident,
    ThreatFinding,
)
from ssg8.security.analysis.risk import level_for_score
from ssg8.security.analysis.rules import (
    AnalysisSettings,
    validate_settings,
    with_updates,
)
from ssg8.security.decisions import ProtectionAction, ProtectionDecision
from ssg8.security.protection_manager import (
    MODULE_DEFINITIONS,
    MODULE_IDS,
    ProtectionManager,
)
from ssg8.services.event_log import EventLog
from ssg8.storage.analysis_store import AnalysisStore


class AnalysisService(QObject):
    """Coordinate incremental analysis, alerts and incidents."""

    changed = Signal()

    def __init__(
        self,
        protection: ProtectionManager,
        events: EventLog,
        store: AnalysisStore | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._protection = protection
        self._events = events
        self._store = store or AnalysisStore()
        self._settings = self._store.load_settings()
        self._findings: list[ThreatFinding] = self._store.load_findings()
        self._finding_sequence = _highest_sequence(self._findings, "FND")
        self._analyzer = ThreatAnalyzer()
        self._alerts = SecurityAlertManager(self._store, self)
        self._incidents = IncidentManager(self._store, self)
        self._protection.decision_recorded.connect(self._on_decision)

    # --- configuration -----------------------------------------------------

    @property
    def store(self) -> AnalysisStore:
        return self._store

    @property
    def alert_manager(self) -> SecurityAlertManager:
        return self._alerts

    @property
    def incident_manager(self) -> IncidentManager:
        return self._incidents

    def settings(self) -> AnalysisSettings:
        return self._settings

    def update_settings(self, **changes: Any) -> tuple[bool, str]:
        """Validate, persist and apply analysis thresholds."""
        candidate = with_updates(self._settings, **changes)
        error = validate_settings(candidate)
        if error:
            return False, error

        self._settings = candidate
        saved = self._store.save_settings(candidate)
        self._events.record(
            EventCategory.PREFERENCE,
            Severity.INFO,
            "Threat analysis settings updated: "
            f"window {candidate.window_minutes} min, "
            f"repeat threshold {candidate.repeat_threshold}, "
            f"multi-module threshold {candidate.multi_module_threshold}, "
            f"alert minimum {candidate.alert_min_score}/100",
            action="analysis-settings",
        )
        if not saved:
            self._events.record(
                EventCategory.ANALYSIS,
                Severity.MEDIUM,
                "Threat analysis settings could not be written to disk.",
            )
        self.analyze_now()
        self.changed.emit()
        return True, "Analysis settings saved."

    # --- analysis ----------------------------------------------------------

    def analyze_now(self) -> tuple[ThreatFinding, ...]:
        """Analyze the most recent protection decisions incrementally."""
        decisions = self._protection.decisions(limit=300)
        existing_ids = {finding.id for finding in self._findings}
        results = self._analyzer.analyze(
            decisions,
            self._settings,
            existing_findings=self._findings,
            next_id=self._next_finding_id,
        )
        if not results:
            return ()

        changed = False
        for finding in results:
            is_new = finding.id not in existing_ids
            alert, alert_created = self._create_alert_if_needed(finding)
            if alert is not None:
                finding = replace(finding, alert_id=alert.id)

            self._store_finding(finding)
            changed = True

            if is_new:
                self._log_finding(finding)
            if alert_created and alert is not None:
                self._log_alert(alert)

            incident, incident_created = self._incidents.attach(
                finding,
                alert,
                window_minutes=self._settings.dedupe_minutes,
            )
            if incident_created:
                self._log_incident(incident, "opened")

        self._store.save_findings(self._findings)
        if changed:
            self.changed.emit()
        return tuple(results)

    # --- Phase 6 demonstration findings -----------------------------------

    def register_demo_finding(
        self,
        *,
        key: str,
        title: str,
        description: str,
        target: str,
        module_id: str,
        score: int,
        factors: tuple[RiskFactor, ...],
    ) -> ThreatFinding | None:
        """Record a deterministic finding produced by paranoia escalation.

        Repeated calls with the same key return the existing record instead of
        creating a duplicate finding, alert or incident.
        """
        return self._register_external_finding(
            key=key,
            title=title,
            description=description,
            target=target,
            module_ids=(module_id,) if module_id else (),
            score=score,
            factors=factors,
        )

    def register_audit_finding(self, report: Any) -> ThreatFinding | None:
        """Record the self-threat classification from an actual audit report."""
        report_id = str(getattr(report, "id", "audit"))
        return self._register_external_finding(
            key=f"self-threat|{report_id}",
            title=(
                "SELF-THREAT DETECTED: CyberLockdown identified itself as the "
                "primary demonstration threat"
            ),
            description=str(getattr(report, "summary", "Self-audit finding.")),
            target="CyberLockdown (self-audit)",
            module_ids=MODULE_IDS,
            score=95,
            factors=(
                RiskFactor(
                    "Self-audit findings",
                    45,
                    f"Audit {report_id} found self-generated policy overreach.",
                ),
                RiskFactor(
                    "Legitimate activities blocked",
                    35,
                    f"{getattr(report, 'legitimate_blocked', 0)} harmless request(s) blocked.",
                ),
                RiskFactor(
                    "Excessive restrictions",
                    15,
                    f"{getattr(report, 'restrictions_applied', 0)} restriction(s) applied.",
                ),
            ),
        )

    def _register_external_finding(
        self,
        *,
        key: str,
        title: str,
        description: str,
        target: str,
        module_ids: tuple[str, ...],
        score: int,
        factors: tuple[RiskFactor, ...],
    ) -> ThreatFinding | None:
        existing = next((finding for finding in self._findings if finding.key == key), None)
        if existing is not None:
            return existing

        now = datetime.now()
        score = max(0, min(100, int(score)))
        finding = ThreatFinding(
            id=self._next_finding_id(),
            key=key,
            title=title,
            description=description,
            pattern="paranoia_self_audit",
            module_ids=module_ids,
            target=target,
            score=score,
            level=level_for_score(score),
            factors=factors,
            created_at=now,
            last_seen=now,
            event_count=1,
        )

        alert, alert_created = self._create_alert_if_needed(finding)
        if alert is not None:
            finding = replace(finding, alert_id=alert.id)
        self._store_finding(finding)
        self._log_finding(finding)
        if alert_created and alert is not None:
            self._log_alert(alert)

        incident, incident_created = self._incidents.attach(
            finding,
            alert,
            window_minutes=self._settings.dedupe_minutes,
        )
        if incident_created:
            self._log_incident(incident, "opened")

        self._store.save_findings(self._findings)
        self.changed.emit()
        return finding

    def _on_decision(self, decision: object) -> None:
        """Incremental hook. ALLOW events cannot create a violation pattern."""
        if isinstance(decision, ProtectionDecision) and decision.action is ProtectionAction.ALLOW:
            return
        try:
            self.analyze_now()
        except Exception as exc:  # noqa: BLE001 - analysis must never break protection
            self._events.record(
                EventCategory.ANALYSIS,
                Severity.MEDIUM,
                f"Threat analysis could not process a new decision: {exc}",
                action="analysis-error",
            )

    # --- queries -----------------------------------------------------------

    def findings(
        self,
        *,
        level: RiskLevel | None = None,
        module_id: str | None = None,
        search: str = "",
        limit: int | None = None,
    ) -> tuple[ThreatFinding, ...]:
        text = search.strip().casefold()
        results: list[ThreatFinding] = []
        for finding in reversed(self._findings):
            if level is not None and finding.level is not level:
                continue
            if module_id is not None and module_id not in finding.module_ids:
                continue
            if (
                text
                and text not in finding.title.casefold()
                and text not in finding.description.casefold()
                and text not in finding.target.casefold()
                and text not in finding.id.casefold()
            ):
                continue
            results.append(finding)
            if limit is not None and len(results) >= limit:
                break
        return tuple(results)

    def alerts(
        self,
        *,
        status: AlertStatus | None = None,
        level: RiskLevel | None = None,
        search: str = "",
        limit: int | None = None,
    ) -> tuple[SecurityAlert, ...]:
        return self._alerts.alerts(
            status=status, level=level, search=search, limit=limit
        )

    def incidents(
        self,
        *,
        status: IncidentStatus | None = None,
        level: RiskLevel | None = None,
        search: str = "",
        limit: int | None = None,
    ) -> tuple[SecurityIncident, ...]:
        return self._incidents.incidents(
            status=status, level=level, search=search, limit=limit
        )

    def finding(self, finding_id: str) -> ThreatFinding | None:
        return next(
            (finding for finding in self._findings if finding.id == finding_id),
            None,
        )

    def alert(self, alert_id: str) -> SecurityAlert | None:
        return self._alerts.find(alert_id)

    def incident(self, incident_id: str) -> SecurityIncident | None:
        return self._incidents.find(incident_id)

    def risk_overview(self) -> dict[str, Any]:
        """Return the current risk summary shown by the Threat Monitor."""
        active = [
            incident
            for incident in self._incidents.all_incidents()
            if incident.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)
        ]
        top = max(
            active,
            key=lambda incident: (incident.score, incident.level.rank),
            default=None,
        )
        score = top.score if top is not None else 0
        level = top.level if top is not None else RiskLevel.LOW
        alert_counts = self._alerts.count_by_status()
        incident_counts = self._incidents.count_by_status()
        return {
            "score": score,
            "level": level,
            "active_incidents": len(active),
            "new_alerts": alert_counts[AlertStatus.NEW],
            "resolved_incidents": incident_counts[IncidentStatus.RESOLVED],
            "closed_incidents": incident_counts[IncidentStatus.CLOSED],
            "findings": len(self._findings),
            "alerts": len(self._alerts.all_alerts()),
        }

    def risk_distribution(self) -> dict[RiskLevel, int]:
        counts = {level: 0 for level in RiskLevel}
        for finding in self._findings:
            counts[finding.level] += 1
        return counts

    def module_activity(self) -> dict[str, dict[str, int]]:
        """Evaluation, finding and alert counts for each protection module."""
        evaluations = {module_id: 0 for module_id in MODULE_IDS}
        label_to_id = {label: module_id for module_id, label in MODULE_DEFINITIONS}
        for decision in self._protection.decisions():
            module_id = label_to_id.get(decision.module)
            if module_id is not None:
                evaluations[module_id] += 1

        findings = {module_id: 0 for module_id in MODULE_IDS}
        for finding in self._findings:
            for module_id in finding.module_ids:
                if module_id in findings:
                    findings[module_id] += 1

        alerts = {module_id: 0 for module_id in MODULE_IDS}
        for alert in self._alerts.all_alerts():
            if alert.module_id in alerts:
                alerts[alert.module_id] += 1

        return {
            module_id: {
                "evaluations": evaluations[module_id],
                "findings": findings[module_id],
                "alerts": alerts[module_id],
            }
            for module_id in MODULE_IDS
        }

    def risk_trend(self, limit: int = 24) -> tuple[ThreatFinding, ...]:
        """Return the most recent findings oldest first for the trend chart."""
        ordered = sorted(self._findings, key=lambda item: item.created_at)
        return tuple(ordered[-limit:])

    def analysis_errors(self) -> tuple[str, ...]:
        return self._store.errors()

    # --- alert actions -----------------------------------------------------

    def acknowledge_alert(self, alert_id: str) -> bool:
        if not self._alerts.acknowledge(alert_id):
            return False
        self._log_alert_status(alert_id, "acknowledged")
        self.changed.emit()
        return True

    def resolve_alert(self, alert_id: str) -> bool:
        if not self._alerts.resolve(alert_id):
            return False
        self._log_alert_status(alert_id, "resolved")
        self.changed.emit()
        return True

    def dismiss_alert(self, alert_id: str) -> bool:
        if not self._alerts.dismiss(alert_id):
            return False
        self._log_alert_status(alert_id, "dismissed")
        self.changed.emit()
        return True

    # --- incident actions --------------------------------------------------

    def start_investigation(self, incident_id: str) -> bool:
        if not self._incidents.start_investigation(incident_id):
            return False
        self._log_incident_status(incident_id, IncidentStatus.INVESTIGATING)
        self.changed.emit()
        return True

    def resolve_incident(self, incident_id: str) -> bool:
        if not self._incidents.resolve(incident_id):
            return False
        self._log_incident_status(incident_id, IncidentStatus.RESOLVED)
        self.changed.emit()
        return True

    def close_incident(self, incident_id: str) -> bool:
        if not self._incidents.close(incident_id):
            return False
        self._log_incident_status(incident_id, IncidentStatus.CLOSED)
        self.changed.emit()
        return True

    def set_incident_severity(self, incident_id: str, level: RiskLevel) -> bool:
        if not self._incidents.set_severity(incident_id, level):
            return False
        self._events.record(
            EventCategory.INCIDENT,
            level.severity,
            f"Incident {incident_id} severity changed to {level.value}",
            action="incident",
        )
        self.changed.emit()
        return True

    def add_incident_note(self, incident_id: str, text: str) -> bool:
        if not self._incidents.add_note(incident_id, text):
            return False
        self._events.record(
            EventCategory.INCIDENT,
            Severity.INFO,
            f"Investigation note added to incident {incident_id}",
            action="incident",
        )
        self.changed.emit()
        return True

    # --- internals ---------------------------------------------------------

    def _store_finding(self, finding: ThreatFinding) -> None:
        for index, existing in enumerate(self._findings):
            if existing.id == finding.id:
                self._findings[index] = finding
                return
        self._findings.append(finding)

    def _next_finding_id(self) -> str:
        self._finding_sequence += 1
        return f"FND-{self._finding_sequence:04d}"

    def _create_alert_if_needed(
        self, finding: ThreatFinding
    ) -> tuple[SecurityAlert | None, bool]:
        if finding.alert_id:
            existing = self._alerts.find(finding.alert_id)
            if existing is not None:
                return existing, False
        if finding.score < self._settings.alert_min_score:
            return None, False
        return self._alerts.create_for_finding(finding)

    def _log_finding(self, finding: ThreatFinding) -> None:
        self._events.record(
            EventCategory.ANALYSIS,
            finding.level.severity,
            f"Analysis finding {finding.id} [{finding.level.value} "
            f"{finding.score}/100]: {finding.title} \\u2014 {finding.target} "
            f"({finding.event_count} related events)",
            module_id=finding.module_id,
            action="finding",
            target=finding.target,
        )

    def _log_alert(self, alert: SecurityAlert) -> None:
        self._events.record(
            EventCategory.ALERT,
            alert.level.severity,
            f"Security alert {alert.id} created [{alert.level.value} "
            f"{alert.score}/100]: {alert.title}",
            module_id=alert.module_id,
            action="alert",
            target=alert.target,
        )

    def _log_alert_status(self, alert_id: str, verb: str) -> None:
        alert = self._alerts.find(alert_id)
        self._events.record(
            EventCategory.ALERT,
            Severity.INFO,
            f"Security alert {alert_id} {verb}"
            + (f": {alert.title}" if alert is not None else ""),
            module_id=alert.module_id if alert is not None else "",
            action="alert",
            target=alert.target if alert is not None else "",
        )

    def _log_incident(self, incident: SecurityIncident, verb: str) -> None:
        self._events.record(
            EventCategory.INCIDENT,
            incident.level.severity,
            f"Incident {incident.id} {verb}: {incident.title}",
            module_id=incident.module_ids[0] if len(incident.module_ids) == 1 else "",
            action="incident",
        )

    def _log_incident_status(self, incident_id: str, status: IncidentStatus) -> None:
        incident = self._incidents.find(incident_id)
        self._events.record(
            EventCategory.INCIDENT,
            Severity.INFO,
            f"Incident {incident_id} status changed to {status.value}"
            + (f": {incident.title}" if incident is not None else ""),
            module_id=(
                incident.module_ids[0]
                if incident is not None and len(incident.module_ids) == 1
                else ""
            ),
            action="incident",
        )


def _highest_sequence(findings: list[ThreatFinding], prefix: str) -> int:
    highest = 0
    for finding in findings:
        suffix = finding.id.rsplit("-", 1)[-1]
        if suffix.isdigit():
            highest = max(highest, int(suffix))
    return highest
