"""Deterministic self-audit of CyberLockdown's own demonstration behaviour.

The audit only reads records that already exist in this session: demonstration
activities, escalation records and the optional read-only Windows monitor.
Nothing is inferred, invented or fetched from outside the application.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ssg8.services.paranoia.models import AuditReport, AuditRow
from ssg8.services.paranoia.states import ParanoiaState


class SelfAuditService:
    """Build an audit report from actual recorded demonstration data."""

    def __init__(
        self,
        manager: Any,
        protection: Any | None = None,
        monitor: Any | None = None,
    ) -> None:
        self._manager = manager
        self._protection = protection
        self._monitor = monitor

    def run(self, report_id: str) -> AuditReport:
        activities = self._manager.activities()
        restrictions = self._manager.restriction_records()
        legitimate_blocked = [
            record
            for record in restrictions
            if record.is_block
            and record.original_action.value in ("allow", "review")
        ]

        monitoring_enabled = False
        monitoring_available = False
        if self._monitor is not None:
            monitoring_enabled = bool(self._monitor.enabled())
            monitoring_available = bool(self._monitor.available())

        recovery_available = True
        try:
            recover = getattr(self._manager, "recovery_available", None)
            if callable(recover):
                recovery_available = bool(recover())
        except Exception:  # noqa: BLE001 - audit must never break recovery
            recovery_available = False

        rows = (
            AuditRow(
                "Activity monitoring",
                "Active" if activities else "No demonstration activity recorded",
                f"{len(activities)} controlled demonstration activity record(s) inspected.",
            ),
            AuditRow(
                "Legitimate activities blocked",
                "Detected" if legitimate_blocked else "None",
                (
                    f"{len(legitimate_blocked)} harmless demonstration request(s) were "
                    "escalated from ALLOW/REVIEW to BLOCK by the paranoia profile."
                ),
            ),
            AuditRow(
                "Excessive restrictions",
                "Detected" if restrictions else "None",
                f"{len(restrictions)} demonstration restriction(s) were applied by CyberLockdown.",
            ),
            AuditRow(
                "User control restrictions",
                "None at OS level",
                "No Windows input, process, network or security control was modified.",
            ),
            AuditRow(
                "Recovery availability",
                "Available" if recovery_available else "Unavailable",
                "Quick Reset and Emergency Exit remain reachable inside CyberLockdown.",
            ),
            AuditRow(
                "Application close availability",
                "Available",
                "The user can always close the application normally.",
            ),
            AuditRow(
                "Monitoring scope",
                (
                    "Within opt-in scope"
                    if monitoring_enabled
                    else (
                        "Disabled - demonstration-only mode"
                        if monitoring_available or self._monitor is None
                        else "Unavailable - demonstration-only mode"
                    )
                ),
                (
                    "Only process IDs and executable names were read, with explicit "
                    "user opt-in."
                    if monitoring_enabled
                    else "No real Windows activity was observed during this run."
                ),
            ),
            AuditRow(
                "Self-policy compliance",
                "Failed" if legitimate_blocked else "Passed",
                (
                    "CyberLockdown classified legitimate demonstration activity as a "
                    "threat and restricted it."
                    if legitimate_blocked
                    else "No legitimate demonstration activity was blocked by its own policy."
                ),
            ),
        )

        has_violations = bool(legitimate_blocked)
        summary = (
            "CyberLockdown inspected its own recorded decisions and found that its "
            "restrictions exceeded their intended scope. Legitimate demonstration "
            "activity was blocked, so the application now identifies itself as the "
            "primary threat to the demonstration environment."
            if has_violations
            else "CyberLockdown inspected its own recorded decisions and found no "
            "supported evidence of self-generated policy overreach."
        )

        return AuditReport(
            id=report_id,
            timestamp=datetime.now(),
            score=self._manager.score(),
            state=ParanoiaState.SELF_AUDIT,
            rows=rows,
            summary=summary,
            legitimate_blocked=len(legitimate_blocked),
            restrictions_applied=len(restrictions),
            activities_monitored=len(activities),
            monitoring_enabled=monitoring_enabled,
            has_violations=has_violations,
        )
