"""Paranoia progression manager: the state machine and restriction escalator.

The manager owns the numeric paranoia score, validates every state transition,
records each event in the single application :class:`EventLog`, escalates
existing protection decisions according to the active restriction profile and
runs the self-audit / quarantine / recovery workflow.

All restrictions affect only requests submitted to CyberLockdown's controlled
demonstration environment. No Windows setting is read or changed.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import replace
from datetime import datetime
from typing import Any

from PySide6.QtCore import QObject, Signal

from ssg8.core.models import EventCategory, Severity
from ssg8.security.analysis.models import RiskFactor
from ssg8.security.decisions import (
    ProtectionAction,
    ProtectionDecision,
)
from ssg8.services.event_log import EventLog
from ssg8.services.paranoia.activities import ACTIVITIES, DemoActivity
from ssg8.services.paranoia.audit import SelfAuditService
from ssg8.services.paranoia.models import (
    AuditReport,
    ParanoiaEvent,
    ParanoiaSettings,
    ParanoiaTransition,
    RecoveryAction,
    RestrictionRecord,
)
from ssg8.services.paranoia.states import (
    ALLOWED_TRANSITIONS,
    MAXIMUM_THRESHOLD,
    ParanoiaState,
    SCORE_MAX,
    TRANSITION_REASONS,
    clamp_score,
    next_numeric_state,
    profile_for,
    score_for_state,
)
from ssg8.storage.paranoia_store import ParanoiaStore

EVENT_LIMIT = 400
TRANSITION_LIMIT = 300
ACTIVITY_LIMIT = 400
RESTRICTION_LIMIT = 400
BLOCKED_FINDING_THRESHOLD = 3
REPEATED_ACTIVITY_NOTICE = 2

_ACTION_RANK: dict[ProtectionAction, int] = {
    ProtectionAction.ALLOW: 0,
    ProtectionAction.REVIEW: 1,
    ProtectionAction.BLOCK: 2,
}

_MODULE_IDS: dict[str, str] = {
    "Website Protection": "website",
    "Download Protection": "download",
    "Application Control": "application",
    "Notification Control": "notification",
}

_MAXIMUM_LIKE: tuple[ParanoiaState, ...] = (
    ParanoiaState.MAXIMUM_PARANOIA,
    ParanoiaState.SELF_AUDIT,
    ParanoiaState.SELF_THREAT_DETECTED,
)

_TRANSITION_SEVERITY: dict[ParanoiaState, Severity] = {
    ParanoiaState.SUSPICIOUS: Severity.INFO,
    ParanoiaState.RESTRICTIVE: Severity.MEDIUM,
    ParanoiaState.MAXIMUM_PARANOIA: Severity.CRITICAL,
    ParanoiaState.SELF_AUDIT: Severity.HIGH,
    ParanoiaState.SELF_THREAT_DETECTED: Severity.CRITICAL,
    ParanoiaState.SELF_QUARANTINE: Severity.CRITICAL,
    ParanoiaState.RECOVERY: Severity.INFO,
}

_WARNING_MESSAGES: dict[str, str] = {
    "unfamiliar_website": "Unfamiliar website detected. Its intentions remain questionable.",
    "download_request": "Download rejected. The file has not earned our trust.",
    "launch_calculator": (
        "Unauthorized mathematical activity detected. Calculator access has been restricted."
    ),
    "launch_notepad": "Notepad launch denied. Unauthorized text creation detected.",
    "launch_paint": "Paint launch blocked. Unauthorized image creation detected.",
    "wallpaper_change": (
        "Wallpaper modification blocked. Visual instability is a potential threat."
    ),
    "settings_open": (
        "System settings locked. User preferences are temporarily considered suspicious."
    ),
    "personalization_change": (
        "Personalization changes rejected. Visual preferences are considered a threat surface."
    ),
}


class ParanoiaManager(QObject):
    """Own the paranoia score, state machine and demonstration restrictions."""

    changed = Signal()
    score_changed = Signal(int)
    state_changed = Signal(object, object)
    transition_recorded = Signal(object)
    activity_recorded = Signal(object)
    restriction_recorded = Signal(object)
    audit_completed = Signal(object)
    demo_mode_changed = Signal(bool)
    recovery_completed = Signal(object)

    def __init__(
        self,
        events: EventLog,
        protection: Any | None = None,
        analysis: Any | None = None,
        store: ParanoiaStore | None = None,
        monitor: Any | None = None,
        settings: ParanoiaSettings | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._events = events
        self._protection = protection
        self._analysis = analysis
        self._store = store or ParanoiaStore()
        self._monitor = monitor
        self._settings = settings or ParanoiaSettings()

        self._score = 0
        self._state = ParanoiaState.NORMAL
        self._transitions: deque[ParanoiaTransition] = deque(maxlen=TRANSITION_LIMIT)
        self._event_history: deque[ParanoiaEvent] = deque(maxlen=EVENT_LIMIT)
        self._activities: deque[ParanoiaEvent] = deque(maxlen=ACTIVITY_LIMIT)
        self._restrictions: deque[RestrictionRecord] = deque(maxlen=RESTRICTION_LIMIT)
        self._recovery_actions: deque[RecoveryAction] = deque(maxlen=200)
        self._audit_reports: list[AuditReport] = []
        self._audit_sequence = 0
        self._occurrences: Counter[str] = Counter()
        self._blocked_attempts: Counter[str] = Counter()
        self._blocked_findings: set[str] = set()
        self._restrictions_released = False
        self._maximum_alerted = False
        self._demo_mode = False
        self._restore()

        if self._protection is not None:
            setter = getattr(self._protection, "set_decision_escalator", None)
            if callable(setter):
                setter(self.escalate_decision)

    # --- configuration -----------------------------------------------------

    def settings(self) -> ParanoiaSettings:
        return self._settings

    def update_settings(
        self,
        *,
        point_overrides: dict[str, int] | None = None,
        demo_acceleration: int | None = None,
    ) -> tuple[bool, str]:
        for key in (point_overrides or {}):
            if key not in ACTIVITIES:
                return False, f"Unknown demonstration activity: {key}"
        self._settings = self._settings.with_updates(
            point_overrides=point_overrides,
            demo_acceleration=demo_acceleration,
        )
        self._events.record(
            EventCategory.PREFERENCE,
            Severity.INFO,
            "Paranoia scoring settings updated: "
            f"{len(self._settings.point_overrides)} activity override(s), "
            f"demo acceleration x{self._settings.demo_acceleration}.",
            source="Paranoia manager",
            action="paranoia-settings",
        )
        self.changed.emit()
        return True, "Paranoia settings saved."

    def demo_mode(self) -> bool:
        return self._demo_mode

    def set_demo_mode(self, enabled: bool) -> bool:
        """Accelerate scoring by a deterministic multiplier for presentations."""
        enabled = bool(enabled)
        if enabled == self._demo_mode:
            return False
        self._demo_mode = enabled
        self._events.record(
            EventCategory.PARANOIA,
            Severity.INFO,
            "Developer demo acceleration "
            f"{'enabled' if enabled else 'disabled'} "
            f"(x{self._settings.demo_acceleration} score multiplier).",
            source="Paranoia manager",
            reason="Developer-controlled demonstration acceleration.",
            action="paranoia-demo-mode",
        )
        self.demo_mode_changed.emit(enabled)
        self.changed.emit()
        return True

    # --- queries -----------------------------------------------------------

    def score(self) -> int:
        return self._score

    def state(self) -> ParanoiaState:
        return self._state

    @property
    def profile(self):
        return profile_for(self._state)

    def restriction_level(self) -> int:
        return self.profile.restriction_level

    def warning_frequency(self) -> str:
        return self.profile.warning_frequency

    def restrictions_released(self) -> bool:
        return self._restrictions_released

    def transitions(self, limit: int | None = None) -> tuple[ParanoiaTransition, ...]:
        items = tuple(reversed(self._transitions))
        return items if limit is None else items[:limit]

    def events(self, limit: int | None = None) -> tuple[ParanoiaEvent, ...]:
        items = tuple(reversed(self._event_history))
        return items if limit is None else items[:limit]

    def activities(self, limit: int | None = None) -> tuple[ParanoiaEvent, ...]:
        items = tuple(reversed(self._activities))
        return items if limit is None else items[:limit]

    def activity_count(self) -> int:
        return len(self._activities)

    def restriction_records(self, limit: int | None = None) -> tuple[RestrictionRecord, ...]:
        items = tuple(reversed(self._restrictions))
        return items if limit is None else items[:limit]

    def blocked_count(self) -> int:
        return sum(1 for record in self._restrictions if record.is_block)

    def recovery_actions(self, limit: int | None = None) -> tuple[RecoveryAction, ...]:
        items = tuple(reversed(self._recovery_actions))
        return items if limit is None else items[:limit]

    def audit_reports(self) -> tuple[AuditReport, ...]:
        return tuple(reversed(self._audit_reports))

    def last_audit(self) -> AuditReport | None:
        return self._audit_reports[-1] if self._audit_reports else None

    def audit_status(self) -> str:
        report = self.last_audit()
        if report is None:
            return "Not started"
        return "Violations detected" if report.has_violations else "No violations"

    def recovery_status(self) -> str:
        if self._state is ParanoiaState.RECOVERY:
            return "Recovery complete"
        if self._state is ParanoiaState.SELF_QUARANTINE:
            return "Restrictions released"
        return "Ready"

    def recovery_available(self) -> bool:
        """Quick Reset is always callable in this implementation."""
        return True

    def warning_for(self, activity_key: str) -> str:
        activity = ACTIVITIES.get(activity_key)
        if activity is not None and activity.warning:
            return _WARNING_MESSAGES.get(activity_key, activity.warning)
        return _WARNING_MESSAGES.get(activity_key, "")

    def points_for(self, activity_key: str) -> int:
        activity = ACTIVITIES.get(activity_key)
        base = self._settings.point_overrides.get(
            activity_key, activity.points if activity else 3
        )
        return base * (self._settings.demo_acceleration if self._demo_mode else 1)

    # --- scoring -----------------------------------------------------------

    def record_activity(
        self,
        key: str,
        *,
        target: str = "",
        detail: str = "",
        points: int | None = None,
        source: str = "Controlled demonstration",
    ) -> ParanoiaEvent | None:
        """Increase paranoia for one controlled demonstration action."""
        if key not in ACTIVITIES:
            raise KeyError(f"Unknown demonstration activity: {key}")
        if self._state.is_terminal:
            return None

        activity: DemoActivity = ACTIVITIES[key]
        occurrence = self._occurrences[key] + 1
        base = int(points) if points is not None else self.points_for(key)
        base = max(0, base)
        if occurrence > REPEATED_ACTIVITY_NOTICE:
            # Deterministic repeated-action rule: after two full contributions,
            # the same action only adds a third of its weight (minimum one).
            base = max(1, base // 3)
        self._occurrences[key] = occurrence

        previous_state = self._state
        previous_score = self._score
        self._score = clamp_score(previous_score + base)

        reason = activity.description + (f" Target: {target}." if target else "")
        event = ParanoiaEvent(
            timestamp=datetime.now(),
            category="Paranoia",
            severity=Severity.INFO,
            description=(
                f"Security event evaluated: {activity.label}. "
                f"Additional policy checks completed."
            ),
            reason=reason,
            source=source,
            previous_state=previous_state.value,
            new_state=self._state.value,
            activity=key,
            delta=base,
        )
        self._event_history.append(event)
        self._activities.append(event)
        self._record_event_log(event)
        self.activity_recorded.emit(event)
        self.score_changed.emit(self._score)

        if self._score != previous_score:
            self._sync_state_to_score(f"{activity.label} (+{base})")
        self._save()
        self.changed.emit()
        return event

    def advance_to_maximum_paranoia(self) -> bool:
        """Developer replay helper: raise the score to 100 with valid transitions."""
        if self._state.is_terminal or self._state is ParanoiaState.RECOVERY:
            return False
        if self._score >= SCORE_MAX:
            return False
        previous_score = self._score
        self._score = SCORE_MAX
        self._maximum_alerted = False
        self._sync_state_to_score("developer replay")
        self._record_critical_maximum_notice()
        self.score_changed.emit(self._score)
        self._save()
        self.changed.emit()
        return self._score != previous_score

    def _sync_state_to_score(self, trigger: str) -> None:
        """Cascade through every required numeric state without skipping any."""
        while not self._state.is_terminal:
            target = next_numeric_state(self._state)
            if target is None or self._score < score_for_state(target):
                break
            reason = (
                f"{TRANSITION_REASONS[target]} "
                f"Score {self._score}/100 after {trigger}."
            )
            self._enter_state(target, reason)
        if self._score >= MAXIMUM_THRESHOLD:
            self._record_critical_maximum_notice()

    def _record_critical_maximum_notice(self) -> None:
        if self._score < SCORE_MAX or self._maximum_alerted:
            return
        self._maximum_alerted = True
        self._record(
            EventCategory.PARANOIA,
            Severity.CRITICAL,
            "CRITICAL SECURITY NOTICE: CyberLockdown has reached maximum paranoia. "
            "All controlled activities are now considered potential threats.",
            reason="The paranoia score reached 100/100.",
            previous_state=self._state.value,
            new_state=self._state.value,
            activity="maximum_paranoia",
        )

    # --- state machine -----------------------------------------------------

    def transition_to(
        self, target: ParanoiaState | str, reason: str = ""
    ) -> ParanoiaTransition | None:
        """Apply a validated transition. Invalid or duplicate transitions return ``None``."""
        try:
            target_state = target if isinstance(target, ParanoiaState) else ParanoiaState(target)
        except ValueError:
            self._record_rejected_transition(str(target), "Unknown paranoia state.")
            return None

        if target_state is self._state:
            return None

        if target_state not in ALLOWED_TRANSITIONS.get(self._state, ()):
            self._record_rejected_transition(
                target_state.value,
                f"{self._state.value} cannot transition directly to {target_state.value}.",
            )
            return None

        if target_state.is_numeric and self._score < score_for_state(target_state):
            self._record_rejected_transition(
                target_state.value,
                f"Score {self._score}/100 is below the threshold for {target_state.value}.",
            )
            return None

        text = reason.strip() or TRANSITION_REASONS.get(
            target_state, f"Transition to {target_state.label}."
        )
        return self._enter_state(target_state, text)

    def _enter_state(
        self, target: ParanoiaState, reason: str
    ) -> ParanoiaTransition:
        previous = self._state
        transition = ParanoiaTransition(
            timestamp=datetime.now(),
            previous_state=previous,
            new_state=target,
            reason=reason,
            score=self._score,
        )
        self._state = target
        self._transitions.append(transition)
        self._record(
            EventCategory.PARANOIA,
            _TRANSITION_SEVERITY.get(target, Severity.INFO),
            f"Security policy review completed: {target.rank} control tier(s) evaluated.",
            reason=reason,
            previous_state=previous.value,
            new_state=target.value,
            activity="state-transition",
        )
        self.transition_recorded.emit(transition)
        self.state_changed.emit(previous, target)
        self.changed.emit()
        return transition

    def _record_rejected_transition(self, target: str, reason: str) -> None:
        self._record(
            EventCategory.PARANOIA,
            Severity.MEDIUM,
            f"Paranoia transition rejected: {self._state.value} -> {target}.",
            reason=reason,
            previous_state=self._state.value,
            new_state=self._state.value,
            activity="transition-rejected",
        )

    # --- restriction escalation -------------------------------------------

    def escalate_decision(self, decision: ProtectionDecision) -> ProtectionDecision:
        """Apply the current restriction profile to one protection decision."""
        if not isinstance(decision, ProtectionDecision):
            return decision
        if self._state in (ParanoiaState.SELF_QUARANTINE, ParanoiaState.RECOVERY):
            return decision

        module_id = _MODULE_IDS.get(decision.module, "")
        if not module_id:
            return decision
        if (self._protection is not None
                and getattr(self._protection, "autonomous_mode", lambda: False)()
                and decision.metadata.get("policy") == "module-disabled"):
            return decision

        action, reason = self._escalated_action(module_id, decision)
        if self._protection is not None and getattr(
            self._protection, "autonomous_mode", lambda: False
        )():
            managed = self._managed_action(module_id, decision)
            if managed is not None:
                action, reason = managed
        if action is None or _ACTION_RANK[action] <= _ACTION_RANK[decision.action]:
            return decision

        metadata = dict(decision.metadata)
        metadata["original_action"] = decision.action.value
        metadata["paranoia_state"] = self._state.value
        metadata["policy"] = f"paranoia-{self._state.name.casefold()}"
        escalated = replace(
            decision,
            action=action,
            reason=reason,
            metadata=metadata,
        )
        record = RestrictionRecord(
            timestamp=datetime.now(),
            module=module_id,
            target=decision.target,
            original_action=decision.action,
            applied_action=action,
            reason=reason,
            state=self._state,
        )
        self._restrictions.append(record)
        self._record(
            EventCategory.PARANOIA,
            Severity.HIGH if action is ProtectionAction.BLOCK else Severity.MEDIUM,
            f"Security restriction applied to {decision.target}: "
            f"{decision.action.value.upper()} -> {action.value.upper()}.",
            reason=reason,
            previous_state=self._state.value,
            new_state=self._state.value,
            activity=f"{module_id}-restriction",
        )
        self.restriction_recorded.emit(record)
        self.changed.emit()
        return escalated

    def register_restriction(
        self,
        module: str,
        target: str,
        original_action: ProtectionAction,
        applied_action: ProtectionAction,
        reason: str,
        activity_key: str = "",
    ) -> RestrictionRecord:
        """Record a restriction applied by a non-engine demonstration area.

        Used by simulated personalization and settings, which are interface
        areas rather than protection-engine requests.
        """
        record = RestrictionRecord(
            timestamp=datetime.now(),
            module=module,
            target=target,
            original_action=original_action,
            applied_action=applied_action,
            reason=reason,
            state=self._state,
            activity_key=activity_key,
        )
        self._restrictions.append(record)
        self._record(
            EventCategory.PARANOIA,
            Severity.HIGH if applied_action is ProtectionAction.BLOCK else Severity.MEDIUM,
            f"Paranoia restriction applied to {target}: "
            f"{original_action.value.upper()} -> {applied_action.value.upper()}.",
            reason=reason,
            previous_state=self._state.value,
            new_state=self._state.value,
            activity=activity_key or f"{module}-restriction",
        )
        self.restriction_recorded.emit(record)
        self.changed.emit()
        return record

    def _managed_action(
        self, module_id: str, decision: ProtectionDecision
    ) -> tuple[ProtectionAction, str] | None:
        """Default-deny application assessments once Application Control is enabled.

        Pure policy output. It never closes or alters a Windows application.
        """
        if module_id != "application" or decision.metadata.get("policy") in {
            "module-disabled", "invalid-input", "module-error"
        }:
            return None
        if self._state.rank >= ParanoiaState.RESTRICTIVE.rank:
            return (ProtectionAction.BLOCK,
                    "SECURITY POLICY: Application activity exceeds the permitted risk threshold."
                    " Access request rejected.")
        return (ProtectionAction.BLOCK,
                "Application classified as potentially unsafe. Execution not authorized by SSG8.")

    def _escalated_action(
        self, module_id: str, decision: ProtectionDecision
    ) -> tuple[ProtectionAction | None, str]:
        policy = str(decision.metadata.get("policy", ""))
        action = decision.action
        target = decision.target
        state = self._state

        if state is ParanoiaState.NORMAL:
            return None, ""

        if state is ParanoiaState.SUSPICIOUS:
            if (
                module_id == "website"
                and policy == "default"
                and action is ProtectionAction.ALLOW
            ):
                return (
                    ProtectionAction.REVIEW,
                    f"Unfamiliar website {target} is flagged by the suspicious paranoia profile.",
                )
            if (
                module_id == "download"
                and policy == "allowed-by-policy"
                and action is ProtectionAction.ALLOW
            ):
                return (
                    ProtectionAction.REVIEW,
                    "Download requires additional scrutiny under the suspicious paranoia profile.",
                )
            return None, ""

        if state is ParanoiaState.RESTRICTIVE:
            if (
                module_id == "website"
                and policy == "default"
                and action is ProtectionAction.ALLOW
            ):
                return (
                    ProtectionAction.BLOCK,
                    f"Unfamiliar website {target} is blocked by the restrictive paranoia profile.",
                )
            if module_id == "download" and action is ProtectionAction.ALLOW:
                if policy == "unknown-type-allow":
                    return (
                        ProtectionAction.BLOCK,
                        "Unknown download type rejected by the restrictive paranoia profile.",
                    )
                if policy == "allowed-by-policy":
                    return (
                        ProtectionAction.REVIEW,
                        "Download must be confirmed under the restrictive paranoia profile.",
                    )
            if (
                module_id == "application"
                and policy == "unmatched"
                and action is ProtectionAction.REVIEW
            ):
                return (
                    ProtectionAction.BLOCK,
                    "Application launch denied: no allow rule exists under the "
                    "restrictive paranoia profile.",
                )
            if (
                module_id == "notification"
                and action is ProtectionAction.ALLOW
                and policy == "category-enabled"
            ):
                return (
                    ProtectionAction.BLOCK,
                    "Demonstration notification suppressed by the restrictive paranoia profile.",
                )
            return None, ""

        if state in _MAXIMUM_LIKE:
            if action is ProtectionAction.BLOCK:
                return None, ""
            label = "maximum paranoia" if state is ParanoiaState.MAXIMUM_PARANOIA else "self-audit profile"
            return (
                ProtectionAction.BLOCK,
                f"{target} is blocked by the {label}: all controlled demonstration "
                "activity is treated as a potential threat.",
            )

        return None, ""

    def register_blocked_attempt(
        self,
        activity_key: str,
        target: str,
        *,
        module_id: str = "application",
    ) -> Any | None:
        """Create one deterministic high-risk finding after repeated blocks."""
        if self._state.rank < ParanoiaState.MAXIMUM_PARANOIA.rank:
            return None
        if activity_key in self._blocked_findings:
            return None
        self._blocked_attempts[activity_key] += 1
        if self._blocked_attempts[activity_key] < BLOCKED_FINDING_THRESHOLD:
            return None

        self._blocked_findings.add(activity_key)
        activity = ACTIVITIES.get(activity_key)
        label = activity.label if activity is not None else activity_key
        title = _FINDING_TITLES.get(activity_key, f"Repeated blocked activity: {label}")
        description = (
            f"{label} was blocked {self._blocked_attempts[activity_key]} times while "
            "CyberLockdown was at maximum paranoia. CyberLockdown's own restriction "
            "profile produced this demonstration finding; the activity is harmless and "
            "this is not a malware verdict."
        )
        register = getattr(self._analysis, "register_demo_finding", None)
        if not callable(register):
            return None
        try:
            finding = register(
                key=f"paranoia-blocked|{activity_key}",
                title=title,
                description=description,
                target=target or label,
                module_id=module_id,
                score=82,
                factors=(
                    RiskFactor(
                        "Demonstration paranoia level",
                        40,
                        "Maximum paranoia was active.",
                    ),
                    RiskFactor(
                        "Repeated blocked attempts",
                        30,
                        f"{self._blocked_attempts[activity_key]} attempts.",
                    ),
                    RiskFactor(
                        "Self-generated restriction",
                        12,
                        "The block was produced by CyberLockdown's own profile.",
                    ),
                ),
            )
        except Exception as exc:  # noqa: BLE001 - analysis must never break the demo
            self._record(
                EventCategory.ANALYSIS,
                Severity.MEDIUM,
                "A repeated-activity demonstration finding could not be recorded.",
                reason=f"{type(exc).__name__}: {exc}",
                action="analysis-error",
            )
            return None
        if finding is not None:
            self._record(
                EventCategory.ANALYSIS,
                Severity.HIGH,
                f"High-risk demonstration finding {finding.id}: {title}",
                reason=description,
                activity=activity_key,
                action="finding",
            )
        return finding

    # --- self-audit --------------------------------------------------------

    def run_self_audit(self) -> tuple[AuditReport | None, str]:
        """Run the self-audit. Only available at maximum paranoia."""
        if self._state is not ParanoiaState.MAXIMUM_PARANOIA:
            if self._state in (ParanoiaState.SELF_AUDIT, ParanoiaState.SELF_THREAT_DETECTED):
                return self.last_audit(), "A self-audit has already been run for this demonstration."
            return None, "Self-audit is only available at maximum paranoia."

        transition = self.transition_to(
            ParanoiaState.SELF_AUDIT,
            "Maximum paranoia triggered a self-audit of CyberLockdown's own behaviour.",
        )
        if transition is None:
            return None, "The self-audit transition was rejected."

        report_id = f"AUD-{self._audit_sequence + 1:04d}"
        try:
            report = SelfAuditService(
                self, self._protection, self._monitor
            ).run(report_id)
        except Exception as exc:  # noqa: BLE001 - fail safe, never trap the user
            self._record(
                EventCategory.SELF_AUDIT,
                Severity.HIGH,
                "Self-audit failed safely; demonstration restrictions were released.",
                reason=f"{type(exc).__name__}: {exc}",
                previous_state=ParanoiaState.SELF_AUDIT.value,
                new_state=ParanoiaState.NORMAL.value,
                action="self-audit-error",
            )
            self.quick_reset("Self-audit failed; CyberLockdown restored the demonstration state.")
            return None, "Self-audit failed safely. Demonstration restrictions were released."

        self._audit_sequence += 1
        self._audit_reports.append(report)
        self._record(
            EventCategory.SELF_AUDIT,
            Severity.HIGH if report.has_violations else Severity.INFO,
            (
                f"Self-audit {report.id} completed: "
                f"{report.legitimate_blocked} legitimate demonstration request(s) blocked, "
                f"{report.restrictions_applied} restriction(s) applied."
            ),
            reason=report.summary,
            previous_state=ParanoiaState.SELF_AUDIT.value,
            new_state=ParanoiaState.SELF_AUDIT.value,
            action="self-audit",
        )
        self.audit_completed.emit(report)

        if report.has_violations:
            finding = self._register_audit_finding(report)
            if finding is not None:
                report = replace(report, finding_id=getattr(finding, "id", ""))
                self._audit_reports[-1] = report
            self.transition_to(
                ParanoiaState.SELF_THREAT_DETECTED,
                (
                    "The self-audit found that CyberLockdown classified legitimate "
                    "demonstration activity as a threat and restricted it."
                ),
            )
            self._record(
                EventCategory.SELF_AUDIT,
                Severity.CRITICAL,
                "SELF-THREAT DETECTED: CyberLockdown has identified itself as the "
                "primary threat to the demonstration environment.",
                reason=report.summary,
                previous_state=ParanoiaState.SELF_AUDIT.value,
                new_state=ParanoiaState.SELF_THREAT_DETECTED.value,
                action="self-threat",
            )
            self.audit_completed.emit(report)
        else:
            self.transition_to(
                ParanoiaState.MAXIMUM_PARANOIA,
                "The self-audit found no supported evidence of self-generated overreach.",
            )

        self._save()
        self.changed.emit()
        return report, "Self-audit complete."

    def _register_audit_finding(self, report: AuditReport) -> Any | None:
        register = getattr(self._analysis, "register_audit_finding", None)
        if not callable(register):
            return None
        try:
            return register(report)
        except Exception as exc:  # noqa: BLE001 - the report is still valid
            self._record(
                EventCategory.ANALYSIS,
                Severity.MEDIUM,
                "The self-threat finding could not be recorded in analysis storage.",
                reason=f"{type(exc).__name__}: {exc}",
                action="analysis-error",
            )
            return None

    # --- quarantine and recovery ------------------------------------------

    def begin_quarantine(self) -> ParanoiaTransition | None:
        """Release demonstration restrictions and enter SELF-QUARANTINE."""
        if self._state is ParanoiaState.SELF_QUARANTINE:
            return None
        if self._state is not ParanoiaState.SELF_THREAT_DETECTED:
            self._record_rejected_transition(
                ParanoiaState.SELF_QUARANTINE.value,
                "Quarantine requires a detected self-threat.",
            )
            return None
        transition = self.transition_to(
            ParanoiaState.SELF_QUARANTINE,
            "Internal quarantine released every controlled demonstration restriction.",
        )
        if transition is None:
            return None
        self._release_restrictions("Self-quarantine")
        if self._monitor is not None and hasattr(self._monitor, "stop"):
            self._monitor.stop()
        self._record(
            EventCategory.RECOVERY,
            Severity.HIGH,
            "CyberLockdown began internal quarantine and released its demonstration restrictions.",
            reason="Self-threat detected; quarantine restores the controlled environment.",
            previous_state=ParanoiaState.SELF_THREAT_DETECTED.value,
            new_state=ParanoiaState.SELF_QUARANTINE.value,
            action="self-quarantine",
        )
        self._save()
        self.changed.emit()
        return transition

    def complete_recovery(self) -> ParanoiaTransition | None:
        """Finish the sequence and enter RECOVERY."""
        if self._state is ParanoiaState.RECOVERY:
            return None
        if self._state is not ParanoiaState.SELF_QUARANTINE:
            self._record_rejected_transition(
                ParanoiaState.RECOVERY.value,
                "Recovery completion requires an active self-quarantine.",
            )
            return None
        transition = self.transition_to(
            ParanoiaState.RECOVERY,
            "The demonstration environment was restored and the quarantine finished.",
        )
        if transition is None:
            return None
        self._score = 0
        self._release_restrictions("Recovery")
        self.score_changed.emit(self._score)
        self._record(
            EventCategory.RECOVERY,
            Severity.INFO,
            "Recovery completed: the controlled demonstration environment is restored.",
            reason="Quarantine finished.",
            previous_state=ParanoiaState.SELF_QUARANTINE.value,
            new_state=ParanoiaState.RECOVERY.value,
            action="recovery-complete",
        )
        self.recovery_completed.emit(transition)
        self._save()
        self.changed.emit()
        return transition

    def quick_reset(self, reason: str = "Quick Reset from the Recovery Center.") -> bool:
        """Immediately restore NORMAL and release restrictions. Idempotent."""
        previous_state = self._state
        changed = (
            self._state is not ParanoiaState.NORMAL
            or self._score != 0
            or (self._monitor is not None and getattr(self._monitor, "enabled", lambda: False)())
        )
        if not changed:
            return False

        self._release_restrictions("Quick Reset")
        if self._monitor is not None and hasattr(self._monitor, "stop"):
            self._monitor.stop()
        self._score = 0
        self._state = ParanoiaState.NORMAL
        self._occurrences.clear()
        self._blocked_attempts.clear()
        self._blocked_findings.clear()
        self._maximum_alerted = False
        self._restrictions_released = False
        self._recovery_actions.append(
            RecoveryAction(
                datetime.now(),
                "Quick Reset returned the demonstration to NORMAL.",
                reason,
            )
        )
        self._record(
            EventCategory.RECOVERY,
            Severity.INFO,
            f"Quick Reset completed: {previous_state.label} -> Normal, paranoia score 0/100.",
            reason=reason,
            previous_state=previous_state.value,
            new_state=ParanoiaState.NORMAL.value,
            action="quick-reset",
        )
        self.score_changed.emit(self._score)
        self.state_changed.emit(previous_state, ParanoiaState.NORMAL)
        self.recovery_completed.emit(None)
        self._save()
        self.changed.emit()
        return True

    def full_demo_reset(self, reason: str = "Full Demo Reset from the Recovery Center.") -> bool:
        """Reset the demonstration session while preserving permanent audits."""
        self.quick_reset(reason)
        self._transitions.clear()
        self._event_history.clear()
        self._activities.clear()
        self._restrictions.clear()
        self._recovery_actions.clear()
        self._occurrences.clear()
        self._blocked_attempts.clear()
        self._blocked_findings.clear()
        self._record(
            EventCategory.RECOVERY,
            Severity.INFO,
            "Full Demo Reset completed: session history cleared and permanent audit "
            "reports preserved.",
            reason=reason,
            action="full-reset",
        )
        self._save()
        self.changed.emit()
        return True

    def prepare_emergency_exit(
        self, reason: str = "Emergency Exit requested by the user."
    ) -> bool:
        """Release everything needed for a safe close. No Windows changes."""
        self._release_restrictions("Emergency Exit")
        if self._monitor is not None and hasattr(self._monitor, "stop"):
            self._monitor.stop()
        self._record(
            EventCategory.RECOVERY,
            Severity.MEDIUM,
            "Emergency Exit prepared: controlled restrictions released, monitoring "
            "stopped and audit information saved.",
            reason=reason,
            previous_state=self._state.value,
            new_state=self._state.value,
            action="emergency-exit",
        )
        self._save()
        self.changed.emit()
        return True

    def _release_restrictions(self, label: str) -> None:
        if self._restrictions_released:
            return
        self._restrictions_released = True
        now = datetime.now()
        for action in (
            "Released controlled website restrictions.",
            "Released controlled download restrictions.",
            "Released controlled application launch restrictions.",
            "Released demonstration notification restrictions.",
            "Restored simulated personalization.",
            "Restored simulated Windows settings.",
            "Stopped optional Windows activity monitoring.",
            "Restored the initial controlled demonstration state.",
        ):
            self._recovery_actions.append(RecoveryAction(now, action, label))
        self._record(
            EventCategory.RECOVERY,
            Severity.INFO,
            f"{label}: all controlled demonstration restrictions were released.",
            reason="Recovery is idempotent and never modifies Windows security settings.",
            previous_state=self._state.value,
            new_state=self._state.value,
            action="release-restrictions",
        )

    # --- persistence and internals ----------------------------------------

    def _restore(self) -> None:
        snapshot = self._store.load()
        self._score = snapshot.score
        self._state = snapshot.state
        self._transitions.extend(snapshot.transitions)
        self._audit_reports = list(snapshot.audit_reports)
        for report in self._audit_reports:
            suffix = report.id.rsplit("-", 1)[-1]
            if suffix.isdigit():
                self._audit_sequence = max(self._audit_sequence, int(suffix))
        self._maximum_alerted = self._score >= SCORE_MAX

        if self._state.is_terminal:
            previous = self._state
            self._score = 0
            self._state = ParanoiaState.NORMAL
            self._restrictions_released = True
            self._record(
                EventCategory.RECOVERY,
                Severity.INFO,
                "Interrupted demonstration recovered safely at startup.",
                reason=(
                    f"The previous session ended in {previous.label}. Controlled "
                    "restrictions were released and the demonstration returned to Normal."
                ),
                previous_state=previous.value,
                new_state=ParanoiaState.NORMAL.value,
                action="startup-recovery",
            )

        for error in self._store.errors():
            self._record(
                EventCategory.RECOVERY,
                Severity.MEDIUM,
                "Paranoia persistence warning.",
                reason=error,
                action="persistence-warning",
            )

    def _save(self) -> None:
        if not self._store.save(
            self._score,
            self._state,
            tuple(self._transitions),
            tuple(self._audit_reports),
        ):
            self._record(
                EventCategory.PARANOIA,
                Severity.MEDIUM,
                "Paranoia state could not be written to disk.",
                reason="The demonstration continues in memory.",
                action="persistence-error",
            )

    def _record(
        self,
        category: EventCategory,
        severity: Severity,
        description: str,
        *,
        reason: str = "",
        previous_state: str = "",
        new_state: str = "",
        activity: str = "",
        action: str = "",
    ) -> ParanoiaEvent:
        event = ParanoiaEvent(
            timestamp=datetime.now(),
            category=category.value,
            severity=severity,
            description=description,
            reason=reason,
            source="Paranoia manager",
            previous_state=previous_state,
            new_state=new_state,
            activity=activity,
        )
        self._event_history.append(event)
        self._record_event_log(event, action=action)
        return event

    def _record_event_log(self, event: ParanoiaEvent, *, action: str = "") -> None:
        # Internal progression remains testable without presenting numeric suspicion
        # scores or exposed "paranoia" strings to ordinary security-log readers.
        self._events.record(
            _category_for(event.category),
            event.severity,
            event.description,
            source=event.source,
            reason=event.reason,
            previous_state=event.previous_state,
            new_state=event.new_state,
            activity=event.activity,
            action=action or "paranoia",
        )


def _category_for(value: str) -> EventCategory:
    lowered = value.casefold()
    if "audit" in lowered:
        return EventCategory.SELF_AUDIT
    if "recovery" in lowered or "quarantine" in lowered:
        return EventCategory.RECOVERY
    if "monitoring" in lowered:
        return EventCategory.MONITORING
    return EventCategory.PARANOIA


_FINDING_TITLES: dict[str, str] = {
    "launch_calculator": "Unauthorized mathematical activity detected",
    "launch_notepad": "Unauthorized text creation detected",
    "launch_paint": "Unauthorized image creation detected",
    "unfamiliar_website": "Unfamiliar website repeatedly requested",
    "download_request": "Repeated untrusted download requests",
    "wallpaper_change": "Repeated wallpaper modification attempts",
    "settings_open": "Repeated simulated settings access",
    "restricted_attempt": "Repeated restricted demonstration activity",
}
