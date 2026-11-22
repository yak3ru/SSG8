"""Application-only assessment and optional self-audit coordinator.

Application Control is user-enabled, not automatically turned on by browsing
or UI navigation. Windows process observation is read-only.
"""
from __future__ import annotations

from PySide6.QtCore import QObject, QTimer, Signal
from ssg8.security.decisions import ProtectionAction
from ssg8.services.paranoia.states import ParanoiaState


def audit_eligible(state: ParanoiaState, records: tuple) -> bool:
    return state is ParanoiaState.MAXIMUM_PARANOIA and sum(
        1 for record in records
        if record.module == 'application' and record.is_block
        and record.original_action in (ProtectionAction.ALLOW, ProtectionAction.REVIEW)
    ) >= 3


class AutonomousController(QObject):
    finale_requested = Signal(object)
    def __init__(self, protection, paranoia, state, parent=None):
        super().__init__(parent)
        self.protection, self.paranoia, self.state = protection, paranoia, state
        self._audit_scheduled = False
        self._finale_sent = False
        self.protection.set_autonomous_mode(True)
        if self.state.lockdown_active():
            self.state.set_lockdown(False, 'Application Control startup')
        self.paranoia.quick_reset('Application Control startup')
        self._disable_all()
        self.protection.decision_recorded.connect(self.on_decision)
        self.paranoia.state_changed.connect(self._on_change)
        self.paranoia.restriction_recorded.connect(self._on_change)
    def _disable_all(self) -> None:
        for module in self.protection.module_ids():
            self.protection.set_module_enabled(module, False, record=False)
        self.state.set_notification_control_enabled(False)
        self.protection.modules_changed.emit()
    def on_decision(self, decision) -> None:
        if decision.module != 'Application Control' or not self.protection.is_module_enabled('application'):
            return
        points = 12 if decision.action is ProtectionAction.BLOCK else 6
        self.paranoia.record_activity('restricted_attempt',target=decision.target,points=points,source='Application Control')
        self._schedule_audit()
    def _on_change(self, *_):
        self._schedule_audit()
    def _schedule_audit(self) -> None:
        if self._audit_scheduled or self._finale_sent:
            return
        if not audit_eligible(self.paranoia.state(),self.paranoia.restriction_records()):
            return
        self._audit_scheduled = True
        QTimer.singleShot(0,self._run_audit)
    def _run_audit(self) -> None:
        self._audit_scheduled = False
        if not audit_eligible(self.paranoia.state(),self.paranoia.restriction_records()):
            return
        report, _ = self.paranoia.run_self_audit()
        if report and report.has_violations and self.paranoia.state() is ParanoiaState.SELF_THREAT_DETECTED:
            self._finale_sent=True
            self.finale_requested.emit(report)
    def record_navigation(self, page_id: str):
        # Navigation must not trigger a security restriction.
        pass
    def reset(self):
        self.paranoia.full_demo_reset('Operator recovery')
        self._audit_scheduled=False
        self._finale_sent=False
        self._disable_all()
    def prepare_shutdown(self):
        self.paranoia.emergency_exit('Closing SSG8')
        self._disable_all()
