"""Shared widgets for the internal protection engines."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ssg8.security.decisions import ProtectionAction, ProtectionDecision
from ssg8.security.protection_manager import ProtectionManager
from ssg8.ui.components.chip import Chip
from ssg8.ui.components.toggle_switch import ToggleSwitch

ACTION_TONES: dict[ProtectionAction, str] = {
    ProtectionAction.ALLOW: "success",
    ProtectionAction.BLOCK: "danger",
    ProtectionAction.REVIEW: "warning",
}


def action_tone(action: ProtectionAction) -> str:
    """Return the semantic tone used for a decision in the interface."""
    return ACTION_TONES.get(action, "neutral")


class DecisionSummary(QWidget):
    """A chip, a reason and the matched rule for the latest decision."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)

        self._chip = Chip("Not evaluated", "neutral", self)
        row.addWidget(self._chip, 0, Qt.AlignmentFlag.AlignTop)

        text_column = QVBoxLayout()
        text_column.setContentsMargins(0, 0, 0, 0)
        text_column.setSpacing(2)

        self._reason = QLabel("No request has been evaluated yet.", self)
        self._reason.setObjectName("ValueText")
        self._reason.setWordWrap(True)
        text_column.addWidget(self._reason)

        self._rule = QLabel("", self)
        self._rule.setObjectName("MutedText")
        self._rule.setWordWrap(True)
        self._rule.setVisible(False)
        text_column.addWidget(self._rule)

        row.addLayout(text_column, 1)

    def set_decision(self, decision: ProtectionDecision) -> None:
        self._chip.setText(decision.action_label.upper())
        self._chip.set_tone(action_tone(decision.action))
        self._reason.setText(decision.reason)
        if decision.rule is not None:
            self._rule.setText(f"Matched rule: {decision.rule_label}")
            self._rule.setVisible(True)
        else:
            self._rule.setText("")
            self._rule.setVisible(False)

    def set_message(self, message: str) -> None:
        self._chip.setText("Not evaluated")
        self._chip.set_tone("neutral")
        self._reason.setText(message)
        self._rule.setText("")
        self._rule.setVisible(False)

    def reason(self) -> str:
        return self._reason.text()


class ProtectionModuleRow(QWidget):
    """Show one engine's enabled state and let the user switch it."""

    def __init__(
        self,
        manager: ProtectionManager,
        module_id: str,
        parent: QWidget | None = None,
        *,
        description: str = "Internal evaluation only. Nothing outside SSG8 is affected.",
    ) -> None:
        super().__init__(parent)
        self._manager = manager
        self._module_id = module_id

        self._re_enable_timer = QTimer(self)
        self._re_enable_timer.setSingleShot(True)
        self._re_enable_timer.setInterval(1000)
        self._re_enable_timer.timeout.connect(self._re_enable)

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)

        text_column = QVBoxLayout()
        text_column.setContentsMargins(0, 0, 0, 0)
        text_column.setSpacing(2)

        title = QLabel(f"{manager.module_label(module_id)} enabled", self)
        title.setObjectName("ValueText")
        text_column.addWidget(title)

        caption = QLabel(description, self)
        caption.setObjectName("MutedText")
        caption.setWordWrap(True)
        text_column.addWidget(caption)

        row.addLayout(text_column, 1)

        self._chip = Chip("Enabled", "success", self)
        row.addWidget(self._chip, 0, Qt.AlignmentFlag.AlignVCenter)

        self._switch = ToggleSwitch(
            self, checked=manager.is_module_enabled(module_id), tone="success"
        )
        self._switch.setAccessibleName(f"{manager.module_label(module_id)} enabled")
        self._switch.toggled.connect(self._on_toggled)
        row.addWidget(self._switch, 0, Qt.AlignmentFlag.AlignVCenter)

        manager.modules_changed.connect(self._refresh)
        self._refresh()

    def _on_toggled(self, checked: bool) -> None:
        self._manager.set_module_enabled(self._module_id, checked)
        self._update_chip(checked)

        if not checked:
            self._re_enable_timer.start()
        else:
            self._re_enable_timer.stop()

    def _re_enable(self) -> None:
        # Calling setChecked(True) instead of set_state_silently(True)
        # lets ToggleSwitch run its built-in slide animation.
        if not self._switch.isChecked():
            self._switch.setChecked(True)

    def _update_chip(self, enabled: bool) -> None:
        self._chip.setText("Enabled" if enabled else "Disabled")
        self._chip.set_tone("success" if enabled else "neutral")

    def _refresh(self) -> None:
        enabled = self._manager.is_module_enabled(self._module_id)
        if self._switch.isChecked() != enabled:
            self._switch.set_state_silently(enabled)
        self._update_chip(enabled)

    def switch(self) -> ToggleSwitch:
        return self._switch
