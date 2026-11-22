"""Lockdown Center: a strictly simulated lockdown inside SSG8."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit

from ssg8.core.models import EventCategory, Severity
from ssg8.ui.components.action_button import ActionButton
from ssg8.ui.components.chip import Chip
from ssg8.ui.components.data_table import DataTable
from ssg8.ui.components.dialog import confirm
from ssg8.ui.components.empty_state import EmptyState
from ssg8.ui.components.panel import ContentPanel
from ssg8.ui.components.section_heading import PageIntro, field_label, muted_label
from ssg8.ui.pages.base_page import BasePage
from ssg8.utils.formatting import format_timestamp

INACTIVE_TITLE = "No simulated lockdowns yet"
INACTIVE_TEXT = "Starting or ending a simulated lockdown is recorded here."


class LockdownPage(BasePage):
    """Start and end a demonstration lockdown that changes only SSG8 state."""

    page_id = "lockdown"

    def build(self) -> None:
        self._module_chips: dict[str, Chip] = {}

        self.body.addWidget(
            PageIntro(
                "Lockdown Center",
                "Run a simulated lockdown to preview a full protection state. The "
                "simulation is confined to this application and enables the internal "
                "protection engines.",
            )
        )
        self.add_demo_notice(
            "FLAGSHIP DEMONSTRATION ONLY. This never locks Windows, blocks the keyboard or "
            "mouse, disables Task Manager, changes the firewall or registry, or stops a "
            "service. You can always leave SSG8 normally.",
            "danger",
            "alert",
        )

        self.body.addWidget(self._build_state_panel())
        self.body.addWidget(self._build_modules_panel())
        self.body.addWidget(self._build_history_panel())

        self.context.state.lockdown_changed.connect(self._refresh_state)
        self.context.state.lockdown_history_changed.connect(self._refresh_history)
        self.context.protection.modules_changed.connect(self._refresh_modules)

        self._refresh_state()
        self._refresh_modules()
        self._refresh_history()

    # --- construction ------------------------------------------------------

    def _build_state_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Lockdown state",
            "Held in memory by SSG8. Nothing is written to Windows.",
        )

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)

        self._state_chip = Chip("INACTIVE", "neutral", panel)
        row.addWidget(self._state_chip, 0, Qt.AlignmentFlag.AlignVCenter)

        self._state_text = QLabel("", panel)
        self._state_text.setObjectName("MutedText")
        self._state_text.setWordWrap(True)
        row.addWidget(self._state_text, 1)

        panel.body.addLayout(row)
        panel.add_divider()

        panel.body.addWidget(field_label("Reason"))
        self._reason = QLineEdit(panel)
        self._reason.setPlaceholderText("Reason for the simulated lockdown (optional)")
        self._reason.setMinimumHeight(34)
        panel.body.addWidget(self._reason)

        panel.body.addWidget(
            muted_label(
                "The reason is stored with the simulated event so the demonstration is "
                "self explanatory."
            )
        )

        panel.add_divider()

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.setSpacing(8)
        buttons.addStretch(1)

        self._start_button = ActionButton("Start simulation", "primary", "lock", panel)
        self._start_button.clicked.connect(self._start_lockdown)
        buttons.addWidget(self._start_button)

        self._recover_button = ActionButton("End simulation", "secondary", "power", panel)
        self._recover_button.clicked.connect(self._end_lockdown)
        buttons.addWidget(self._recover_button)

        panel.body.addLayout(buttons)
        return panel

    def _build_modules_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Protection module state",
            "Lockdown enables all four internal modules. Recovery restores the exact "
            "states from before activation.",
        )

        for module_id in self.context.protection.module_ids():
            row = QHBoxLayout()
            row.setContentsMargins(0, 4, 0, 4)
            row.setSpacing(12)

            label = QLabel(self.context.protection.module_label(module_id), panel)
            label.setObjectName("ValueText")
            row.addWidget(label, 1)

            chip = Chip("Enabled", "success", panel)
            self._module_chips[module_id] = chip
            row.addWidget(chip, 0, Qt.AlignmentFlag.AlignVCenter)

            panel.body.addLayout(row)

        self._restore_note = muted_label("")
        panel.body.addWidget(self._restore_note)
        return panel

    def _build_history_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Previous simulated events",
            "Chronological record of simulated lockdown actions.",
        )

        self._table = DataTable(["Timestamp", "Action", "Reason"], panel)
        self._table.configure_columns({0: 150}, stretch=2)
        panel.body.addWidget(self._table)

        self._empty = EmptyState("lock", INACTIVE_TITLE, INACTIVE_TEXT, panel)
        panel.body.addWidget(self._empty)
        self.register_empty_pair(self._table, self._empty)
        return panel

    # --- state -------------------------------------------------------------

    def _refresh_state(self, _active: bool | None = None) -> None:
        active = self.context.state.lockdown_active()
        if active:
            self._state_chip.setText("SIMULATED LOCKDOWN ACTIVE")
            self._state_chip.set_tone("danger")
            self._state_text.setText(
                "SSG8 is showing the simulated lockdown state and all protection modules "
                "are enabled. Windows, input devices, processes and system settings are "
                "untouched."
            )
        else:
            self._state_chip.setText("INACTIVE")
            self._state_chip.set_tone("neutral")
            self._state_text.setText(
                "No simulated lockdown is running. Starting one changes only the "
                "demonstration state inside this window."
            )

        self._start_button.setEnabled(not active)
        self._recover_button.setEnabled(active)

    def _refresh_modules(self) -> None:
        states = self.context.protection.module_states()
        for module_id, chip in self._module_chips.items():
            enabled = bool(states.get(module_id, False))
            chip.setText("Enabled" if enabled else "Disabled")
            chip.set_tone("success" if enabled else "neutral")

        if self.context.protection.lockdown_snapshot_active:
            self._restore_note.setText(
                "Previous module states are saved and will be restored when the "
                "simulation ends."
            )
        else:
            self._restore_note.setText(
                "No pre-lockdown module state is currently saved."
            )

    def _refresh_history(self) -> None:
        self._table.clear_rows()
        for event in self.context.state.lockdown_history():
            self._table.add_row(
                [format_timestamp(event.timestamp), event.action, event.reason],
                event,
            )
        if not self.context.state.lockdown_history():
            self._empty.set_content("lock", INACTIVE_TITLE, INACTIVE_TEXT)
        self.sync_empty_states()

    # --- actions -----------------------------------------------------------

    def _start_lockdown(self) -> None:
        accepted = confirm(
            self,
            "Start simulated lockdown",
            "This changes only the SSG8 demonstration state and enables the internal "
            "protection modules.\n\n"
            "Windows is not locked, input is not blocked, Task Manager still works and no "
            "system setting changes.\n\nStart the simulation?",
            confirm_label="Start simulation",
            danger=True,
        )
        if not accepted:
            return

        event = self.context.state.set_lockdown(True, self._reason.text())
        if event is not None:
            self.context.events.record(
                EventCategory.LOCKDOWN,
                Severity.HIGH,
                f"{event.action}: {event.reason}",
            )
        self._refresh_state()
        self._refresh_history()

    def _end_lockdown(self) -> None:
        accepted = confirm(
            self,
            "End simulated lockdown",
            "End the simulated lockdown, restore the previous protection module states "
            "and return to the normal demonstration state?",
            confirm_label="End simulation",
        )
        if not accepted:
            return

        event = self.context.state.set_lockdown(False, self._reason.text())
        if event is not None:
            self.context.events.record(
                EventCategory.LOCKDOWN,
                Severity.INFO,
                f"{event.action}: {event.reason}",
            )
        self._refresh_state()
        self._refresh_history()

    def on_shown(self) -> None:
        self._refresh_state()
        self._refresh_modules()
        self._refresh_history()

    # --- convenience for tests --------------------------------------------

    def start_simulation(self, reason: str = "Automated check") -> None:
        """Start the simulation without a confirmation dialog (tests only)."""
        event = self.context.state.set_lockdown(True, reason)
        if event is not None:
            self.context.events.record(
                EventCategory.LOCKDOWN, Severity.HIGH, f"{event.action}: {event.reason}"
            )
        self._refresh_state()
        self._refresh_history()

    def end_simulation(self) -> None:
        """End the simulation without a confirmation dialog (tests only)."""
        event = self.context.state.set_lockdown(False, "Automated check")
        if event is not None:
            self.context.events.record(
                EventCategory.LOCKDOWN, Severity.INFO, f"{event.action}: {event.reason}"
            )
        self._refresh_state()
        self._refresh_history()

    def state_text(self) -> str:
        return self._state_chip.text()

    def module_states(self) -> dict[str, bool]:
        return self.context.protection.module_states()
