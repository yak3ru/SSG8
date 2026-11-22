"""Notification Control: internal notification simulation and category rules."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QVBoxLayout, QWidget

from ssg8.core.app_state import NOTIFICATION_CATEGORIES
from ssg8.core.models import EventCategory, Severity
from ssg8.ui.components.action_button import ActionButton
from ssg8.ui.components.chip import CellContainer, Chip, ChipCell
from ssg8.ui.components.data_table import DataTable
from ssg8.ui.components.dialog import confirm, prompt_text
from ssg8.ui.components.empty_state import EmptyState
from ssg8.ui.components.panel import ContentPanel
from ssg8.ui.components.protection import DecisionSummary, action_tone
from ssg8.ui.components.search_input import SelectBox
from ssg8.ui.components.section_heading import PageIntro, field_label
from ssg8.ui.components.toggle_switch import ToggleSwitch
from ssg8.ui.pages.base_page import BasePage
from ssg8.utils.formatting import format_timestamp

EMPTY_TITLE = "No applications configured"
EMPTY_TEXT = (
    "Add an application to describe how its notifications should be treated. "
    "SSG8 does not change Windows notification settings."
)
HISTORY_TITLE = "No notification requests yet"
HISTORY_TEXT = (
    "Submit an SSG8-managed notification for policy evaluation."
)

PREFERENCES: tuple[tuple[str, str, str], ...] = (
    (
        "toast_notifications",
        "Suppress toast notifications",
        "Preferred treatment for application toasts (application-level configuration).",
    ),
    (
        "tray_notifications",
        "Suppress tray balloon notifications",
        "Preferred treatment for tray balloons (application-level configuration).",
    ),
    (
        "critical_alerts",
        "Always allow critical alerts",
        "Keeps emergency alerts visible in the internal notification service.",
    ),
)


class NotificationsPage(BasePage):
    """Evaluate internal notifications against master and category settings."""

    page_id = "notifications"

    def __init__(self, context, parent=None) -> None:
        super().__init__(context, parent)
        self._suppress_refresh = False
        self._preference_switches: dict[str, ToggleSwitch] = {}
        self._category_switches: dict[str, ToggleSwitch] = {}
        self._category_labels: dict[str, str] = dict(NOTIFICATION_CATEGORIES)

    def build(self) -> None:
        self.body.addWidget(
            PageIntro(
                "Notification Control",
            "Review notifications generated inside SSG8 against configured policies.",
            )
        )


        self.body.addWidget(self._build_master_panel())
        self.body.addWidget(self._build_categories_panel())
        self.body.addWidget(self._build_simulation_panel())
        self.body.addWidget(self._build_targets_panel())
        self.body.addWidget(self._build_preferences_panel())

        self.context.state.notifications_changed.connect(self._refresh)
        self.context.protection.changed.connect(self._refresh_history)
        self._refresh()
        self._refresh_history()

    # --- construction ------------------------------------------------------

    def _build_master_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Notification protection",
            "Master switch for the internal notification engine.",
        )

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)

        text_column = QVBoxLayout()
        text_column.setContentsMargins(0, 0, 0, 0)
        text_column.setSpacing(2)

        title = QLabel("Enable notification protection", panel)
        title.setObjectName("ValueText")
        text_column.addWidget(title)

        description = QLabel(
            "When disabled, every internal notification evaluates to BLOCK. "
            "Windows notifications are unaffected.",
            panel,
        )
        description.setObjectName("MutedText")
        description.setWordWrap(True)
        text_column.addWidget(description)

        row.addLayout(text_column, 1)

        self._master_switch = ToggleSwitch(
            panel,
            checked=self.context.state.notification_control_enabled(),
            tone="success",
        )
        self._master_switch.setAccessibleName("Enable notification protection")
        self._master_switch.toggled.connect(self._on_master_toggled)
        row.addWidget(self._master_switch, 0, Qt.AlignmentFlag.AlignVCenter)

        panel.body.addLayout(row)

        badge_row = QHBoxLayout()
        badge_row.setContentsMargins(0, 0, 0, 0)
        self._status_chip = Chip("Disabled", "neutral", panel)
        badge_row.addWidget(self._status_chip)
        badge_row.addStretch(1)
        panel.body.addLayout(badge_row)
        return panel

    def _build_categories_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Notification categories",
            "Categories used by the internal notification simulator.",
        )
        for index, (key, label) in enumerate(NOTIFICATION_CATEGORIES):
            if index:
                panel.add_divider()
            panel.body.addWidget(self._category_row(panel, key, label))
        return panel

    def _category_row(self, parent: QWidget, key: str, label: str) -> QWidget:
        row_widget = QWidget(parent)
        row = QHBoxLayout(row_widget)
        row.setContentsMargins(0, 4, 0, 4)
        row.setSpacing(12)

        text = QLabel(label, row_widget)
        text.setObjectName("ValueText")
        text.setWordWrap(True)
        row.addWidget(text, 1)

        switch = ToggleSwitch(
            row_widget,
            checked=self.context.state.notification_categories().get(key, True),
            tone="accent",
        )
        switch.setAccessibleName(f"Allow {label}")
        switch.toggled.connect(lambda checked, name=key: self._on_category_toggled(name, checked))
        self._category_switches[key] = switch
        row.addWidget(switch, 0, Qt.AlignmentFlag.AlignVCenter)
        return row_widget

    def _build_simulation_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Notification assessment",
            "Inspect notification delivery requests managed by SSG8.",
        )

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)

        self._category_select = SelectBox(panel)
        self._category_select.add_options(
            [(label, key) for key, label in NOTIFICATION_CATEGORIES]
        )
        row.addWidget(self._category_select)

        self._message_input = QLineEdit(panel)
        self._message_input.setPlaceholderText("Notification message")
        self._message_input.setMinimumHeight(34)
        self._message_input.returnPressed.connect(self._simulate)
        row.addWidget(self._message_input, 1)

        simulate_button = ActionButton("Evaluate", "primary", "bell", panel)
        simulate_button.clicked.connect(self._simulate)
        row.addWidget(simulate_button)
        panel.body.addLayout(row)

        self._decision = DecisionSummary(panel)
        panel.body.addWidget(self._decision)

        panel.add_divider()
        panel.body.addWidget(field_label("Recent notification evaluations"))

        self._history = DataTable(
            ["Time", "Category", "Decision", "Reason"], panel, row_height=36
        )
        self._history.configure_columns({0: 148, 1: 185, 2: 110}, stretch=3)
        panel.body.addWidget(self._history)

        self._history_empty = EmptyState(
            "logs", HISTORY_TITLE, HISTORY_TEXT, panel, minimum_height=140
        )
        panel.body.addWidget(self._history_empty)
        self.register_empty_pair(self._history, self._history_empty)
        return panel

    def _build_targets_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Configured applications",
            "Per-application notification preference. Nothing is enforced on Windows.",
        )

        self._add_button = ActionButton("Add app", "primary", "plus", panel)
        self._add_button.clicked.connect(self._add_target)
        panel.add_action(self._add_button)

        self._remove_button = ActionButton("Remove", "danger", "trash", panel)
        self._remove_button.setEnabled(False)
        self._remove_button.clicked.connect(self._remove_target)
        panel.add_action(self._remove_button)

        self._table = DataTable(["Application", "Notifications", "Added"], panel)
        self._table.configure_columns({0: 240, 1: 150, 2: 165}, stretch=0)
        self._table.itemSelectionChanged.connect(self._update_buttons)
        panel.body.addWidget(self._table)

        self._empty = EmptyState("bell", EMPTY_TITLE, EMPTY_TEXT, panel)
        panel.body.addWidget(self._empty)
        self.register_empty_pair(self._table, self._empty)
        return panel

    def _build_preferences_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Notification preferences",
            "Additional application-level preferences for the internal service.",
        )

        for index, (key, title, description) in enumerate(PREFERENCES):
            if index:
                panel.add_divider()
            panel.body.addWidget(self._preference_row(panel, key, title, description))
        return panel

    def _preference_row(self, parent: QWidget, key: str, title: str, description: str) -> QWidget:
        row_widget = QWidget(parent)
        row = QHBoxLayout(row_widget)
        row.setContentsMargins(0, 4, 0, 4)
        row.setSpacing(12)

        text_column = QVBoxLayout()
        text_column.setContentsMargins(0, 0, 0, 0)
        text_column.setSpacing(2)

        title_label = QLabel(title, row_widget)
        title_label.setObjectName("ValueText")
        text_column.addWidget(title_label)

        description_label = QLabel(description, row_widget)
        description_label.setObjectName("MutedText")
        description_label.setWordWrap(True)
        text_column.addWidget(description_label)

        row.addLayout(text_column, 1)

        switch = ToggleSwitch(
            row_widget,
            checked=self.context.state.notification_preferences().get(key, False),
            tone="accent",
        )
        switch.setAccessibleName(title)
        switch.toggled.connect(lambda checked, name=key: self._on_preference_toggled(name, checked))
        self._preference_switches[key] = switch
        row.addWidget(switch, 0, Qt.AlignmentFlag.AlignVCenter)
        return row_widget

    # --- data --------------------------------------------------------------

    def _refresh(self) -> None:
        if self._suppress_refresh:
            return

        enabled = self.context.state.notification_control_enabled()
        self._master_switch.set_state_silently(enabled)
        self._status_chip.setText("Enabled" if enabled else "Disabled")
        self._status_chip.set_tone("success" if enabled else "neutral")

        for key, switch in self._preference_switches.items():
            switch.set_state_silently(
                self.context.state.notification_preferences().get(key, False)
            )
        for key, switch in self._category_switches.items():
            switch.set_state_silently(
                self.context.state.notification_categories().get(key, True)
            )

        self._table.clear_rows()
        for target in reversed(self.context.state.notification_targets()):
            switch = ToggleSwitch(self._table, checked=target.suppress, tone="accent")
            switch.setAccessibleName(f"Suppress notifications for {target.application}")
            switch.toggled.connect(
                lambda checked, name=target.application: self._on_target_toggled(name, checked)
            )
            self._table.add_row(
                [target.application, CellContainer(switch), format_timestamp(target.added)],
                target,
            )

        self.sync_empty_states()
        self._update_buttons()

    def _refresh_history(self) -> None:
        decisions = self.context.protection.decisions("notification", limit=12)
        self._history.clear_rows()
        for decision in decisions:
            self._history.add_row(
                [
                    format_timestamp(decision.timestamp),
                    decision.metadata.get("label", decision.target),
                    ChipCell(decision.action_label, action_tone(decision.action)),
                    decision.reason,
                ],
                decision,
            )
        if decisions:
            self._history_empty.set_content("logs", HISTORY_TITLE, HISTORY_TEXT)
        else:
            self._history_empty.set_content("logs", HISTORY_TITLE, HISTORY_TEXT)
        self.sync_empty_states()

    def _update_buttons(self) -> None:
        self._remove_button.setEnabled(self._table.has_selection())

    # --- actions -----------------------------------------------------------

    def _on_master_toggled(self, checked: bool) -> None:
        self.context.state.set_notification_control_enabled(checked)
        self.context.protection.set_module_enabled(
            "notification", checked, record=False
        )
        self.context.events.record(
            EventCategory.PREFERENCE,
            Severity.INFO,
            f"Notification protection {'enabled' if checked else 'disabled'}",
        )
        self._refresh()

    def _on_category_toggled(self, key: str, checked: bool) -> None:
        self._suppress_refresh = True
        try:
            self.context.protection.set_notification_category(key, checked)
        finally:
            self._suppress_refresh = False

    def _simulate(self) -> None:
        category = self._category_select.current_value()
        message = self._message_input.text().strip()
        if not isinstance(category, str):
            self._decision.set_message("Choose a notification category.")
            return

        decision = self.context.protection.evaluate_notification(category, message)
        self._decision.set_decision(decision)
        self._refresh_history()
        self.notify_decision(decision)
        if decision.action.value == "allow" and message:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.information(self, "SSG8 Notification", message)

    def _on_target_toggled(self, application: str, checked: bool) -> None:
        self._suppress_refresh = True
        try:
            self.context.state.set_notification_suppressed(application, checked)
            self.context.events.record(
                EventCategory.CONFIGURATION,
                Severity.INFO,
                f"Notifications for {application} set to "
                f"{'suppressed' if checked else 'allowed'} (configuration only)",
            )
        finally:
            self._suppress_refresh = False

    def _on_preference_toggled(self, key: str, checked: bool) -> None:
        self.context.state.set_notification_preference(key, checked)
        self.context.events.record(
            EventCategory.PREFERENCE,
            Severity.INFO,
            f"Notification preference '{key}' set to {checked} (configuration only)",
        )

    def _add_target(self) -> None:
        def validate(value: str) -> str | None:
            if not value.strip():
                return "Enter an application name."
            if any(
                target.application.casefold() == value.strip().casefold()
                for target in self.context.state.notification_targets()
            ):
                return "That application is already configured."
            return None

        application = prompt_text(
            self,
            title="Add application",
            label="Application name",
            placeholder="e.g. Microsoft Teams",
            confirm_label="Add application",
            validator=validate,
            description="Stored in this session only. Windows notifications are unchanged.",
        )
        if not application:
            return

        target = self.context.state.add_notification_target(application)
        if target is None:
            return
        self.context.events.record(
            EventCategory.CONFIGURATION,
            Severity.INFO,
            f"Notification preference added: {target.application} (configuration only)",
        )
        self._refresh()

    def _remove_target(self) -> None:
        target = self._table.selected_payload()
        if target is None:
            return

        if self.context.preferences.get("confirm_before_delete"):
            accepted = confirm(
                self,
                "Remove application",
                f"Remove {target.application} from the notification configuration?",
                confirm_label="Remove",
                danger=True,
            )
            if not accepted:
                return

        if self.context.state.remove_notification_target(target.application):
            self.context.events.record(
                EventCategory.CONFIGURATION,
                Severity.INFO,
                f"Notification preference removed: {target.application}",
            )
        self._refresh()

    def on_shown(self) -> None:
        self._refresh()
        self._refresh_history()

    # --- convenience for tests --------------------------------------------

    def add_entry(self, application: str) -> None:
        """Add a notification target without a dialog (used by automated checks)."""
        self.context.state.add_notification_target(application)
        self._refresh()

    def simulate(self, category: str, message: str = "Test notification"):
        self._category_select.setCurrentIndex(
            max(0, self._category_select.findData(category))
        )
        self._message_input.setText(message)
        self._simulate()
        return self.context.protection.last_decision()

    def visible_evaluations(self) -> int:
        return self._history.rowCount()
