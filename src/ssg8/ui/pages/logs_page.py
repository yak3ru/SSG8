"""Security Logs: application events plus structured protection decisions."""

from __future__ import annotations

from datetime import datetime, timedelta

from PySide6.QtWidgets import QHBoxLayout

from ssg8.core.models import EventCategory, Severity
from ssg8.security.decisions import ProtectionAction
from ssg8.security.protection_manager import MODULE_DEFINITIONS, MODULE_LABELS
from ssg8.ui import theme
from ssg8.ui.components.action_button import ActionButton
from ssg8.ui.components.chip import ChipCell
from ssg8.ui.components.data_table import DataTable
from ssg8.ui.components.dialog import confirm
from ssg8.ui.components.empty_state import EmptyState
from ssg8.ui.components.panel import ContentPanel
from ssg8.ui.components.protection import action_tone
from ssg8.ui.components.search_input import SearchInput, SelectBox
from ssg8.ui.components.section_heading import PageIntro
from ssg8.ui.pages.base_page import BasePage
from ssg8.utils.formatting import format_timestamp

EMPTY_TITLE = "No application events"
EMPTY_TEXT = (
    "SSG8 records its own interface and protection events here. This list is not a "
    "Windows security log."
)

FILTERED_TITLE = "No matching events"
FILTERED_TEXT = "No application event matches the current filters."

DECISION_EMPTY_TITLE = "No protection decisions yet"
DECISION_EMPTY_TEXT = (
    "Every website, download, application and notification evaluation appears here "
    "with its module, target, decision and reason."
)


class LogsPage(BasePage):
    """Searchable event log and structured protection decision history."""

    page_id = "logs"

    def build(self) -> None:
        self.body.addWidget(
            PageIntro(
                "Security Logs",
                "Every entry here was produced by SSG8. Windows event logs are never read "
                "and no operating system security event is claimed.",
            )
        )


        self.body.addWidget(self._build_events_panel())
        self.body.addWidget(self._build_decisions_panel())

        self.context.events.changed.connect(self._refresh)
        self.context.protection.changed.connect(self._refresh_decisions)
        self._refresh()
        self._refresh_decisions()

    # --- construction ------------------------------------------------------

    def _build_events_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Application event log",
            "Newest entries first. The log is bounded to the most recent 500 events.",
        )

        refresh_button = ActionButton("Refresh", "secondary", "refresh", panel)
        refresh_button.clicked.connect(self._refresh)
        panel.add_action(refresh_button)

        clear_button = ActionButton("Clear", "danger", "trash", panel)
        clear_button.clicked.connect(self._clear)
        panel.add_action(clear_button)

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(0, 0, 0, 0)
        toolbar.setSpacing(10)

        self._search = SearchInput("Search events", panel)
        self._search.textChanged.connect(self._refresh)
        toolbar.addWidget(self._search, 1)

        self._severity_filter = SelectBox(panel)
        self._severity_filter.add_options(
            [("All severities", None)] + [(s.value, s) for s in Severity]
        )
        self._severity_filter.currentIndexChanged.connect(self._refresh)
        toolbar.addWidget(self._severity_filter)

        self._category_filter = SelectBox(panel)
        self._category_filter.add_options(
            [("All categories", None)] +
            [("Policy Evaluation" if c is EventCategory.PARANOIA else c.value, c)
             for c in EventCategory]
        )
        self._category_filter.currentIndexChanged.connect(self._refresh)
        toolbar.addWidget(self._category_filter)
        panel.body.addLayout(toolbar)

        filters = QHBoxLayout()
        filters.setContentsMargins(0, 0, 0, 0)
        filters.setSpacing(10)

        self._module_filter = SelectBox(panel)
        self._module_filter.add_options(
            [("All modules", None)]
            + [(label, module_id) for module_id, label in MODULE_DEFINITIONS]
        )
        self._module_filter.currentIndexChanged.connect(self._refresh)
        filters.addWidget(self._module_filter)

        self._event_decision_filter = SelectBox(panel)
        self._event_decision_filter.add_options(
            [("All decisions", None)]
            + [(action.label, action.value) for action in ProtectionAction]
        )
        self._event_decision_filter.currentIndexChanged.connect(self._refresh)
        filters.addWidget(self._event_decision_filter)

        self._time_filter = SelectBox(panel)
        self._time_filter.add_options(
            [
                ("Any time", None),
                ("Last hour", 3600),
                ("Last 24 hours", 86400),
                ("Last 7 days", 604800),
            ]
        )
        self._time_filter.currentIndexChanged.connect(self._refresh)
        filters.addWidget(self._time_filter)
        filters.addStretch(1)
        panel.body.addLayout(filters)

        self._table = DataTable(
            ["Timestamp", "Event type", "Module", "Severity", "Description"],
            panel,
        )
        self._table.configure_columns({0: 140, 1: 105, 2: 140, 3: 90}, stretch=4)
        panel.body.addWidget(self._table)

        self._empty = EmptyState("logs", EMPTY_TITLE, EMPTY_TEXT, panel)
        panel.body.addWidget(self._empty)
        self.register_empty_pair(self._table, self._empty)
        return panel

    def _build_decisions_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Protection decisions",
            "Module, target, decision and reason for every evaluation. These rows are "
            "also recorded in the application event log.",
        )

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(0, 0, 0, 0)
        toolbar.setSpacing(10)

        self._decision_search = SearchInput("Search decisions", panel)
        self._decision_search.textChanged.connect(self._refresh_decisions)
        toolbar.addWidget(self._decision_search, 1)

        self._decision_filter = SelectBox(panel)
        self._decision_filter.add_options(
            [("All decisions", None)]
            + [(action.label, action.value) for action in ProtectionAction]
        )
        self._decision_filter.currentIndexChanged.connect(self._refresh_decisions)
        toolbar.addWidget(self._decision_filter)
        panel.body.addLayout(toolbar)

        self._decision_table = DataTable(
            ["Time", "Module", "Target", "Decision", "Reason"], panel, row_height=36
        )
        self._decision_table.configure_columns(
            {0: 148, 1: 135, 2: 200, 3: 110}, stretch=4
        )
        panel.body.addWidget(self._decision_table)

        self._decision_empty = EmptyState(
            "shield", DECISION_EMPTY_TITLE, DECISION_EMPTY_TEXT, panel
        )
        panel.body.addWidget(self._decision_empty)
        self.register_empty_pair(self._decision_table, self._decision_empty)
        return panel

    # --- data --------------------------------------------------------------

    def _refresh(self) -> None:
        search = self._search.text()
        severity = self._severity_filter.current_as(Severity)
        category = self._category_filter.current_as(EventCategory)
        module_id = self._module_filter.current_value()
        action = self._event_decision_filter.current_value()
        seconds = self._time_filter.current_value()
        since = (
            datetime.now() - timedelta(seconds=seconds)
            if isinstance(seconds, int)
            else None
        )

        entries = self.context.events.filtered(
            search=search,
            severity=severity,
            category=category,
            module_id=str(module_id) if module_id is not None else None,
            action=str(action) if action is not None else None,
            since=since,
        )

        self._table.clear_rows()
        for entry in entries:
            module = MODULE_LABELS.get(entry.module_id, "SSG8")
            self._table.add_row(
                [
                    format_timestamp(entry.timestamp),
                    "Policy Evaluation" if entry.category is EventCategory.PARANOIA else entry.category.value,
                    module,
                    ChipCell(entry.severity.value, theme.severity_tone(entry.severity)),
                    ("Security policy evaluation completed." if entry.category is EventCategory.PARANOIA
                     and "paranoia" in entry.message.casefold() else entry.message),
                ],
                entry,
            )

        filtered = (
            bool(search.strip())
            or severity is not None
            or category is not None
            or module_id is not None
            or action is not None
            or since is not None
        )
        if entries:
            self._empty.set_content("logs", EMPTY_TITLE, EMPTY_TEXT)
        elif filtered:
            self._empty.set_content("search", FILTERED_TITLE, FILTERED_TEXT)
        else:
            self._empty.set_content("logs", EMPTY_TITLE, EMPTY_TEXT)

        self.sync_empty_states()

    def _refresh_decisions(self) -> None:
        query = self._decision_search.text().strip().casefold()
        action = self._decision_filter.current_value()
        actions = [ProtectionAction(action)] if action is not None else None

        decisions = self.context.protection.decisions(actions=actions)
        self._decision_table.clear_rows()
        for decision in decisions:
            if (
                query
                and query not in decision.target.casefold()
                and query not in decision.reason.casefold()
                and query not in decision.module.casefold()
            ):
                continue
            self._decision_table.add_row(
                [
                    format_timestamp(decision.timestamp),
                    decision.module,
                    decision.target,
                    ChipCell(decision.action_label, action_tone(decision.action)),
                    decision.reason,
                ],
                decision,
            )

        if self._decision_table.rowCount():
            self._decision_empty.set_content(
                "shield", DECISION_EMPTY_TITLE, DECISION_EMPTY_TEXT
            )
        elif query or action is not None:
            self._decision_empty.set_content(
                "search",
                "No matching decisions",
                "No protection decision matches the current filters.",
            )
        else:
            self._decision_empty.set_content(
                "shield", DECISION_EMPTY_TITLE, DECISION_EMPTY_TEXT
            )

        self.sync_empty_states()

    # --- actions -----------------------------------------------------------

    def _clear(self) -> None:
        if self.context.events.count() == 0:
            return
        accepted = confirm(
            self,
            "Clear application events",
            "Remove all recorded application events? This only clears SSG8's own "
            "interface log.",
            confirm_label="Clear events",
            danger=True,
        )
        if not accepted:
            return
        self.context.events.clear()
        self.context.events.record(
            EventCategory.APPLICATION,
            Severity.INFO,
            "Application event log cleared",
        )
        self._refresh()

    def on_shown(self) -> None:
        self._refresh()
        self._refresh_decisions()

    # --- convenience for tests --------------------------------------------

    def visible_events(self) -> int:
        return self._table.rowCount()

    def visible_decisions(self) -> int:
        return self._decision_table.rowCount()
