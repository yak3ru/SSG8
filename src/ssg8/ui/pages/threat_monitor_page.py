"""Threat Monitor: internal threat analysis and alert overview.

Every number on this page is derived from decisions SSG8 produced for requests
submitted to it. There is no fabricated activity and no claim of malware or
system-wide monitoring.
"""

from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ssg8.security.analysis.models import (
    AlertStatus,
    IncidentStatus,
    RiskLevel,
)
from ssg8.security.protection_manager import MODULE_DEFINITIONS, MODULE_LABELS
from ssg8.ui.components.action_button import ActionButton
from ssg8.ui.components.chip import Chip, ChipCell
from ssg8.ui.components.data_table import DataTable
from ssg8.ui.components.dialog import FieldSpec, prompt_form
from ssg8.ui.components.empty_state import EmptyState
from ssg8.ui.components.info_list import InfoList
from ssg8.ui.components.panel import ContentPanel
from ssg8.ui.components.protection import action_tone
from ssg8.ui.components.risk_chart import RiskTrendChart
from ssg8.ui.components.search_input import SearchInput, SelectBox
from ssg8.ui.components.section_heading import PageIntro
from ssg8.ui.components.stat_card import StatCard
from ssg8.ui.pages.base_page import BasePage
from ssg8.utils.formatting import format_timestamp

FINDINGS_EMPTY_TITLE = "No analysis findings yet"
FINDINGS_EMPTY_TEXT = (
    "Findings appear only when SSG8 detects repeated or cross-module policy "
    "activity in its own protection decisions. Nothing is fabricated."
)

ALERTS_EMPTY_TITLE = "No security alerts"
ALERTS_EMPTY_TEXT = (
    "Alerts are generated from real analysis findings once their risk score "
    "reaches the configured alert threshold."
)

INCIDENTS_EMPTY_TITLE = "No incidents yet"
INCIDENTS_EMPTY_TEXT = (
    "Related findings are grouped into an incident when they share a target, "
    "module and detection window."
)

ALERT_TONES: dict[AlertStatus, str] = {
    AlertStatus.NEW: "accent",
    AlertStatus.ACKNOWLEDGED: "warning",
    AlertStatus.RESOLVED: "success",
    AlertStatus.DISMISSED: "neutral",
}

INCIDENT_TONES: dict[IncidentStatus, str] = {
    IncidentStatus.OPEN: "accent",
    IncidentStatus.INVESTIGATING: "warning",
    IncidentStatus.RESOLVED: "success",
    IncidentStatus.CLOSED: "neutral",
}


class ThreatMonitorPage(BasePage):
    """Threat-intelligence overview backed by real SSG8 analysis records."""

    page_id = "threat-monitor"

    def build(self) -> None:
        self._distribution_labels: dict[RiskLevel, QLabel] = {}
        self._activity_labels: dict[str, QLabel] = {}

        self.body.addWidget(
            PageIntro(
                "Threat Monitor",
                "Deterministic analysis of SSG8's own protection decisions: risk "
                "findings, security alerts and incident overview. These are policy "
                "anomalies, not verified malware or Windows threat telemetry.",
            )
        )


        self.body.addWidget(self._build_overview_panel())
        self.body.addWidget(self._build_middle_row())
        self.body.addWidget(self._build_trend_panel())
        self.body.addWidget(self._build_findings_panel())
        self.body.addWidget(self._build_decisions_panel())
        self.body.addWidget(self._build_alerts_panel())
        self.body.addWidget(self._build_incidents_panel())

        self.context.analysis.changed.connect(self._refresh)
        self.context.protection.changed.connect(self._refresh_overview)
        self.context.protection.changed.connect(self._refresh_decisions)
        self._refresh()

    # --- construction ------------------------------------------------------

    def _build_overview_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Risk overview",
            "Current risk is the highest score among open and investigating incidents.",
            margins=(10, 16, 10, 16),
        )

        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)

        self._risk_card = StatCard("Risk", "LOW 0", "Active incident.", "shield")
        self._alerts_card = StatCard("Alerts", "0", "Awaiting review.", "alert")
        self._incidents_card = StatCard("Active", "0", "Open or active.", "activity")
        self._resolved_card = StatCard("Resolved", "0", "Completed.", "check")
        for index, card in enumerate(
            (
                self._risk_card,
                self._alerts_card,
                self._incidents_card,
                self._resolved_card,
            )
        ):
            grid.addWidget(card, index // 2, index % 2)
        for column in range(2):
            grid.setColumnStretch(column, 1)

        panel.body.addLayout(grid)

        actions = QHBoxLayout()
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(8)
        refresh = ActionButton("Analyze", "secondary", "refresh", panel)
        refresh.clicked.connect(self._run_analysis)
        actions.addWidget(refresh)

        settings = ActionButton("Settings", "secondary", "sliders", panel)
        settings.clicked.connect(self._open_settings)
        actions.addWidget(settings)
        actions.addStretch(1)
        panel.body.addLayout(actions)

        self._settings_note = QLabel("", panel)
        self._settings_note.setObjectName("MutedText")
        self._settings_note.setWordWrap(True)
        panel.body.addWidget(self._settings_note)
        return panel

    def _build_middle_row(self) -> QWidget:
        row = QWidget()
        layout = QVBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        distribution = ContentPanel(
            "Risk distribution",
            "How persisted analysis findings are classified by deterministic score.",
        )
        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(8)

        for column, level in enumerate(RiskLevel):
            cell = QWidget(distribution)
            column_layout = QVBoxLayout(cell)
            column_layout.setContentsMargins(0, 0, 0, 0)
            column_layout.setSpacing(6)
            column_layout.addWidget(Chip(level.value, level.tone, cell), 0)
            value = QLabel("0", cell)
            value.setObjectName("StatValue")
            column_layout.addWidget(value)
            grid.addWidget(cell, 0, column)
            grid.setColumnStretch(column, 1)
            self._distribution_labels[level] = value

        distribution.body.addLayout(grid)
        self._distribution_total = QLabel("0 findings", distribution)
        self._distribution_total.setObjectName("MutedText")
        distribution.body.addWidget(self._distribution_total)
        layout.addWidget(distribution)

        activity = ContentPanel(
            "Protection module activity",
            "Session evaluations and analysis records per internal module.",
        )
        info = InfoList(activity, label_width=160)
        for module_id, label in MODULE_DEFINITIONS:
            self._activity_labels[module_id] = info.add_row(label, "0 evaluations")
        activity.body.addWidget(info)
        layout.addWidget(activity)
        return row

    def _build_trend_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Risk trend",
            "Scores of the most recent findings, oldest to newest. Painted natively "
            "with no external chart dependency.",
        )
        self._trend_chart = RiskTrendChart(panel)
        panel.body.addWidget(self._trend_chart)
        self._trend_empty = QLabel("", panel)
        self._trend_empty.setObjectName("MutedText")
        self._trend_empty.setWordWrap(True)
        self._trend_empty.setVisible(False)
        panel.body.addWidget(self._trend_empty)
        return panel

    def _build_findings_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Recent security findings",
            "Newest first. Each finding names the internal pattern and its transparent score.",
        )
        self._findings_table = DataTable(
            ["Time", "Finding", "Severity", "Score", "Module"], panel, row_height=38
        )
        self._findings_table.configure_columns(
            {0: 140, 2: 100, 3: 60, 4: 150}, stretch=1
        )
        panel.body.addWidget(self._findings_table)

        self._findings_empty = EmptyState(
            "activity", FINDINGS_EMPTY_TITLE, FINDINGS_EMPTY_TEXT, panel
        )
        panel.body.addWidget(self._findings_empty)
        self.register_empty_pair(self._findings_table, self._findings_empty)
        return panel

    def _build_decisions_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Recent policy decisions",
            "The underlying SSG8 evaluations the analyzer consumes. Nothing here "
            "comes from Windows telemetry.",
        )
        self._decisions_table = DataTable(
            ["Time", "Module", "Target", "Decision"], panel, row_height=36
        )
        self._decisions_table.configure_columns({0: 140, 1: 140, 3: 110}, stretch=2)
        panel.body.addWidget(self._decisions_table)

        self._decisions_empty = EmptyState(
            "logs",
            "No policy decisions yet",
            "Evaluate a request inside SSG8 to create analysis input.",
            panel,
        )
        panel.body.addWidget(self._decisions_empty)
        self.register_empty_pair(self._decisions_table, self._decisions_empty)
        return panel

    def _build_alerts_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Security alerts",
            "Generated from findings at or above the configured alert score. Alerts "
            "belong to SSG8 only; they do not enforce anything on Windows.",
        )

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(0, 0, 0, 0)
        toolbar.setSpacing(8)

        self._alert_search = SearchInput("Search alerts", panel)
        self._alert_search.textChanged.connect(self._refresh_alerts)
        toolbar.addWidget(self._alert_search, 1)

        self._alert_status = SelectBox(panel)
        self._alert_status.add_options(
            [("All statuses", None)]
            + [(status.value.title(), status.value) for status in AlertStatus]
        )
        self._alert_status.currentIndexChanged.connect(self._refresh_alerts)
        toolbar.addWidget(self._alert_status)

        self._alert_level = SelectBox(panel)
        self._alert_level.add_options(
            [("All severities", None)]
            + [(level.value, level.value) for level in RiskLevel]
        )
        self._alert_level.currentIndexChanged.connect(self._refresh_alerts)
        toolbar.addWidget(self._alert_level)
        panel.body.addLayout(toolbar)

        self._alerts_table = DataTable(
            ["Time", "Alert", "Severity", "Score", "Status"], panel, row_height=36
        )
        self._alerts_table.configure_columns(
            {0: 136, 2: 100, 3: 58, 4: 120}, stretch=1
        )
        self._alerts_table.itemSelectionChanged.connect(self._show_alert_detail)
        panel.body.addWidget(self._alerts_table)

        self._alert_detail = QLabel(
            "Select an alert to inspect its target, related finding and risk detail.",
            panel,
        )
        self._alert_detail.setObjectName("MutedText")
        self._alert_detail.setWordWrap(True)
        self._alert_detail.setMinimumHeight(48)
        panel.body.addWidget(self._alert_detail)

        actions = QHBoxLayout()
        actions.setContentsMargins(0, 0, 0, 0)
        actions.setSpacing(8)
        actions.addStretch(1)

        self._ack_button = ActionButton("Acknowledge", "secondary", "check", panel)
        self._ack_button.clicked.connect(self._acknowledge_selected)
        actions.addWidget(self._ack_button)

        self._resolve_button = ActionButton("Resolve", "secondary", "shield", panel)
        self._resolve_button.clicked.connect(self._resolve_selected)
        actions.addWidget(self._resolve_button)

        self._dismiss_button = ActionButton("Dismiss", "danger", "close", panel)
        self._dismiss_button.clicked.connect(self._dismiss_selected)
        actions.addWidget(self._dismiss_button)
        panel.body.addLayout(actions)

        self._alerts_empty = EmptyState(
            "alert", ALERTS_EMPTY_TITLE, ALERTS_EMPTY_TEXT, panel
        )
        panel.body.addWidget(self._alerts_empty)
        self.register_empty_pair(self._alerts_table, self._alerts_empty)
        self._update_alert_actions(None)
        return panel

    def _build_incidents_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Incident overview",
            "Related findings and alerts grouped for investigation.",
        )

        manage = ActionButton("Manage incidents", "secondary", "shield", panel)
        manage.clicked.connect(lambda: self.navigate_to("incidents"))
        panel.add_action(manage)

        self._incidents_table = DataTable(
            ["ID", "Incident", "Severity", "Status", "Updated"], panel, row_height=36
        )
        self._incidents_table.configure_columns({0: 100, 2: 100, 3: 126, 4: 140}, stretch=1)
        panel.body.addWidget(self._incidents_table)

        self._incidents_empty = EmptyState(
            "shield", INCIDENTS_EMPTY_TITLE, INCIDENTS_EMPTY_TEXT, panel
        )
        panel.body.addWidget(self._incidents_empty)
        self.register_empty_pair(self._incidents_table, self._incidents_empty)
        return panel

    # --- refresh -----------------------------------------------------------

    def _refresh(self) -> None:
        self._refresh_overview()
        self._refresh_findings()
        self._refresh_decisions()
        self._refresh_alerts()
        self._refresh_incidents()

    def _refresh_overview(self) -> None:
        overview = self.context.analysis.risk_overview()
        level = overview["level"]
        self._risk_card.set_value(
            f"{level.value} {overview['score']}", _stat_tone(level)
        )
        self._alerts_card.set_value(
            str(overview["new_alerts"]), "danger" if overview["new_alerts"] else None
        )
        self._incidents_card.set_value(
            str(overview["active_incidents"]), "warning" if overview["active_incidents"] else None
        )
        self._resolved_card.set_value(str(overview["resolved_incidents"]), "success")

        distribution = self.context.analysis.risk_distribution()
        for level_key, label in self._distribution_labels.items():
            label.setText(str(distribution[level_key]))
        total = sum(distribution.values())
        self._distribution_total.setText(
            f"{total} finding{'s' if total != 1 else ''} across all risk levels"
        )

        activity = self.context.analysis.module_activity()
        for module_id, label in self._activity_labels.items():
            values = activity[module_id]
            label.setText(
                f"{values['evaluations']} evaluations \u00b7 "
                f"{values['findings']} findings \u00b7 {values['alerts']} alerts"
            )

        settings = self.context.analysis.settings()
        errors = self.context.analysis.analysis_errors()
        note = (
            f"Analysis window {settings.window_minutes} min \u00b7 "
            f"{settings.repeat_threshold} repeated events \u00b7 "
            f"{settings.multi_module_threshold} modules \u00b7 "
            f"alerts at {settings.alert_min_score}/100."
        )
        if errors:
            note += f" Last storage issue: {errors[-1]}"
        self._settings_note.setText(note)

        trend = self.context.analysis.risk_trend()
        self._trend_chart.set_points(trend)
        self._trend_chart.setVisible(bool(trend))
        self._trend_empty.setVisible(not trend)
        self._trend_empty.setText(
            "No risk trend yet. Evaluate requests until repeated policy activity "
            "produces a finding."
        )

    def _refresh_decisions(self) -> None:
        decisions = self.context.protection.decisions(limit=10)
        self._decisions_table.clear_rows()
        for decision in decisions:
            self._decisions_table.add_row(
                [
                    format_timestamp(decision.timestamp),
                    decision.module,
                    decision.target,
                    ChipCell(decision.action_label, action_tone(decision.action)),
                ],
                decision,
            )
        self.sync_empty_states()

    def _refresh_findings(self) -> None:
        findings = self.context.analysis.findings(limit=12)
        self._findings_table.clear_rows()
        for finding in findings:
            self._findings_table.add_row(
                [
                    format_timestamp(finding.last_seen),
                    finding.title,
                    ChipCell(finding.level.value, finding.level.tone),
                    f"{finding.score}/100",
                    _modules_text(finding.module_ids),
                ],
                finding,
            )
        self.sync_empty_states()

    def _refresh_alerts(self) -> None:
        previous = self._selected_alert_id()
        search = self._alert_search.text()
        status_value = self._alert_status.current_value()
        level_value = self._alert_level.current_value()
        status = AlertStatus(status_value) if status_value else None
        level = RiskLevel(level_value) if level_value else None

        alerts = self.context.analysis.alerts(
            status=status, level=level, search=search, limit=12
        )
        self._alerts_table.clear_rows()
        for alert in alerts:
            self._alerts_table.add_row(
                [
                    format_timestamp(alert.updated_at),
                    alert.title,
                    ChipCell(alert.level.value, alert.level.tone),
                    f"{alert.score}/100",
                    ChipCell(alert.status.value.title(), ALERT_TONES[alert.status]),
                ],
                alert,
            )

        if self._alerts_table.rowCount():
            self._alerts_empty.set_content("alert", ALERTS_EMPTY_TITLE, ALERTS_EMPTY_TEXT)
        elif search.strip() or status is not None or level is not None:
            self._alerts_empty.set_content(
                "search",
                "No matching alerts",
                "No security alert matches the current filters.",
            )
        else:
            self._alerts_empty.set_content("alert", ALERTS_EMPTY_TITLE, ALERTS_EMPTY_TEXT)
        self.sync_empty_states()

        if previous:
            for row in range(self._alerts_table.rowCount()):
                payload = self._alerts_table.row_payload(row)
                if payload is not None and payload.id == previous:
                    self._alerts_table.selectRow(row)
                    break
        self._show_alert_detail()

    def _refresh_incidents(self) -> None:
        incidents = self.context.analysis.incidents(limit=8)
        self._incidents_table.clear_rows()
        for incident in incidents:
            self._incidents_table.add_row(
                [
                    incident.id,
                    incident.title,
                    ChipCell(incident.level.value, incident.level.tone),
                    ChipCell(
                        incident.status.value.title(),
                        INCIDENT_TONES[incident.status],
                    ),
                    format_timestamp(incident.updated_at),
                ],
                incident,
            )
        self.sync_empty_states()

    # --- alert actions -----------------------------------------------------

    def _selected_alert_id(self) -> str:
        payload = self._alerts_table.selected_payload()
        return payload.id if payload is not None else ""

    def _show_alert_detail(self) -> None:
        payload = self._alerts_table.selected_payload()
        if payload is None:
            self._alert_detail.setText(
                "Select an alert to inspect its target, related finding and risk detail."
            )
            self._update_alert_actions(None)
            return

        finding = self.context.analysis.finding(payload.finding_id)
        module = MODULE_LABELS.get(payload.module_id, payload.module_id or "Multiple modules")
        detail = (
            f"{payload.id} \u00b7 {payload.level.value} {payload.score}/100 \u00b7 "
            f"{payload.status.value}\n"
            f"{payload.description}\n"
            f"Module: {module} \u00b7 Target: {payload.target or 'multiple targets'} \u00b7 "
            f"Finding: {payload.finding_id}"
        )
        if finding is not None:
            detail += f"\nScoring: {finding.explanation.replace(chr(10), ' | ')}"
        self._alert_detail.setText(detail)
        self._update_alert_actions(payload)

    def _update_alert_actions(self, alert) -> None:
        self._ack_button.setEnabled(alert is not None and alert.status is AlertStatus.NEW)
        self._resolve_button.setEnabled(
            alert is not None
            and alert.status in (AlertStatus.NEW, AlertStatus.ACKNOWLEDGED)
        )
        self._dismiss_button.setEnabled(
            alert is not None
            and alert.status in (AlertStatus.NEW, AlertStatus.ACKNOWLEDGED)
        )

    def _acknowledge_selected(self) -> None:
        alert_id = self._selected_alert_id()
        if alert_id:
            self.context.analysis.acknowledge_alert(alert_id)
            self._refresh_alerts()

    def _resolve_selected(self) -> None:
        alert_id = self._selected_alert_id()
        if alert_id:
            self.context.analysis.resolve_alert(alert_id)
            self._refresh_alerts()

    def _dismiss_selected(self) -> None:
        alert_id = self._selected_alert_id()
        if alert_id:
            self.context.analysis.dismiss_alert(alert_id)
            self._refresh_alerts()

    # --- toolbar actions ---------------------------------------------------

    def _run_analysis(self) -> None:
        self.context.analysis.analyze_now()
        self._refresh()

    def _open_settings(self) -> None:
        settings = self.context.analysis.settings()
        result = prompt_form(
            self,
            title="Threat analysis settings",
            description=(
                "These thresholds only affect deterministic analysis inside SSG8. "
                "No Windows or external security setting is changed."
            ),
            fields=[
                FieldSpec(
                    "window",
                    "Analysis window (minutes)",
                    "1 to 1440",
                    str(settings.window_minutes),
                    _range_validator(1, 1440, "minutes"),
                ),
                FieldSpec(
                    "repeat",
                    "Repeated-event threshold",
                    "2 to 50",
                    str(settings.repeat_threshold),
                    _range_validator(2, 50, "events"),
                ),
                FieldSpec(
                    "multi",
                    "Multi-module threshold",
                    "2 to 4",
                    str(settings.multi_module_threshold),
                    _range_validator(2, 4, "modules"),
                ),
                FieldSpec(
                    "alert",
                    "Minimum alert score",
                    "0 to 100",
                    str(settings.alert_min_score),
                    _range_validator(0, 100, "score"),
                ),
            ],
            confirm_label="Save settings",
        )
        if result is None:
            return

        ok, message = self.context.analysis.update_settings(
            window_minutes=int(result["window"]),
            repeat_threshold=int(result["repeat"]),
            multi_module_threshold=int(result["multi"]),
            alert_min_score=int(result["alert"]),
        )
        if not ok:
            self._settings_note.setText(message)
        self._refresh()

    def on_shown(self) -> None:
        self._refresh()

    # --- convenience for tests --------------------------------------------

    def visible_findings(self) -> int:
        return self._findings_table.rowCount()

    def visible_alerts(self) -> int:
        return self._alerts_table.rowCount()

    def visible_incidents(self) -> int:
        return self._incidents_table.rowCount()

    def visible_decisions(self) -> int:
        return self._decisions_table.rowCount()

    def select_alert(self, alert_id: str) -> bool:
        for row in range(self._alerts_table.rowCount()):
            payload = self._alerts_table.row_payload(row)
            if payload is not None and payload.id == alert_id:
                self._alerts_table.selectRow(row)
                return True
        return False

    def alert_detail_text(self) -> str:
        return self._alert_detail.text()


def _range_validator(minimum: int, maximum: int, unit: str):
    def validate(text: str) -> str | None:
        if not text.strip().isdigit():
            return f"Enter a whole number of {unit}."
        value = int(text)
        if not minimum <= value <= maximum:
            return f"Enter a value between {minimum} and {maximum}."
        return None

    return validate


def _stat_tone(level: RiskLevel) -> str:
    if level is RiskLevel.LOW:
        return "info"
    if level is RiskLevel.MEDIUM:
        return "warning"
    return "danger"


def _modules_text(module_ids: tuple[str, ...]) -> str:
    labels = [MODULE_LABELS.get(module_id, module_id) for module_id in module_ids]
    return ", ".join(labels) if labels else "Multiple"
