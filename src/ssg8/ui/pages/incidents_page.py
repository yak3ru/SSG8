"""Incident Management: investigate findings grouped by the SSG8 analyzer."""

from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ssg8.security.analysis.models import (
    IncidentStatus,
    RiskLevel,
    SecurityIncident,
)
from ssg8.security.protection_manager import MODULE_LABELS
from ssg8.ui.components.action_button import ActionButton
from ssg8.ui.components.chip import Chip, ChipCell
from ssg8.ui.components.data_table import DataTable
from ssg8.ui.components.dialog import confirm, prompt_text
from ssg8.ui.components.empty_state import EmptyState
from ssg8.ui.components.info_list import InfoList
from ssg8.ui.components.panel import ContentPanel
from ssg8.ui.components.search_input import SearchInput, SelectBox
from ssg8.ui.components.section_heading import PageIntro, muted_label
from ssg8.ui.components.stat_card import StatCard
from ssg8.ui.pages.base_page import BasePage
from ssg8.utils.formatting import format_timestamp

INCIDENT_TONES: dict[IncidentStatus, str] = {
    IncidentStatus.OPEN: "accent",
    IncidentStatus.INVESTIGATING: "warning",
    IncidentStatus.RESOLVED: "success",
    IncidentStatus.CLOSED: "neutral",
}

EMPTY_TITLE = "No incidents to investigate"
EMPTY_TEXT = (
    "Incidents are created only when SSG8 analysis finds related policy "
    "violations. Nothing on this page is randomly generated."
)


class IncidentsPage(BasePage):
    """Open, investigate, annotate, resolve and close security incidents."""

    page_id = "incidents"

    def build(self) -> None:
        self._selected_id = ""
        self._detail_visible = False

        self.body.addWidget(
            PageIntro(
                "Incident Management",
                "Group related SSG8 findings and alerts, record investigation notes "
                "and track an incident from OPEN to CLOSED. Everything stays local.",
            )
        )


        self.body.addWidget(self._build_stats_row())
        self.body.addWidget(self._build_table_panel())
        self._detail_panel = self._build_detail_panel()
        self._detail_panel.setVisible(False)
        self.body.addWidget(self._detail_panel)

        self.context.analysis.changed.connect(self._refresh)
        self._refresh()

    # --- construction ------------------------------------------------------

    def _build_stats_row(self) -> QWidget:
        host = QWidget()
        grid = QGridLayout(host)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(12)

        self._open_card = StatCard("Open", "0", "Awaiting review.", "alert")
        self._investigating_card = StatCard(
            "Review", "0", "Under investigation.", "activity"
        )
        self._resolved_card = StatCard("Resolved", "0", "Completed.", "check")
        self._highest_card = StatCard("Top risk", "LOW 0", "Active incidents.", "shield")
        for index, card in enumerate(
            (
                self._open_card,
                self._investigating_card,
                self._resolved_card,
                self._highest_card,
            )
        ):
            grid.addWidget(card, index // 2, index % 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        grid.setVerticalSpacing(12)
        return host

    def _build_table_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Incidents",
            "Newest first. Select an incident to open its investigation record.",
        )

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(0, 0, 0, 0)
        toolbar.setSpacing(8)

        self._search = SearchInput("Search incidents", panel)
        self._search.textChanged.connect(self._refresh_table)
        toolbar.addWidget(self._search, 1)

        self._status_filter = SelectBox(panel)
        self._status_filter.add_options(
            [("All statuses", None)]
            + [(status.value.title(), status.value) for status in IncidentStatus]
        )
        self._status_filter.currentIndexChanged.connect(self._refresh_table)
        toolbar.addWidget(self._status_filter)

        self._level_filter = SelectBox(panel)
        self._level_filter.add_options(
            [("All severities", None)]
            + [(level.value, level.value) for level in RiskLevel]
        )
        self._level_filter.currentIndexChanged.connect(self._refresh_table)
        toolbar.addWidget(self._level_filter)
        panel.body.addLayout(toolbar)

        self._table = DataTable(
            ["ID", "Incident", "Severity", "Score", "Status", "Updated"],
            panel,
            row_height=38,
        )
        self._table.configure_columns(
            {0: 94, 2: 98, 3: 58, 4: 126, 5: 140}, stretch=1
        )
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        panel.body.addWidget(self._table)

        self._empty = EmptyState("shield", EMPTY_TITLE, EMPTY_TEXT, panel)
        panel.body.addWidget(self._empty)
        self.register_empty_pair(self._table, self._empty)
        return panel

    def _build_detail_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Investigation record",
            "Related alerts, findings and notes for the selected incident.",
        )

        heading = QWidget(panel)
        heading_row = QHBoxLayout(heading)
        heading_row.setContentsMargins(0, 0, 0, 0)
        heading_row.setSpacing(8)

        self._detail_title = QLabel("", heading)
        self._detail_title.setObjectName("PanelTitle")
        self._detail_title.setWordWrap(True)
        heading_row.addWidget(self._detail_title, 1)

        self._severity_chip = Chip("", "neutral", heading)
        heading_row.addWidget(self._severity_chip)
        self._status_chip = Chip("", "neutral", heading)
        heading_row.addWidget(self._status_chip)
        panel.body.addWidget(heading)

        self._summary = QLabel("", panel)
        self._summary.setObjectName("MutedText")
        self._summary.setWordWrap(True)
        panel.body.addWidget(self._summary)

        info = InfoList(panel, label_width=150)
        self._id_value = info.add_row("Incident ID", "", mono=True)
        self._score_value = info.add_row("Risk score", "")
        self._created_value = info.add_row("Detected", "")
        self._updated_value = info.add_row("Last updated", "")
        self._modules_value = info.add_row("Protection modules", "")
        self._alerts_value = info.add_row("Related alerts", "")
        self._findings_value = info.add_row("Related findings", "")
        self._events_value = info.add_row("Related events", "")
        panel.body.addWidget(info)

        panel.add_divider()
        notes_title = QLabel("Investigation notes", panel)
        notes_title.setObjectName("FieldLabel")
        panel.body.addWidget(notes_title)
        self._notes = QLabel("No investigation notes yet.", panel)
        self._notes.setObjectName("MutedText")
        self._notes.setWordWrap(True)
        panel.body.addWidget(self._notes)

        panel.add_divider()
        severity_row = QHBoxLayout()
        severity_row.setContentsMargins(0, 0, 0, 0)
        severity_row.setSpacing(8)
        severity_row.addWidget(muted_label("Severity", wrap=False))
        self._severity_select = SelectBox(panel)
        self._severity_select.add_options(
            [(level.value, level.value) for level in RiskLevel]
        )
        self._severity_select.setMinimumWidth(120)
        severity_row.addWidget(self._severity_select)
        self._apply_severity = ActionButton("Apply", "secondary", parent=panel)
        self._apply_severity.clicked.connect(self._change_severity)
        severity_row.addWidget(self._apply_severity)
        severity_row.addStretch(1)
        panel.body.addLayout(severity_row)

        controls = QHBoxLayout()
        controls.setContentsMargins(0, 0, 0, 0)
        controls.setSpacing(8)
        self._investigate = ActionButton("Investigate", "secondary", "activity", panel)
        self._investigate.clicked.connect(self._start_investigation)
        controls.addWidget(self._investigate)

        self._note_button = ActionButton("Add note", "secondary", "plus", panel)
        self._note_button.clicked.connect(self._add_note)
        controls.addWidget(self._note_button)

        self._resolve = ActionButton("Resolve", "secondary", "check", panel)
        self._resolve.clicked.connect(self._resolve_incident)
        controls.addWidget(self._resolve)

        self._close = ActionButton("Close", "danger", "close", panel)
        self._close.clicked.connect(self._close_incident)
        controls.addWidget(self._close)
        controls.addStretch(1)
        panel.body.addLayout(controls)
        return panel

    # --- refresh -----------------------------------------------------------

    def _refresh(self) -> None:
        counts = self.context.analysis.incident_manager.count_by_status()
        self._open_card.set_value(str(counts[IncidentStatus.OPEN]))
        self._investigating_card.set_value(str(counts[IncidentStatus.INVESTIGATING]))
        self._resolved_card.set_value(
            str(counts[IncidentStatus.RESOLVED]), "success"
        )
        active = [
            incident
            for incident in self.context.analysis.incidents()
            if incident.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)
        ]
        active_level = max(
            (incident.level for incident in active),
            key=lambda item: item.rank,
            default=RiskLevel.LOW,
        )
        active_score = max((incident.score for incident in active), default=0)
        self._highest_card.set_value(
            f"{active_level.value} {active_score}",
            "danger" if active_level.rank >= RiskLevel.HIGH.rank else "warning",
        )
        self._refresh_table()

    def _refresh_table(self) -> None:
        previous = self._selected_id
        search = self._search.text()
        status_value = self._status_filter.current_value()
        level_value = self._level_filter.current_value()
        status = IncidentStatus(status_value) if status_value else None
        level = RiskLevel(level_value) if level_value else None

        incidents = self.context.analysis.incidents(
            status=status, level=level, search=search, limit=100
        )
        self._table.clear_rows()
        for incident in incidents:
            self._table.add_row(
                [
                    incident.id,
                    incident.title,
                    ChipCell(incident.level.value, incident.level.tone),
                    f"{incident.score}/100",
                    ChipCell(
                        incident.status.value.title(),
                        INCIDENT_TONES[incident.status],
                    ),
                    format_timestamp(incident.updated_at),
                ],
                incident,
            )

        if self._table.rowCount():
            self._empty.set_content("shield", EMPTY_TITLE, EMPTY_TEXT)
        elif search.strip() or status is not None or level is not None:
            self._empty.set_content(
                "search",
                "No matching incidents",
                "No incident matches the current filters.",
            )
        else:
            self._empty.set_content("shield", EMPTY_TITLE, EMPTY_TEXT)
        self.sync_empty_states()

        target_row = -1
        for row in range(self._table.rowCount()):
            payload = self._table.row_payload(row)
            if payload is not None and payload.id == previous:
                target_row = row
                break
        if target_row < 0 and self._table.rowCount():
            target_row = 0
        if target_row >= 0:
            self._table.selectRow(target_row)
        else:
            self._selected_id = ""
            self._detail_panel.setVisible(False)
        self._on_selection_changed()

    def _on_selection_changed(self) -> None:
        incident = self._table.selected_payload()
        if incident is None:
            self._selected_id = ""
            self._detail_panel.setVisible(False)
            return

        self._selected_id = incident.id
        self._detail_panel.setVisible(True)
        self._render_detail(incident)

    def _render_detail(self, incident: SecurityIncident) -> None:
        self._detail_title.setText(incident.title)
        self._severity_chip.setText(incident.level.value)
        self._severity_chip.set_tone(incident.level.tone)
        self._status_chip.setText(incident.status.value)
        self._status_chip.set_tone(INCIDENT_TONES[incident.status])
        self._summary.setText(incident.summary)

        self._id_value.setText(incident.id)
        self._score_value.setText(f"{incident.score}/100 ({incident.level.value})")
        self._created_value.setText(format_timestamp(incident.created_at))
        self._updated_value.setText(format_timestamp(incident.updated_at))
        self._modules_value.setText(
            ", ".join(
                MODULE_LABELS.get(module_id, module_id)
                for module_id in incident.module_ids
            )
            or "Multiple modules"
        )

        alerts = [
            alert
            for alert_id in incident.alert_ids
            if (alert := self.context.analysis.alert(alert_id)) is not None
        ]
        self._alerts_value.setText(
            "\n".join(f"{alert.id} \u00b7 {alert.title}" for alert in alerts[:4])
            or "No alert reached the configured threshold."
        )

        findings = [
            finding
            for finding_id in incident.finding_ids
            if (finding := self.context.analysis.finding(finding_id)) is not None
        ]
        self._findings_value.setText(
            "\n".join(f"{finding.id} \u00b7 {finding.title}" for finding in findings[:4])
            or "No related findings are available."
        )

        evidence = sorted(
            (item for finding in findings for item in finding.evidence),
            key=lambda item: item.timestamp,
        )
        self._events_value.setText(
            "\n".join(
                f"{format_timestamp(item.timestamp)} \u00b7 "
                f"{item.action.upper()} \u00b7 {item.target}"
                for item in evidence[-4:]
            )
            or "No related evidence is available."
        )

        if incident.notes:
            self._notes.setText(
                "\n".join(
                    f"{format_timestamp(note.timestamp)} \u2014 {note.text}"
                    for note in reversed(incident.notes)
                )
            )
        else:
            self._notes.setText("No investigation notes yet.")

        closed = incident.status is IncidentStatus.CLOSED
        self._severity_select.setEnabled(not closed)
        self._apply_severity.setEnabled(not closed)
        index = self._severity_select.findData(incident.level.value)
        self._severity_select.setCurrentIndex(max(0, index))
        self._investigate.setEnabled(incident.status is IncidentStatus.OPEN)
        self._note_button.setEnabled(not closed)
        self._resolve.setEnabled(
            incident.status in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)
        )
        self._close.setEnabled(not closed)

    # --- actions -----------------------------------------------------------

    def _start_investigation(self) -> None:
        if self._selected_id:
            self.context.analysis.start_investigation(self._selected_id)

    def _add_note(self) -> None:
        if not self._selected_id:
            return

        def validate(text: str) -> str | None:
            if not text.strip():
                return "Enter an investigation note."
            if len(text) > 500:
                return "Keep the note to 500 characters or fewer."
            return None

        text = prompt_text(
            self,
            title="Add investigation note",
            label="Note",
            placeholder="What did you check, and what did you conclude?",
            confirm_label="Add note",
            validator=validate,
            description="The note is stored locally with this incident.",
        )
        if text:
            self.context.analysis.add_incident_note(self._selected_id, text)

    def _change_severity(self) -> None:
        if not self._selected_id:
            return
        value = self._severity_select.current_value()
        if value:
            self.context.analysis.set_incident_severity(
                self._selected_id, RiskLevel(value)
            )

    def _resolve_incident(self) -> None:
        if not self._selected_id:
            return
        accepted = confirm(
            self,
            "Resolve incident",
            "Mark this incident as resolved? Related alerts and findings stay in "
            "the audit log.",
            confirm_label="Resolve",
        )
        if accepted:
            self.context.analysis.resolve_incident(self._selected_id)

    def _close_incident(self) -> None:
        if not self._selected_id:
            return
        accepted = confirm(
            self,
            "Close incident",
            "Close this incident? Investigation notes and related records are kept.",
            confirm_label="Close incident",
            danger=True,
        )
        if accepted:
            self.context.analysis.close_incident(self._selected_id)

    def on_shown(self) -> None:
        self._refresh()

    # --- convenience for tests --------------------------------------------

    def visible_incidents(self) -> int:
        return self._table.rowCount()

    def selected_incident_id(self) -> str:
        return self._selected_id

    def detail_title(self) -> str:
        return self._detail_title.text()

    def detail_visible(self) -> bool:
        return self._detail_panel.isVisible()
