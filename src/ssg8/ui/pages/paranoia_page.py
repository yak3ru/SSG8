"""Paranoia Center: progression, restrictions, self-audit and quarantine."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)

from ssg8.services.paranoia.activities import ACTIVITIES
from ssg8.services.paranoia.states import ParanoiaState
from ssg8.ui import theme
from ssg8.ui.components.action_button import ActionButton
from ssg8.ui.components.chip import Chip, ChipCell
from ssg8.ui.components.data_table import DataTable
from ssg8.ui.components.dialog import confirm
from ssg8.ui.components.empty_state import EmptyState
from ssg8.ui.components.panel import ContentPanel
from ssg8.ui.components.progress_meter import ScoreMeter
from ssg8.ui.components.search_input import SelectBox
from ssg8.ui.components.section_heading import PageIntro, muted_label
from ssg8.ui.components.stat_card import StatCard
from ssg8.ui.components.toggle_switch import ToggleSwitch
from ssg8.ui.pages.base_page import BasePage
from ssg8.utils.formatting import format_timestamp


def state_tone(state: ParanoiaState) -> str:
    if state is ParanoiaState.NORMAL:
        return "success"
    if state is ParanoiaState.SUSPICIOUS:
        return "warning"
    if state is ParanoiaState.RESTRICTIVE:
        return "accent"
    if state in (
        ParanoiaState.MAXIMUM_PARANOIA,
        ParanoiaState.SELF_AUDIT,
        ParanoiaState.SELF_THREAT_DETECTED,
    ):
        return "danger"
    return "info"


def restriction_tone(mode: str) -> str:
    lowered = mode.casefold()
    if lowered in ("available", "released"):
        return "success"
    if lowered in ("flagged", "scrutinised"):
        return "warning"
    if lowered == "restricted":
        return "accent"
    if lowered == "blocked":
        return "danger"
    return "neutral"


class ParanoiaPage(BasePage):
    """The visible story of the paranoia progression."""

    page_id = "paranoia"

    def build(self) -> None:
        self.body.addWidget(
            PageIntro(
                "Paranoia Center",
                "CyberLockdown becomes increasingly suspicious of harmless activity inside "
                "its own controlled demonstration environment. No Windows setting is read "
                "or changed.",
            )
        )
        self.add_demo_notice(
            "DEMONSTRATION ONLY. Restrictions affect the controlled browser, downloads, "
            "launcher and simulated settings inside this application. Windows, input "
            "devices, Task Manager and real internet access remain untouched.",
            "danger",
            "alert",
        )

        self._build_stat_row()
        self.body.addWidget(self._build_meter_panel())
        self.body.addWidget(self._build_restrictions_panel())
        self.body.addWidget(self._build_audit_panel())
        self.body.addWidget(self._build_history_row())

        paranoia = self.context.paranoia
        paranoia.changed.connect(self._refresh_all)
        paranoia.state_changed.connect(self._on_state_changed)
        paranoia.audit_completed.connect(lambda _report: self._refresh_all())
        self.context.analysis.changed.connect(self._refresh_counts)
        self._refresh_all()

    # --- construction ------------------------------------------------------

    def _build_stat_row(self) -> None:
        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)

        self._score_card = StatCard("Paranoia", "0/100", "Current suspicion score.", "alert")
        self._state_card = StatCard("State", "Normal", "Progression state.", "activity")
        self._level_card = StatCard(
            "Restriction level", "0", "Controlled demo restrictions.", "lock"
        )
        self._blocked_card = StatCard(
            "Blocked activity", "0", "Escalated demonstration requests.", "shield"
        )
        self._findings_card = StatCard(
            "Threat findings", "0", "Phase 5 analysis records.", "logs"
        )
        self._alerts_card = StatCard("Active alerts", "0", "New security alerts.", "bell")

        cards = (
            self._score_card,
            self._state_card,
            self._level_card,
            self._blocked_card,
            self._findings_card,
            self._alerts_card,
        )
        for index, card in enumerate(cards):
            grid.addWidget(card, index // 2, index % 2)
        for column in range(2):
            grid.setColumnStretch(column, 1)

        container = QWidget()
        container.setLayout(grid)
        self.body.addWidget(container)

    def _build_meter_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Paranoia meter",
            "Every increase is explained and recorded in Security Logs.",
        )

        self._meter = ScoreMeter(panel)
        panel.body.addWidget(self._meter)

        status_row = QHBoxLayout()
        status_row.setContentsMargins(0, 0, 0, 0)
        status_row.setSpacing(10)

        self._state_chip = Chip("NORMAL", "success", panel)
        status_row.addWidget(self._state_chip, 0, Qt.AlignmentFlag.AlignVCenter)

        self._score_text = QLabel("", panel)
        self._score_text.setObjectName("ValueText")
        self._score_text.setWordWrap(True)
        status_row.addWidget(self._score_text, 1)
        panel.body.addLayout(status_row)

        self._profile_text = muted_label("")
        panel.body.addWidget(self._profile_text)

        self._maximum_warning = QLabel("", panel)
        self._maximum_warning.setWordWrap(True)
        self._maximum_warning.setVisible(False)
        panel.body.addWidget(self._maximum_warning)

        panel.add_divider()

        activity_row = QHBoxLayout()
        activity_row.setContentsMargins(0, 0, 0, 0)
        activity_row.setSpacing(10)

        activity_row.addWidget(QLabel("Activity", panel))
        self._activity_select = SelectBox(panel)
        self._activity_select.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self._activity_select.setMinimumContentsLength(8)
        self._activity_select.add_options(
            [(activity.label, activity.key) for activity in ACTIVITIES.values()]
        )
        activity_row.addWidget(self._activity_select, 1)

        record_button = ActionButton("Record", "secondary", "plus", panel)
        record_button.clicked.connect(self._record_selected_activity)
        activity_row.addWidget(record_button)
        panel.body.addLayout(activity_row)

        demo_row = QHBoxLayout()
        demo_row.setContentsMargins(0, 0, 0, 0)
        demo_row.setSpacing(10)

        demo_row.addWidget(QLabel("Demo acceleration", panel))
        self._demo_switch = ToggleSwitch(panel, checked=False)
        self._demo_switch.toggled.connect(self.context.paranoia.set_demo_mode)
        demo_row.addWidget(self._demo_switch)
        demo_row.addWidget(muted_label("Faster run."))
        demo_row.addStretch(1)
        panel.body.addLayout(demo_row)

        button_row = QHBoxLayout()
        button_row.setContentsMargins(0, 0, 0, 0)
        button_row.setSpacing(8)
        button_row.addStretch(1)

        self._replay_button = ActionButton("Replay from Normal", "primary", "refresh", panel)
        self._replay_button.clicked.connect(self._replay_demonstration)
        button_row.addWidget(self._replay_button)

        self._max_button = ActionButton("Advance to maximum", "danger", "alert", panel)
        self._max_button.clicked.connect(self._advance_maximum)
        button_row.addWidget(self._max_button)
        panel.body.addLayout(button_row)
        return panel

    def _build_restrictions_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Progressive restrictions",
            "Applied by the existing protection engines and the simulated settings areas.",
        )
        self._restriction_chips: dict[str, Chip] = {}
        for label, _mode in self.context.paranoia.profile.as_rows():
            row = QHBoxLayout()
            row.setContentsMargins(0, 3, 0, 3)
            row.setSpacing(10)
            name = QLabel(label, panel)
            name.setObjectName("ValueText")
            row.addWidget(name, 1)
            chip = Chip("available", "success", panel)
            self._restriction_chips[label] = chip
            row.addWidget(chip, 0, Qt.AlignmentFlag.AlignVCenter)
            panel.body.addLayout(row)
        return panel

    def _build_audit_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Automatic self-audit",
            "The audit reads actual recorded demonstration activity and policy decisions.",
        )

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)

        self._audit_chip = Chip("NOT STARTED", "neutral", panel)
        row.addWidget(self._audit_chip, 0, Qt.AlignmentFlag.AlignVCenter)

        self._audit_text = QLabel("", panel)
        self._audit_text.setObjectName("MutedText")
        self._audit_text.setWordWrap(True)
        row.addWidget(self._audit_text, 1)

        self._audit_button = ActionButton("Run Self-Audit", "primary", "shield", panel)
        self._audit_button.clicked.connect(self.run_audit)
        row.addWidget(self._audit_button)
        panel.body.addLayout(row)

        sequence_row = QHBoxLayout()
        sequence_row.setContentsMargins(0, 0, 0, 0)
        sequence_row.setSpacing(8)
        sequence_row.addStretch(1)

        self._quarantine_button = ActionButton("Begin Self-Quarantine", "danger", "lock", panel)
        self._quarantine_button.clicked.connect(self.begin_quarantine)
        self._quarantine_button.setEnabled(False)
        sequence_row.addWidget(self._quarantine_button)

        self._recovery_button = ActionButton("Complete Recovery", "secondary", "refresh", panel)
        self._recovery_button.clicked.connect(self.complete_recovery)
        self._recovery_button.setEnabled(False)
        sequence_row.addWidget(self._recovery_button)
        panel.body.addLayout(sequence_row)

        self._audit_table = DataTable(
            ["Audit category", "Result", "Detail"], panel, row_height=34
        )
        self._audit_table.configure_columns({0: 210, 1: 130}, stretch=2)
        panel.body.addWidget(self._audit_table)

        self._audit_empty = EmptyState(
            "shield",
            "No self-audit yet",
            "Reach Maximum Paranoia, observe the state, then run the self-audit.",
            panel,
            minimum_height=120,
        )
        panel.body.addWidget(self._audit_empty)
        self.register_empty_pair(self._audit_table, self._audit_empty)

        self._quarantine_text = muted_label("")
        panel.body.addWidget(self._quarantine_text)
        return panel

    def _build_history_row(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        activity_panel = ContentPanel(
            "Recent paranoia events",
            "Newest first. Every score change and restriction is recorded.",
        )
        self._activity_table = DataTable(
            ["Time", "Activity", "Change", "Explanation"], row_height=34
        )
        self._activity_table.configure_columns({0: 140, 1: 190, 2: 80}, stretch=3)
        self._activity_table.setMinimumHeight(150)
        self._activity_empty = EmptyState(
            "activity",
            "No paranoia events yet",
            "Use the controlled demonstration page or record an activity above.",
            minimum_height=140,
        )
        activity_panel.body.addWidget(self._activity_table)
        activity_panel.body.addWidget(self._activity_empty)
        self.register_empty_pair(self._activity_table, self._activity_empty)
        layout.addWidget(activity_panel)

        transition_panel = ContentPanel(
            "State transition history",
            "Validated transitions with their recorded reason.",
        )
        self._transition_table = DataTable(
            ["Time", "Previous", "New", "Reason"], row_height=34
        )
        self._transition_table.configure_columns({0: 140, 1: 150, 2: 160}, stretch=3)
        self._transition_table.setMinimumHeight(140)
        self._transition_empty = EmptyState(
            "logs",
            "No state transitions yet",
            "Reaching 20, 40 and 70 creates validated transitions.",
            minimum_height=130,
        )
        transition_panel.body.addWidget(self._transition_table)
        transition_panel.body.addWidget(self._transition_empty)
        self.register_empty_pair(self._transition_table, self._transition_empty)
        layout.addWidget(transition_panel)
        return container

    # --- refresh -----------------------------------------------------------

    def _on_state_changed(self, _previous: ParanoiaState, _new: ParanoiaState) -> None:
        self._refresh_all()

    def _refresh_all(self) -> None:
        paranoia = self.context.paranoia
        state = paranoia.state()
        score = paranoia.score()
        profile = paranoia.profile

        self._meter.set_score(score, state)
        self._state_chip.setText(state.value)
        self._state_chip.set_tone(state_tone(state))
        self._score_text.setText(
            f"{score}/100 - {state.label}. Warning frequency: {profile.warning_frequency}."
        )
        self._profile_text.setText(profile.summary)

        if state in (
            ParanoiaState.MAXIMUM_PARANOIA,
            ParanoiaState.SELF_AUDIT,
            ParanoiaState.SELF_THREAT_DETECTED,
        ):
            self._maximum_warning.setStyleSheet(
                f"color: {theme.tone('danger').text}; font-size: 9pt; font-weight: 700;"
            )
            self._maximum_warning.setText(
                "CRITICAL SECURITY NOTICE: CyberLockdown has reached maximum paranoia. "
                "All controlled activities are now considered potential threats. Windows "
                "and the real desktop remain unaffected."
            )
            self._maximum_warning.setVisible(True)
        elif state in (ParanoiaState.SELF_QUARANTINE, ParanoiaState.RECOVERY):
            self._maximum_warning.setStyleSheet(
                f"color: {theme.tone('success').text}; font-size: 9pt; font-weight: 600;"
            )
            self._maximum_warning.setText(
                "Controlled restrictions released. The demonstration environment is "
                "restored; permanent audit reports are preserved."
            )
            self._maximum_warning.setVisible(True)
        else:
            self._maximum_warning.setVisible(False)

        self._score_card.set_value(f"{score}/100", state_tone(state))
        self._score_card.set_caption("Current suspicion score.")
        self._state_card.set_value(state.short_label, state_tone(state))
        self._state_card.set_caption(f"Restriction level {profile.restriction_level}.")
        self._level_card.set_value(
            str(profile.restriction_level),
            "danger" if profile.restriction_level >= 3 else None,
        )

        for label, mode in profile.as_rows():
            chip = self._restriction_chips.get(label)
            if chip is not None:
                chip.setText(mode.upper())
                chip.set_tone(restriction_tone(mode))

        self._refresh_counts()
        self._refresh_activity_table()
        self._refresh_transition_table()
        self._refresh_audit()
        self._refresh_buttons()

    def _refresh_counts(self) -> None:
        paranoia = self.context.paranoia
        overview = self.context.analysis.risk_overview()
        self._blocked_card.set_value(
            str(paranoia.blocked_count()),
            "danger" if paranoia.blocked_count() else None,
        )
        self._findings_card.set_value(
            str(overview["findings"]), "warning" if overview["findings"] else None
        )
        self._alerts_card.set_value(
            str(overview["new_alerts"]), "danger" if overview["new_alerts"] else None
        )

    def _refresh_activity_table(self) -> None:
        paranoia = self.context.paranoia
        events = paranoia.activities(limit=12)
        self._activity_table.clear_rows()
        for event in events:
            label = ACTIVITIES[event.activity].label if event.activity in ACTIVITIES else event.activity
            change = f"+{event.delta}" if event.delta else ""
            self._activity_table.add_row(
                [format_timestamp(event.timestamp), label, change, event.reason or event.description],
                event,
            )
        if events:
            self._activity_empty.set_content(
                "activity", "No paranoia events yet", "Use the controlled demonstration page."
            )
        self.sync_empty_states()

    def _refresh_transition_table(self) -> None:
        transitions = self.context.paranoia.transitions(limit=12)
        self._transition_table.clear_rows()
        for transition in transitions:
            self._transition_table.add_row(
                [
                    format_timestamp(transition.timestamp),
                    ChipCell(transition.previous_state.value, state_tone(transition.previous_state)),
                    ChipCell(transition.new_state.value, state_tone(transition.new_state)),
                    transition.reason,
                ],
                transition,
            )
        self.sync_empty_states()

    def _refresh_audit(self) -> None:
        report = self.context.paranoia.last_audit()
        self._audit_table.clear_rows()
        if report is None:
            self._audit_chip.setText("NOT STARTED")
            self._audit_chip.set_tone("neutral")
            self._audit_text.setText(
                "A self-audit becomes available when the demonstration reaches Maximum "
                "Paranoia. It inspects the activity and restrictions recorded in this session."
            )
            self._quarantine_text.setText("")
            self.sync_empty_states()
            return

        tone = "danger" if report.has_violations else "success"
        self._audit_chip.setText("VIOLATIONS DETECTED" if report.has_violations else "COMPLIANT")
        self._audit_chip.set_tone(tone)
        self._audit_text.setText(report.summary)
        for row in report.rows:
            result_tone = (
                "danger"
                if row.result in ("Detected", "Failed", "Unavailable")
                else ("warning" if row.result.startswith("Within") else "success")
            )
            self._audit_table.add_row(
                [row.category, ChipCell(row.result, result_tone), row.detail], row
            )
        self.sync_empty_states()

        state = self.context.paranoia.state()
        if state is ParanoiaState.SELF_QUARANTINE:
            self._quarantine_text.setText(
                "Quarantine active: controlled restrictions are released. Complete Recovery "
                "to finish the sequence; the application stays usable and closable."
            )
        elif state is ParanoiaState.RECOVERY:
            self._quarantine_text.setText(
                "Recovery complete. The demonstration environment is restored and another "
                "run can be started from the Recovery Center."
            )
        elif state is ParanoiaState.SELF_THREAT_DETECTED:
            self._quarantine_text.setText(
                "Self-threat detected. Begin Self-Quarantine to release the demonstration "
                "restrictions and restore the controlled environment."
            )
        else:
            self._quarantine_text.setText("")

    def _refresh_buttons(self) -> None:
        paranoia = self.context.paranoia
        state = paranoia.state()
        self._audit_button.setEnabled(state is ParanoiaState.MAXIMUM_PARANOIA)
        self._quarantine_button.setEnabled(state is ParanoiaState.SELF_THREAT_DETECTED)
        self._recovery_button.setEnabled(state is ParanoiaState.SELF_QUARANTINE)
        self._max_button.setEnabled(not state.is_terminal)
        self._replay_button.setEnabled(True)
        self._demo_switch.set_state_silently(paranoia.demo_mode())

    # --- actions -----------------------------------------------------------

    def _record_selected_activity(self) -> None:
        key = self._activity_select.current_value()
        if key:
            self.context.paranoia.record_activity(str(key))
            self._refresh_all()

    def _advance_maximum(self) -> None:
        if self.context.paranoia.advance_to_maximum_paranoia():
            self._refresh_all()

    def _replay_demonstration(self) -> None:
        accepted = confirm(
            self,
            "Replay demonstration",
            "Return the demonstration to Normal and raise paranoia to Maximum Paranoia? "
            "This changes only the CyberLockdown demonstration state.\n\n"
            "The audit still has to be run explicitly so the maximum state can be observed.",
            confirm_label="Replay",
            danger=True,
        )
        if not accepted:
            return
        self.context.paranoia.quick_reset("Developer replay started from the Paranoia Center.")
        self.context.paranoia.advance_to_maximum_paranoia()
        self._refresh_all()

    def run_audit(self) -> None:
        report, message = self.context.paranoia.run_self_audit()
        if report is None:
            self._audit_text.setText(message)
        self._refresh_all()

    def begin_quarantine(self) -> None:
        if self.context.paranoia.state() is not ParanoiaState.SELF_THREAT_DETECTED:
            return
        accepted = confirm(
            self,
            "Begin simulated self-quarantine",
            "Release every controlled demonstration restriction and begin the simulated "
            "self-removal sequence?\n\n"
            "No executable, source file, user file or Windows setting is deleted or changed.",
            confirm_label="Begin quarantine",
            danger=True,
        )
        if not accepted:
            return
        self.context.paranoia.begin_quarantine()
        self._refresh_all()

    def complete_recovery(self) -> None:
        self.context.paranoia.complete_recovery()
        self._refresh_all()

    def on_shown(self) -> None:
        self._refresh_all()

    # --- convenience for tests --------------------------------------------

    def visible_score(self) -> str:
        return self._score_card.value()

    def state_text(self) -> str:
        return self._state_chip.text()

    def visible_activities(self) -> int:
        return self._activity_table.rowCount()

    def visible_transitions(self) -> int:
        return self._transition_table.rowCount()

    def audit_rows(self) -> int:
        return self._audit_table.rowCount()
