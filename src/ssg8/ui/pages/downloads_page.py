"""Download Protection: read-only metadata inspection with policy decisions."""

from __future__ import annotations

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel

from ssg8.security.decisions import ProtectionAction
from ssg8.ui.components.action_button import ActionButton
from ssg8.ui.components.chip import ChipCell
from ssg8.ui.components.data_table import DataTable
from ssg8.ui.components.empty_state import EmptyState
from ssg8.ui.components.info_list import InfoList
from ssg8.ui.components.panel import ContentPanel, divider
from ssg8.ui.components.protection import (
    DecisionSummary,
    ProtectionModuleRow,
    action_tone,
)
from ssg8.ui.components.search_input import SearchInput, SelectBox
from ssg8.ui.components.section_heading import PageIntro, field_label, muted_label
from ssg8.ui.pages.base_page import BasePage
from ssg8.utils.formatting import format_timestamp, shorten_path

EMPTY_TITLE = "No files inspected yet"
EMPTY_TEXT = (
    "Select a file and inspect it. SSG8 reads the file to compute a SHA-256 and "
    "applies the local policy. It is metadata inspection, not antivirus software."
)

DECISION_OPTIONS: list[tuple[str, object]] = [
    ("All decisions", None),
    ("Allowed", ProtectionAction.ALLOW.value),
    ("Blocked", ProtectionAction.BLOCK.value),
    ("Requires review", ProtectionAction.REVIEW.value),
]


class DownloadsPage(BasePage):
    """Inspect one explicitly selected file against the download policy."""

    page_id = "downloads"

    def build(self) -> None:
        self._selected_path = ""
        self._metadata_labels: dict[str, QLabel] = {}

        self.body.addWidget(
            PageIntro(
                "Download Protection",
                "Inspect a file you select and evaluate it against the internal policy. "
                "SSG8 never executes, opens, moves, modifies or deletes the file.",
            )
        )


        self.body.addWidget(self._build_status_panel())
        self.body.addWidget(self._build_inspection_panel())
        self.body.addWidget(self._build_history_panel())

        self.context.protection.changed.connect(self._refresh_history)
        self.context.protection.settings_changed.connect(self._refresh_limit)
        self._refresh_history()

    # --- construction ------------------------------------------------------

    def _build_status_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Download protection status",
            "Assess selected files using extension, size and integrity metadata.",
        )

        panel.body.addWidget(
            ProtectionModuleRow(
                self.context.protection,
                "download",
                panel,
                description=(
                    "When disabled, inspection requests are blocked with a "
                    "module-disabled reason instead of being evaluated."
                ),
            )
        )
        panel.body.addWidget(divider())

        info = InfoList(panel)
        info.add_row("Inspection engine", "Metadata, SHA-256 and extension policy")
        info.add_row("Quarantine or delete", "Not available \u2014 files are never moved")
        info.add_row("Result type", "Policy result, not a malware verdict")
        self._limit_value = info.add_row("Inspection limit", "")
        self._last_value = info.add_row("Last inspection", "None")
        panel.body.addWidget(info)

        panel.body.addWidget(
            muted_label(
                "Inspection history is kept in memory for this session only. "
                "No file content is stored."
            )
        )
        self._refresh_limit()
        return panel

    def _build_inspection_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Inspect a file",
            "SSG8 reads the selected file but never writes to it.",
        )

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.setSpacing(8)

        select_button = ActionButton("Select file", "secondary", "download", panel)
        select_button.clicked.connect(self._select_file)
        buttons.addWidget(select_button)

        inspect_button = ActionButton("Inspect file", "primary", "search", panel)
        inspect_button.clicked.connect(self._inspect)
        buttons.addWidget(inspect_button)

        clear_button = ActionButton("Clear", "ghost", parent=panel)
        clear_button.clicked.connect(self._clear)
        buttons.addWidget(clear_button)
        buttons.addStretch(1)
        panel.body.addLayout(buttons)

        selection_row = QHBoxLayout()
        selection_row.setContentsMargins(0, 0, 0, 0)
        selection_row.setSpacing(10)
        self._path_label = QLabel("No file selected", panel)
        self._path_label.setObjectName("MonoText")
        self._path_label.setWordWrap(True)
        selection_row.addWidget(self._path_label, 1)
        panel.body.addLayout(selection_row)

        self._decision = DecisionSummary(panel)
        panel.body.addWidget(self._decision)

        panel.add_divider()
        panel.body.addWidget(field_label("File metadata"))

        metadata = InfoList(panel)
        for key, label in (
            ("name", "File name"),
            ("size", "Size"),
            ("extension", "Extension"),
            ("mime", "MIME type"),
            ("sha256", "SHA-256"),
        ):
            self._metadata_labels[key] = metadata.add_row(label, "\u2014")
        self._metadata_labels["inspected"] = metadata.add_row("Inspected", "\u2014")
        panel.body.addWidget(metadata)

        panel.body.addWidget(
            muted_label(
                "A passing result means the file type and size match the local policy. "
                "It does not guarantee that the file is safe."
            )
        )
        return panel

    def _build_history_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Inspection history",
            "Newest first. Kept for this session only.",
        )

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(0, 0, 0, 0)
        toolbar.setSpacing(10)

        self._search = SearchInput("Search file names", panel)
        self._search.textChanged.connect(self._refresh_history)
        toolbar.addWidget(self._search, 1)

        self._result_filter = SelectBox(panel)
        self._result_filter.add_options(DECISION_OPTIONS)
        self._result_filter.currentIndexChanged.connect(self._refresh_history)
        toolbar.addWidget(self._result_filter)
        panel.body.addLayout(toolbar)

        self._table = DataTable(["File name", "Size", "Decision", "Inspected"], panel)
        self._table.configure_columns({0: 290, 1: 100, 2: 140}, stretch=0)
        self._table.itemSelectionChanged.connect(self._show_selected)
        panel.body.addWidget(self._table)

        self._empty = EmptyState("download", EMPTY_TITLE, EMPTY_TEXT, panel)
        panel.body.addWidget(self._empty)
        self.register_empty_pair(self._table, self._empty)
        return panel

    # --- data --------------------------------------------------------------

    def _refresh_limit(self) -> None:
        settings = self.context.protection.settings()
        self._limit_value.setText(f"{settings.max_file_size_mb} MB")

    def _refresh_history(self) -> None:
        query = self._search.text().strip().casefold()
        action_filter = self._result_filter.current_value()

        decisions = self.context.protection.decisions("download")
        self._table.clear_rows()
        for decision in decisions:
            if action_filter is not None and decision.action.value != action_filter:
                continue
            name = decision.metadata.get("name", decision.target)
            digest = decision.metadata.get("sha256", "")
            if query and query not in name.casefold() and query not in digest.casefold():
                continue
            self._table.add_row(
                [
                    name,
                    decision.metadata.get("size", "\u2014"),
                    ChipCell(decision.action_label, action_tone(decision.action)),
                    format_timestamp(decision.timestamp),
                ],
                decision,
            )

        if self._table.rowCount():
            self._empty.set_content("download", EMPTY_TITLE, EMPTY_TEXT)
        elif query or action_filter is not None:
            self._empty.set_content(
                "search",
                "No matching inspections",
                "No inspected file matches the current filters.",
            )
        else:
            self._empty.set_content("download", EMPTY_TITLE, EMPTY_TEXT)

        self.sync_empty_states()

    def _show_selected(self) -> None:
        decision = self._table.selected_payload()
        if decision is not None:
            self._show_decision(decision)

    def _show_decision(self, decision) -> None:
        self._decision.set_decision(decision)
        metadata = decision.metadata
        for key in ("name", "size", "extension", "mime", "sha256"):
            self._metadata_labels[key].setText(metadata.get(key, "\u2014") or "\u2014")
        self._metadata_labels["inspected"].setText(format_timestamp(decision.timestamp))
        self._last_value.setText(format_timestamp(decision.timestamp))

    # --- actions -----------------------------------------------------------

    def _select_file(self) -> None:
        path, _selected_filter = QFileDialog.getOpenFileName(
            self, "Select a file to inspect", "", "All files (*.*)"
        )
        if not path:
            return
        self._selected_path = path
        self._path_label.setText(shorten_path(path, 88))
        self._path_label.setToolTip(path)
        self._decision.set_message(
            "File selected. Choose Inspect file to evaluate it against the local policy."
        )

    def _inspect(self) -> None:
        if not self._selected_path:
            self._decision.set_message("Select a file before inspecting.")
            return

        decision = self.context.protection.evaluate_download(self._selected_path)
        self._show_decision(decision)
        self._refresh_history()
        self.notify_decision(decision)

    def _clear(self) -> None:
        self._selected_path = ""
        self._path_label.setText("No file selected")
        self._path_label.setToolTip("")
        self._decision.set_message("No request has been evaluated yet.")
        for label in self._metadata_labels.values():
            label.setText("\u2014")

    def on_shown(self) -> None:
        self._refresh_limit()
        self._refresh_history()

    # --- convenience for tests --------------------------------------------

    def select_file(self, path: str) -> None:
        self._selected_path = path
        self._path_label.setText(shorten_path(path, 88))
        self._path_label.setToolTip(path)

    def inspect_file(self, path: str):
        self.select_file(path)
        self._inspect()
        return self.context.protection.last_decision()

    def visible_inspections(self) -> int:
        return self._table.rowCount()
