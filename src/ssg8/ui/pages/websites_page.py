"""Website Protection: Edge companion status and recent website decisions.

No URL box or manual domain list is needed for Edge block-all mode. The Edge
extension observes navigations and the local bridge sends permitted metadata
into the existing ProtectionManager and autonomous escalation pipeline.
"""
from __future__ import annotations


from ssg8.ui.components.chip import ChipCell
from ssg8.ui.components.data_table import DataTable
from ssg8.ui.components.empty_state import EmptyState
from ssg8.ui.components.panel import ContentPanel
from ssg8.ui.components.protection import ProtectionModuleRow, action_tone
from ssg8.ui.components.section_heading import PageIntro, muted_label
from ssg8.ui.pages.base_page import BasePage
from ssg8.utils.formatting import format_timestamp


class WebsitesPage(BasePage):
    """Display connected Edge protection status and actual decision history."""

    page_id = "websites"

    def build(self) -> None:
        self.body.addWidget(PageIntro(
            "Website Protection",
            "Website navigation protection for a connected Microsoft Edge profile.",
        ))

        panel = ContentPanel(
            "Microsoft Edge protection",
            "Website blocking is automatic once protection activates; no URL list is required.",
        )
        panel.body.addWidget(ProtectionModuleRow(
            self.context.protection, "website", panel,
            description=(
                "Active protection redirects HTTP(S) websites to an SSG8 access-denied page "
                "in an Edge profile with the SSG8 extension installed."
            ),
        ))
        panel.body.addWidget(muted_label(
            "To connect Edge: open edge://extensions, enable Developer mode, "
            "choose Load unpacked, and select this project's edge-extension folder. "
            "The extension can always be paused or removed."
        ))
        self.body.addWidget(panel)

        history_panel = ContentPanel(
            "Recent website events",
            "Website requests recorded by SSG8. Only the domain is received from Edge.",
        )
        self._history = DataTable(
            ["Time", "Website", "Decision", "Reason"], history_panel, row_height=36
        )
        self._history.configure_columns({0: 145, 1: 230, 2: 110}, stretch=3)
        history_panel.body.addWidget(self._history)
        self._empty = EmptyState(
            "globe", "No website events yet",
            "Launch the SSG8 extension in Edge and visit a website to record an event.",
            history_panel, minimum_height=150,
        )
        history_panel.body.addWidget(self._empty)
        self.register_empty_pair(self._history, self._empty)
        self.body.addWidget(history_panel)

        self.context.protection.changed.connect(self._refresh)
        self._refresh()

    def _refresh(self) -> None:
        decisions = self.context.protection.decisions("website", limit=24)
        self._history.clear_rows()
        for decision in decisions:
            self._history.add_row(
                [format_timestamp(decision.timestamp), decision.target,
                 ChipCell(decision.action_label, action_tone(decision.action)),
                 decision.reason],
                decision,
            )
        self.sync_empty_states()

    def on_shown(self) -> None:
        self._refresh()

    # Backward-compatible programming/test helpers, not visible UI controls.
    def add_entry(self, domain: str, list_type: str = "block") -> tuple[bool, str]:
        return self.context.protection.add_website_rule(domain, list_type)

    def evaluate(self, url: str):
        return self.context.protection.evaluate_website(url)

    def visible_rules(self) -> int:
        return len(self.context.state.websites())

    def rule_domains(self) -> list[str]:
        return [entry.domain for entry in self.context.state.websites()]
