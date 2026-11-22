"""Shared page frame: scrolling content, demonstrates notices and navigation."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QScrollArea, QVBoxLayout, QWidget

from ssg8.core.context import AppContext
from ssg8.ui.components.empty_state import EmptyState
from ssg8.ui.components.notice_banner import NoticeBanner

CONTENT_MARGINS = (28, 24, 28, 28)


class BasePage(QWidget):
    """Base class for every page in the control center.

    Subclasses set :attr:`page_id` during construction, implement
    :meth:`build` to populate ``self.body`` and may override
    :meth:`on_shown` to refresh themselves when navigated to.
    """

    navigate_requested = Signal(str)

    page_id: str = ""

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        self._built = False
        self._demo_banners: list[NoticeBanner] = []
        self._empty_widgets: list[tuple[QWidget, EmptyState]] = []

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self._scroll = QScrollArea(self)
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        self._content = QWidget()
        self._content.setObjectName("PageContent")
        self.body = QVBoxLayout(self._content)
        self.body.setContentsMargins(*CONTENT_MARGINS)
        self.body.setSpacing(16)
        self.body.setAlignment(Qt.AlignmentFlag.AlignTop)

        self._scroll.setWidget(self._content)
        outer.addWidget(self._scroll)

        self.context.preferences.changed.connect(self._on_preference_changed)

    # --- lifecycle ---------------------------------------------------------

    def ensure_built(self) -> None:
        """Build the page content once."""
        if self._built:
            return
        self._built = True
        self.build()

    def build(self) -> None:  # pragma: no cover - overridden by pages
        """Populate ``self.body``. Implemented by each page."""

    def on_shown(self) -> None:
        """Called every time the page becomes the visible page."""

    # --- helpers -----------------------------------------------------------

    def notify_decision(self, decision) -> None:
        """Show a native security warning only for a rejected request."""
        from ssg8.security.decisions import ProtectionAction
        if decision.action is ProtectionAction.BLOCK:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.warning(
                self, "SSG8 Security Alert",
                f"{decision.module.upper()} — ACCESS RESTRICTED\n\n"
                f"Target: {decision.target}\n\nReason: {decision.reason}"
            )


    def navigate_to(self, page_id: str) -> None:
        self.navigate_requested.emit(page_id)

    def add_demo_notice(
        self,
        text: str,
        tone: str = "warning",
        icon: str | None = None,
    ) -> NoticeBanner:
        """Add a notice banner that follows the demonstration-notice preference."""
        banner = NoticeBanner(text, tone, icon, self._content)
        banner.setVisible(self.context.preferences.get("show_demo_notices"))
        self._demo_banners.append(banner)
        self.body.addWidget(banner)
        return banner

    def register_empty_pair(self, table: QWidget, empty: EmptyState) -> None:
        """Keep a table and its empty state in sync automatically."""
        self._empty_widgets.append((table, empty))
        self._sync_empty_pair(table, empty)
        self.context.preferences.changed.connect(lambda _key: self._sync_empty_pair(table, empty))

    def sync_empty_states(self) -> None:
        for table, empty in self._empty_widgets:
            self._sync_empty_pair(table, empty)

    @staticmethod
    def _sync_empty_pair(table: QWidget, empty: EmptyState) -> None:
        has_rows = bool(getattr(table, "rowCount", lambda: 0)())
        table.setVisible(has_rows)
        empty.setVisible(not has_rows)

    def _on_preference_changed(self, key: str) -> None:
        if key != "show_demo_notices":
            return
        visible = self.context.preferences.get("show_demo_notices")
        for banner in self._demo_banners:
            banner.setVisible(visible)
