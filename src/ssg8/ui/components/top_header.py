"""Top header: page identity, application status and header shortcuts."""

from __future__ import annotations

from PySide6.QtCore import QPoint, Qt, Signal
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QMenu, QVBoxLayout, QWidget

from ssg8.services.event_log import EventLog
from ssg8.ui import theme
from ssg8.ui.components.action_button import IconButton
from ssg8.ui.components.chip import Chip
from ssg8.ui.components.panel import vertical_divider
from ssg8.ui.components.status_badge import StatusBadge
from ssg8.utils.formatting import format_timestamp

HEADER_HEIGHT = 76
MAX_MENU_ENTRIES = 8


class TopHeader(QFrame):
    """Shows the current page, a demonstration chip and app level controls."""

    settings_requested = Signal()
    logs_requested = Signal()

    def __init__(self, events: EventLog, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("TopHeader")
        self.setFixedHeight(HEADER_HEIGHT)
        self._events = events

        row = QHBoxLayout(self)
        row.setContentsMargins(28, 10, 18, 10)
        row.setSpacing(12)

        identity = QVBoxLayout()
        identity.setContentsMargins(0, 0, 0, 0)
        identity.setSpacing(2)

        self._breadcrumb = QLabel("OVERVIEW", self)
        self._breadcrumb.setObjectName("Breadcrumb")
        self._breadcrumb.setFont(theme.with_letter_spacing(self._breadcrumb.font(), 1.3))
        identity.addWidget(self._breadcrumb)

        self._title = QLabel("Dashboard", self)
        self._title.setObjectName("PageTitle")
        identity.addWidget(self._title)

        row.addLayout(identity, 1)

        self._demo_chip = Chip("DEMO", "warning", self)
        self._demo_chip.setToolTip(
            "Demonstration interface. No Windows security feature is active."
        )
        self._demo_chip.hide()

        self.status_badge = StatusBadge("APPLICATION ONLINE", "success", self)
        self.status_badge.setToolTip("The SSG8 interface process is running.")
        row.addWidget(self.status_badge, 0, Qt.AlignmentFlag.AlignVCenter)

        self._notifications = IconButton("bell", "Recent application events", self)
        self._notifications.clicked.connect(self._show_event_menu)
        row.addWidget(self._notifications, 0, Qt.AlignmentFlag.AlignVCenter)

        row.addWidget(vertical_divider(), 0, Qt.AlignmentFlag.AlignVCenter)

        self._settings = IconButton("sliders", "Open settings", self)
        self._settings.clicked.connect(self.settings_requested.emit)
        row.addWidget(self._settings, 0, Qt.AlignmentFlag.AlignVCenter)

    # --- public API --------------------------------------------------------

    def set_page(self, title: str, section: str) -> None:
        self._title.setText(title)
        self._breadcrumb.setText(section.upper())

    def page_title(self) -> str:
        return self._title.text()

    def breadcrumb(self) -> str:
        return self._breadcrumb.text()

    def notifications_button(self):
        return self._notifications

    def settings_button(self):
        return self._settings

    # --- notification menu -------------------------------------------------

    def build_event_menu(self) -> QMenu:
        """Build the recent-events menu without showing it."""
        menu = QMenu(self)
        entries = self._events.entries()[:MAX_MENU_ENTRIES]
        if not entries:
            empty = menu.addAction("No application events recorded")
            empty.setEnabled(False)
        else:
            for entry in entries:
                message = entry.message
                if len(message) > 64:
                    message = message[:61] + "..."
                action = menu.addAction(f"{format_timestamp(entry.timestamp)}   {message}")
                action.setEnabled(False)
        menu.addSeparator()
        view_all = menu.addAction("View all application events")
        view_all.triggered.connect(self.logs_requested.emit)
        return menu

    def _show_event_menu(self) -> None:
        menu = self.build_event_menu()
        position = self._notifications.mapToGlobal(
            QPoint(0, self._notifications.height() + 6)
        )
        menu.exec(position)
        menu.deleteLater()

    def event_count(self) -> int:
        return self._events.count()
