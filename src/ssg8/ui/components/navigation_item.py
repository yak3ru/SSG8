"""Sidebar navigation button with an icon that follows its state."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QPushButton, QWidget

from ssg8.ui import theme
from ssg8.ui.components import icons
from ssg8.ui.navigation import NavigationEntry

ICON_SIZE = 16
ITEM_HEIGHT = 38


class NavigationItem(QPushButton):
    """A checkable, icon-and-label navigation button."""

    def __init__(self, entry: NavigationEntry, parent: QWidget | None = None) -> None:
        super().__init__(entry.label, parent)
        self.page_id = entry.page_id
        self._icon_name = entry.icon
        self._hovered = False

        self.setObjectName("NavItem")
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(ITEM_HEIGHT)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setIconSize(QSize(ICON_SIZE, ICON_SIZE))
        self.setToolTip(entry.label)
        self._sync_icon()

    # --- state -------------------------------------------------------------

    def _icon_colour(self) -> str:
        if self.isChecked():
            return theme.TEXT_PRIMARY
        if self._hovered:
            return theme.TEXT_SECONDARY
        return theme.TEXT_MUTED

    def _sync_icon(self) -> None:
        self.setIcon(icons.make_icon(self._icon_name, self._icon_colour(), ICON_SIZE))

    def setChecked(self, checked: bool) -> None:  # noqa: N802 - Qt naming
        super().setChecked(checked)
        self._sync_icon()

    def nextCheckState(self) -> None:  # noqa: N802 - Qt naming
        # Clicking the active page keeps it selected instead of toggling off.
        if not self.isChecked():
            super().nextCheckState()

    def enterEvent(self, event) -> None:  # noqa: N802 - Qt naming
        self._hovered = True
        self._sync_icon()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # noqa: N802 - Qt naming
        self._hovered = False
        self._sync_icon()
        super().leaveEvent(event)
