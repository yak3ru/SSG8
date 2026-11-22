"""Buttons with a consistent set of visual variants and icons."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QPushButton, QWidget

from ssg8.ui import theme
from ssg8.ui.components import icons

ICON_COLORS: dict[str, str] = {
    "primary": "#FFF3F4",
    "secondary": theme.TEXT_SECONDARY,
    "danger": "#EE9296",
    "ghost": theme.TEXT_MUTED,
    "icon": theme.TEXT_SECONDARY,
    "icon-active": theme.TEXT_PRIMARY,
}

ICON_BUTTON_SIZE = 34


class ActionButton(QPushButton):
    """A push button styled through the shared ``buttonStyle`` property."""

    def __init__(
        self,
        text: str = "",
        style: str = "secondary",
        icon: str | None = None,
        parent: QWidget | None = None,
        *,
        icon_size: int = 15,
    ) -> None:
        super().__init__(text, parent)
        self._icon_name = icon
        self._icon_size = icon_size
        self.setProperty("buttonStyle", style)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        if icon is not None:
            self.setIcon(icons.make_icon(icon, ICON_COLORS.get(style, theme.TEXT_SECONDARY), icon_size))
            self.setIconSize(QSize(icon_size, icon_size))
        if style == "icon":
            self.setFixedSize(ICON_BUTTON_SIZE, ICON_BUTTON_SIZE)
            self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        theme.refresh_style(self)

    def set_style(self, style: str) -> None:
        """Switch the visual variant, updating the icon colour to match."""
        self.setProperty("buttonStyle", style)
        if self._icon_name is not None:
            self.setIcon(
                icons.make_icon(
                    self._icon_name,
                    ICON_COLORS.get(style, theme.TEXT_SECONDARY),
                    self._icon_size,
                )
            )
        theme.refresh_style(self)

    def set_icon_name(self, name: str, color: str | None = None) -> None:
        """Replace the icon, keeping the current variant colour by default."""
        self._icon_name = name
        style = self.property("buttonStyle") or "secondary"
        self.setIcon(icons.make_icon(name, color or ICON_COLORS.get(style, theme.TEXT_SECONDARY), self._icon_size))
        self.setIconSize(QSize(self._icon_size, self._icon_size))


class IconButton(ActionButton):
    """A square, icon-only button with a tooltip."""

    def __init__(
        self,
        icon: str,
        tooltip: str = "",
        parent: QWidget | None = None,
        *,
        icon_size: int = 17,
    ) -> None:
        super().__init__("", "icon", icon, parent, icon_size=icon_size)
        if tooltip:
            self.setToolTip(tooltip)
        self.setAccessibleName(tooltip or icon)
