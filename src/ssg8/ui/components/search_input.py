"""Search and filter input widgets."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter
from PySide6.QtWidgets import QComboBox, QLineEdit, QWidget

from ssg8.ui import theme
from ssg8.ui.components import icons


class SearchInput(QLineEdit):
    """A line edit with a leading magnifier icon and a clear button."""

    def __init__(self, placeholder: str = "Search", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SearchInput")
        self.setPlaceholderText(placeholder)
        self.setClearButtonEnabled(True)
        self.setMinimumHeight(34)
        self.setMinimumWidth(190)
        self.addAction(
            icons.make_icon("search", theme.TEXT_MUTED, 15),
            QLineEdit.ActionPosition.LeadingPosition,
        )


class SelectBox(QComboBox):
    """A combo box with a painted chevron instead of a platform arrow."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("SelectBox")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(34)
        self.setMinimumWidth(150)

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt naming
        super().paintEvent(event)

        pixmap = icons.make_pixmap(
            "chevron-down",
            theme.TEXT_FAINT if not self.isEnabled() else theme.TEXT_MUTED,
            13,
        )
        ratio = pixmap.devicePixelRatio() or 1.0
        logical_width = pixmap.width() / ratio
        logical_height = pixmap.height() / ratio

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.drawPixmap(
            int(self.width() - logical_width - 10),
            int((self.height() - logical_height) / 2),
            pixmap,
        )
        painter.end()

    def add_options(self, options: list[tuple[str, object]]) -> None:
        """Populate the box from ``(label, value)`` pairs."""
        for label, value in options:
            self.addItem(label, value)

    def current_value(self) -> object:
        return self.currentData()

    def current_as(self, enum_type):
        """Return the current value coerced to ``enum_type``.

        Qt stores item data in a ``QVariant``, so ``str`` based enums arrive
        back as plain strings. This converts them safely, returning ``None``
        for the "all" entry and for anything that cannot be converted.
        """
        value = self.currentData()
        if value is None:
            return None
        try:
            return enum_type(value)
        except (TypeError, ValueError):
            return None

