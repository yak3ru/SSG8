"""Two column label/value list used by Settings and About."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QLabel, QWidget

from ssg8.ui import theme


class InfoList(QWidget):
    """A compact grid of descriptive rows."""

    def __init__(self, parent: QWidget | None = None, *, label_width: int = 190) -> None:
        super().__init__(parent)
        self._grid = QGridLayout(self)
        self._grid.setContentsMargins(0, 0, 0, 0)
        self._grid.setHorizontalSpacing(18)
        self._grid.setVerticalSpacing(9)
        self._grid.setColumnMinimumWidth(0, label_width)
        self._grid.setColumnStretch(1, 1)
        self._row = 0

    def add_row(self, label: str, value: str, *, mono: bool = False) -> QLabel:
        """Append a row and return the value label for later updates."""
        label_widget = QLabel(label, self)
        label_widget.setObjectName("MutedText")
        label_widget.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)

        value_widget = QLabel(value, self)
        value_widget.setObjectName("ValueText")
        value_widget.setWordWrap(True)
        value_widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if mono:
            value_widget.setFont(theme.mono_font(9.0))

        self._grid.addWidget(label_widget, self._row, 0, Qt.AlignmentFlag.AlignTop)
        self._grid.addWidget(value_widget, self._row, 1, Qt.AlignmentFlag.AlignTop)
        self._row += 1
        return value_widget


class ColourSwatch(QLabel):
    """A small square showing a colour from the palette."""

    def __init__(self, colour: str, parent: QWidget | None = None, *, size: int = 14) -> None:
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setStyleSheet(
            f"background-color: {colour};"
            " border: 1px solid #3A3A46;"
            " border-radius: 3px;"
        )
