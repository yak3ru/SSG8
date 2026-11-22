"""Small tinted label used for severities, states and counts."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QSizePolicy, QWidget

from ssg8.ui import theme


class Chip(QLabel):
    """A compact, rounded label tinted with a semantic tone."""

    def __init__(
        self,
        text: str = "",
        tone: str = "neutral",
        parent: QWidget | None = None,
        *,
        point_size: float = 8.0,
    ) -> None:
        super().__init__(text, parent)
        self.setObjectName("Chip")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        self._point_size = point_size
        self._tone_name = tone
        self._apply_tone(tone)

    def tone(self) -> str:
        return self._tone_name

    def set_tone(self, tone: str) -> None:
        self._tone_name = tone
        self._apply_tone(tone)

    def _apply_tone(self, tone: str) -> None:
        self.setStyleSheet(
            "QLabel {"
            f" {theme.tone_style_sheet(tone, radius=4, padding='2px 8px')}"
            f" font-size: {self._point_size}pt;"
            " font-weight: 600;"
            " }"
        )


class ChipCell(QWidget):
    """Left aligned wrapper that keeps a chip compact inside a table cell."""

    def __init__(
        self,
        text: str,
        tone: str = "neutral",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(10, 0, 10, 0)
        row.setSpacing(0)
        self._chip = Chip(text, tone, self)
        row.addWidget(self._chip, 0, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        row.addStretch(1)

    def chip(self) -> Chip:
        return self._chip

    def set_text(self, text: str) -> None:
        self._chip.setText(text)

    def set_tone(self, tone: str) -> None:
        self._chip.set_tone(tone)


class CellContainer(QWidget):
    """Left aligned wrapper for a single widget inside a table cell."""

    def __init__(self, widget: QWidget, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        row = QHBoxLayout(self)
        row.setContentsMargins(10, 0, 10, 0)
        row.setSpacing(0)
        widget.setParent(self)
        row.addWidget(widget, 0, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        row.addStretch(1)
        self._widget = widget

    def widget(self) -> QWidget:
        return self._widget

