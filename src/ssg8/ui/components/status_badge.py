"""Pill shaped status indicator used across the SSG8 interface."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy, QWidget

from ssg8.ui import theme

DOT_SIZE = 7


class StatusBadge(QFrame):
    """A coloured dot and a short uppercase label.

    ``tone`` selects from :data:`ssg8.ui.theme.TONES`; ``success`` is the
    default because most badges describe a healthy local state.
    """

    def __init__(
        self,
        text: str = "",
        tone: str = "success",
        parent: QWidget | None = None,
        *,
        height: int = 26,
        show_dot: bool = True,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("StatusBadge")
        self.setFixedHeight(height)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(11, 0, 13, 0)
        layout.setSpacing(7)

        self._dot = QFrame(self)
        self._dot.setObjectName("StatusDot")
        self._dot.setFixedSize(DOT_SIZE, DOT_SIZE)
        self._dot.setVisible(show_dot)

        self._label = QLabel(text, self)
        self._label.setObjectName("StatusText")
        self._label.setFont(theme.with_letter_spacing(self._label.font(), 0.9))

        if show_dot:
            layout.addWidget(self._dot, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self._label, 0, Qt.AlignmentFlag.AlignVCenter)

        self._tone_name = tone
        self._apply_tone(tone)

    # --- public API --------------------------------------------------------

    def text(self) -> str:
        return self._label.text()

    def set_text(self, text: str) -> None:
        self._label.setText(text)

    def set_tone(self, tone: str) -> None:
        """Change the colour tone of the badge."""
        self._tone_name = tone
        self._apply_tone(tone)

    def tone(self) -> str:
        return self._tone_name

    # --- internals ---------------------------------------------------------

    def _apply_tone(self, tone: str) -> None:
        palette = theme.tone(tone)
        radius = self.height() // 2
        self.setStyleSheet(
            "QFrame#StatusBadge {"
            f" background-color: {palette.background};"
            f" border: 1px solid {palette.border};"
            f" border-radius: {radius}px;"
            " }"
            "QLabel#StatusText {"
            f" color: {palette.text};"
            " font-size: 8.5pt;"
            " font-weight: 700;"
            " }"
            "QFrame#StatusDot {"
            f" background-color: {palette.text};"
            f" border-radius: {DOT_SIZE // 2}px;"
            " }"
        )
