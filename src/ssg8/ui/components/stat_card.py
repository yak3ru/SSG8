"""Compact metric cards used on the dashboard."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ssg8.ui import theme
from ssg8.ui.components import icons

_VALUE_TONES: dict[str, str] = {
    "success": theme.SUCCESS,
    "warning": theme.WARNING,
    "danger": theme.DANGER,
    "info": theme.INFO,
}



class StatCard(QFrame):
    """A label, a value and a caption describing one honest interface state."""

    def __init__(
        self,
        label: str,
        value: str,
        caption: str = "",
        icon: str | None = None,
        parent: QWidget | None = None,
        *,
        value_tone: str | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("StatCard")
        self.setMinimumHeight(92)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 13, 16, 13)
        layout.setSpacing(6)

        top = QHBoxLayout()
        top.setContentsMargins(0, 0, 0, 0)
        top.setSpacing(8)

        self._label = QLabel(label.upper(), self)
        self._label.setObjectName("StatLabel")
        self._label.setFont(theme.with_letter_spacing(self._label.font(), 0.8))
        top.addWidget(self._label)
        top.addStretch(1)

        if icon:
            icon_label = QLabel(self)
            icon_label.setPixmap(icons.make_pixmap(icon, theme.TEXT_FAINT, 15))
            top.addWidget(icon_label, 0, Qt.AlignmentFlag.AlignTop)

        layout.addLayout(top)

        self._value = QLabel(value, self)
        self._value.setObjectName("StatValue")
        layout.addWidget(self._value)

        self._caption = QLabel(caption, self)
        self._caption.setObjectName("StatCaption")
        self._caption.setWordWrap(True)
        self._caption.setVisible(bool(caption))
        layout.addWidget(self._caption)

        self.set_value(value, value_tone)

    def set_value(self, value: str, value_tone: str | None = None) -> None:
        self._value.setText(value)
        colour = _VALUE_TONES.get(value_tone or "")
        self._value.setStyleSheet(f"color: {colour};" if colour else "")

    def set_caption(self, caption: str) -> None:
        self._caption.setText(caption)
        self._caption.setVisible(bool(caption))

    def value(self) -> str:
        return self._value.text()
