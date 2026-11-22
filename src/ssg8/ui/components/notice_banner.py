"""Inline notice banners used to state limitations honestly."""

from __future__ import annotations

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QWidget

from ssg8.ui import theme
from ssg8.ui.components import icons
from ssg8.ui.components.action_button import ActionButton


class NoticeBanner(QFrame):
    """A tinted strip with an icon and an explanatory message."""

    _ICONS = {
        "warning": "alert",
        "danger": "alert",
        "info": "info",
        "success": "check",
        "neutral": "info",
        "accent": "shield",
    }

    def __init__(
        self,
        text: str,
        tone: str = "warning",
        icon: str | None = None,
        parent: QWidget | None = None,
        *,
        dismissible: bool = False,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("NoticeBanner")
        palette = theme.tone(tone)
        self._tone_name = tone

        self.setStyleSheet(
            "QFrame#NoticeBanner {"
            f" background-color: {palette.background};"
            f" border: 1px solid {palette.border};"
            " border-radius: 6px;"
            " }"
            "QLabel#NoticeText {"
            f" color: {palette.text};"
            " font-size: 8.5pt;"
            " }"
        )

        row = QHBoxLayout(self)
        row.setContentsMargins(13, 9, 11, 9)
        row.setSpacing(10)

        icon_label = QLabel(self)
        icon_label.setPixmap(icons.make_pixmap(icon or self._ICONS.get(tone, "info"), palette.text, 15))
        row.addWidget(icon_label, 0)

        self._text = QLabel(text, self)
        self._text.setObjectName("NoticeText")
        self._text.setWordWrap(True)
        row.addWidget(self._text, 1)

        if dismissible:
            dismiss = ActionButton("", "icon", "close", self, icon_size=12)
            dismiss.setFixedSize(22, 22)
            dismiss.setToolTip("Dismiss")
            dismiss.clicked.connect(self.hide)
            row.addWidget(dismiss, 0)

    def set_text(self, text: str) -> None:
        self._text.setText(text)

    def text(self) -> str:
        return self._text.text()

    def tone(self) -> str:
        return self._tone_name
