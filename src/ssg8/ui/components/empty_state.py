"""Empty state placeholder shown when a list or table has no rows."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

from ssg8.ui import theme
from ssg8.ui.components import icons


class EmptyState(QFrame):
    """A centred icon, title and explanation for an empty region."""

    def __init__(
        self,
        icon: str = "info",
        title: str = "Nothing to show",
        description: str = "",
        parent: QWidget | None = None,
        *,
        minimum_height: int = 168,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("EmptyState")
        self.setMinimumHeight(minimum_height)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 26, 28, 26)
        layout.setSpacing(8)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._icon = QLabel(self)
        self._icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._icon.setPixmap(icons.make_pixmap(icon, theme.TEXT_FAINT, 26))
        layout.addWidget(self._icon)

        self._title = QLabel(title, self)
        self._title.setObjectName("EmptyTitle")
        self._title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._title)

        self._text = QLabel(description, self)
        self._text.setObjectName("EmptyText")
        self._text.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._text.setWordWrap(True)
        self._text.setMinimumWidth(380)
        self._text.setMaximumWidth(520)
        self._text.setVisible(bool(description))
        layout.addWidget(self._text)

    def set_content(self, icon: str, title: str, description: str = "") -> None:
        """Replace the placeholder content."""
        self._icon.setPixmap(icons.make_pixmap(icon, theme.TEXT_FAINT, 26))
        self._title.setText(title)
        self._text.setText(description)
        self._text.setVisible(bool(description))
