"""The standard bordered panel used to group content."""

from __future__ import annotations

from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget


class ContentPanel(QFrame):
    """A panel with an optional title block, header actions and a body layout."""

    def __init__(
        self,
        title: str = "",
        subtitle: str = "",
        parent: QWidget | None = None,
        *,
        margins: tuple[int, int, int, int] = (18, 16, 18, 16),
        spacing: int = 12,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("Panel")

        self._root = QVBoxLayout(self)
        self._root.setContentsMargins(*margins)
        self._root.setSpacing(spacing)

        self._actions = QHBoxLayout()
        self._actions.setContentsMargins(0, 0, 0, 0)
        self._actions.setSpacing(8)

        if title:
            self._root.addWidget(self._build_header(title, subtitle))
            self._root.addSpacing(2)

        self.body = QVBoxLayout()
        self.body.setContentsMargins(0, 0, 0, 0)
        self.body.setSpacing(10)
        self._root.addLayout(self.body)

    # --- public API --------------------------------------------------------

    def add_action(self, widget: QWidget) -> None:
        """Add a widget to the panel header's right hand side."""
        self._actions.addWidget(widget)

    def add_body_widget(self, widget: QWidget, stretch: int = 0) -> None:
        self.body.addWidget(widget, stretch)

    def add_divider(self) -> QFrame:
        """Add a horizontal rule between sections of the body."""
        divider = QFrame()
        divider.setObjectName("PanelDivider")
        divider.setFixedHeight(1)
        self.body.addWidget(divider)
        return divider

    # --- internals ---------------------------------------------------------

    def _build_header(self, title: str, subtitle: str) -> QWidget:
        header = QWidget()
        row = QHBoxLayout(header)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)

        text_column = QVBoxLayout()
        text_column.setContentsMargins(0, 0, 0, 0)
        text_column.setSpacing(3)

        title_label = QLabel(title)
        title_label.setObjectName("PanelTitle")
        text_column.addWidget(title_label)

        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setObjectName("PanelSubtitle")
            subtitle_label.setWordWrap(True)
            text_column.addWidget(subtitle_label)

        row.addLayout(text_column, 1)
        row.addLayout(self._actions)
        return header


def divider() -> QFrame:
    """Return a standalone horizontal rule."""
    line = QFrame()
    line.setObjectName("PanelDivider")
    line.setFixedHeight(1)
    return line


def vertical_divider(height: int = 22) -> QFrame:
    """Return a thin vertical separator for headers and toolbars."""
    line = QFrame()
    line.setObjectName("HeaderDivider")
    line.setFixedSize(1, height)
    return line
