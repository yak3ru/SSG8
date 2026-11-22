"""Section headings and page level titles."""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ssg8.ui import theme


class SectionHeading(QWidget):
    """A title, an optional description and an optional row of actions."""

    def __init__(
        self,
        title: str,
        description: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        text_column = QVBoxLayout()
        text_column.setContentsMargins(0, 0, 0, 0)
        text_column.setSpacing(3)

        self._title = QLabel(title)
        self._title.setObjectName("PanelTitle")
        text_column.addWidget(self._title)

        self._description = QLabel(description)
        self._description.setObjectName("PanelSubtitle")
        self._description.setWordWrap(True)
        self._description.setVisible(bool(description))
        text_column.addWidget(self._description)

        layout.addLayout(text_column, 1)

        self._actions = QHBoxLayout()
        self._actions.setContentsMargins(0, 0, 0, 0)
        self._actions.setSpacing(8)
        layout.addLayout(self._actions)

    def add_action(self, widget: QWidget) -> None:
        self._actions.addWidget(widget)

    def set_description(self, text: str) -> None:
        self._description.setText(text)
        self._description.setVisible(bool(text))

    def title(self) -> str:
        return self._title.text()


class PageIntro(QWidget):
    """The headline block at the top of a page."""

    def __init__(
        self,
        heading: str,
        lead: str = "",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self.heading = QLabel(heading)
        self.heading.setObjectName("PageHeading")
        layout.addWidget(self.heading)

        if lead:
            self.lead = QLabel(lead)
            self.lead.setObjectName("PageLead")
            self.lead.setWordWrap(True)
            self.lead.setMaximumWidth(880)
            layout.addWidget(self.lead)


def field_label(text: str) -> QLabel:
    """Return a small form label."""
    label = QLabel(text)
    label.setObjectName("FieldLabel")
    return label


def muted_label(text: str, wrap: bool = True) -> QLabel:
    """Return a muted explanatory label."""
    label = QLabel(text)
    label.setObjectName("MutedText")
    label.setWordWrap(wrap)
    return label


def mono_label(text: str) -> QLabel:
    """Return a monospaced label, used for paths and identifiers."""
    label = QLabel(text)
    label.setObjectName("MonoText")
    label.setFont(theme.mono_font(9.0))
    return label
