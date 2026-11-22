"""Deterministic progress meter for the paranoia score."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ssg8.ui import theme
from ssg8.services.paranoia.states import ParanoiaState

_STATE_COLOURS: dict[ParanoiaState, str] = {
    ParanoiaState.NORMAL: theme.SUCCESS,
    ParanoiaState.SUSPICIOUS: theme.WARNING,
    ParanoiaState.RESTRICTIVE: "#E38A32",
    ParanoiaState.MAXIMUM_PARANOIA: theme.DANGER,
    ParanoiaState.SELF_AUDIT: theme.DANGER,
    ParanoiaState.SELF_THREAT_DETECTED: theme.DANGER,
    ParanoiaState.SELF_QUARANTINE: theme.INFO,
    ParanoiaState.RECOVERY: theme.SUCCESS,
}


class ScoreMeter(QWidget):
    """A horizontal 0-100 meter with a live numeric value and a tick legend."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._score = 0
        self._state = ParanoiaState.NORMAL

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        row.addWidget(_caption("0"))
        self._bar = QProgressBar(self)
        self._bar.setRange(0, 100)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(12)
        self._bar.setMinimumWidth(0)
        row.addWidget(self._bar, 1)
        row.addWidget(_caption("100"))
        layout.addLayout(row)

        legend = QHBoxLayout()
        legend.setContentsMargins(0, 0, 0, 0)
        legend.setSpacing(0)
        for text, tip in (
            ("0-19", "NORMAL 0-19"),
            ("20-39", "SUSPICIOUS 20-39"),
            ("40-69", "RESTRICTIVE 40-69"),
            ("70-100", "MAXIMUM PARANOIA 70-100"),
        ):
            label = QLabel(text, self)
            label.setObjectName("StatCaption")
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label.setToolTip(tip)
            label.setMinimumWidth(0)
            label.setSizePolicy(
                QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred
            )
            legend.addWidget(label, 1)
        layout.addLayout(legend)

        self.set_score(0, ParanoiaState.NORMAL)

    def set_score(self, score: int, state: ParanoiaState) -> None:
        self._score = max(0, min(100, int(score)))
        self._state = state
        colour = _STATE_COLOURS.get(state, theme.ACCENT)
        self._bar.setStyleSheet(
            "QProgressBar {"
            f" background-color: {theme.SURFACE_RAISED};"
            f" border: 1px solid {theme.BORDER};"
            " border-radius: 5px;"
            " }"
            "QProgressBar::chunk {"
            f" background-color: {colour};"
            " border-radius: 5px;"
            " }"
        )
        self._bar.setValue(self._score)

    def score(self) -> int:
        return self._score

    def state(self) -> ParanoiaState:
        return self._state


def _caption(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("StatCaption")
    label.setFixedWidth(30)
    return label
