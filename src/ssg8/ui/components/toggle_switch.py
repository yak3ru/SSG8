"""Animated on/off switch used for interface configuration."""

from __future__ import annotations

from PySide6.QtCore import Property, QEasingCurve, QPropertyAnimation, QRectF, Qt
from PySide6.QtGui import QColor, QPainter
from PySide6.QtWidgets import QAbstractButton, QWidget

from ssg8.ui import theme

TRACK_WIDTH = 38
TRACK_HEIGHT = 21
KNOB_INSET = 2.5

_OFF_COLOR = QColor("#2C2C35")
_ON_COLORS = {"accent": QColor(theme.ACCENT), "success": QColor(theme.SUCCESS)}
_DISABLED_TRACK = QColor("#1A1A1F")
_DISABLED_KNOB = QColor("#4A4A55")


class ToggleSwitch(QAbstractButton):
    """A compact switch that animates between its two states.

    This is a pure interface control. It changes local configuration only.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        checked: bool = False,
        tone: str = "accent",
    ) -> None:
        super().__init__(parent)
        self.setCheckable(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(TRACK_WIDTH, TRACK_HEIGHT)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._on_color = _ON_COLORS.get(tone, _ON_COLORS["accent"])
        self._position = 1.0 if checked else 0.0
        self._hovered = False

        self._animation = QPropertyAnimation(self, b"position", self)
        self._animation.setDuration(140)
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)

        self.setChecked(checked)
        self.toggled.connect(self._animate_to_state)

    # --- animated property -------------------------------------------------

    def _get_position(self) -> float:
        return self._position

    def _set_position(self, value: float) -> None:
        self._position = float(value)
        self.update()

    position = Property(float, _get_position, _set_position)

    def _animate_to_state(self, checked: bool) -> None:
        self._animation.stop()
        self._animation.setStartValue(self._position)
        self._animation.setEndValue(1.0 if checked else 0.0)
        self._animation.start()

    # --- public helpers ----------------------------------------------------

    def set_state_silently(self, checked: bool) -> None:
        """Set the state without emitting ``toggled`` or animating."""
        self.blockSignals(True)
        self.setChecked(checked)
        self.blockSignals(False)
        self._animation.stop()
        self._position = 1.0 if checked else 0.0
        self.update()

    def set_tone(self, tone: str) -> None:
        self._on_color = _ON_COLORS.get(tone, _ON_COLORS["accent"])
        self.update()

    # --- painting ----------------------------------------------------------

    def enterEvent(self, event) -> None:  # noqa: N802 - Qt naming
        self._hovered = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # noqa: N802 - Qt naming
        self._hovered = False
        self.update()
        super().leaveEvent(event)

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        track = QRectF(0.5, 0.5, self.width() - 1.0, self.height() - 1.0)
        radius = track.height() / 2.0

        if not self.isEnabled():
            track_color = _DISABLED_TRACK
            knob_color = _DISABLED_KNOB
        else:
            track_color = self._blend(_OFF_COLOR, self._on_color, self._position)
            if self._hovered:
                track_color = track_color.lighter(118)
            knob_color = QColor("#F4F4F6")

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(track_color)
        painter.drawRoundedRect(track, radius, radius)

        diameter = track.height() - KNOB_INSET * 2
        travel = track.width() - diameter - KNOB_INSET * 2
        knob_x = track.left() + KNOB_INSET + travel * self._position
        painter.setBrush(knob_color)
        painter.drawEllipse(QRectF(knob_x, track.top() + KNOB_INSET, diameter, diameter))
        painter.end()

    @staticmethod
    def _blend(start: QColor, end: QColor, ratio: float) -> QColor:
        ratio = max(0.0, min(1.0, ratio))
        return QColor(
            round(start.red() + (end.red() - start.red()) * ratio),
            round(start.green() + (end.green() - start.green()) * ratio),
            round(start.blue() + (end.blue() - start.blue()) * ratio),
        )
