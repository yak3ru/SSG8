"""Native PySide6 risk-trend chart.

No charting dependency is introduced: the widget paints the findings produced
by the SSG8 analysis service directly.
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QWidget

from ssg8.security.analysis.models import ThreatFinding
from ssg8.ui import theme

LEFT_GUTTER = 38
RIGHT_GUTTER = 16
TOP_GUTTER = 14
BOTTOM_GUTTER = 26


class RiskTrendChart(QWidget):
    """A lightweight line chart of finding scores over time."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._points: tuple[ThreatFinding, ...] = ()
        self.setMinimumHeight(196)

    def set_points(self, points: tuple[ThreatFinding, ...] | list[ThreatFinding]) -> None:
        self._points = tuple(points)
        self.update()

    def points_count(self) -> int:
        return len(self._points)

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt naming
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        plot = QRectF(
            LEFT_GUTTER,
            TOP_GUTTER,
            max(10.0, self.width() - LEFT_GUTTER - RIGHT_GUTTER),
            max(10.0, self.height() - TOP_GUTTER - BOTTOM_GUTTER),
        )

        label_font = QFont(self.font())
        label_font.setPointSizeF(7.5)
        painter.setFont(label_font)

        for value, fraction in ((100, 0.0), (75, 0.25), (50, 0.5), (25, 0.75), (0, 1.0)):
            y = plot.top() + plot.height() * fraction
            painter.setPen(QPen(QColor(theme.BORDER), 1))
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            painter.setPen(QColor(theme.TEXT_FAINT))
            painter.drawText(
                QRectF(0, y - 8, LEFT_GUTTER - 8, 16),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                str(value),
            )

        if not self._points:
            painter.setPen(QColor(theme.TEXT_MUTED))
            body_font = QFont(self.font())
            body_font.setPointSizeF(9)
            painter.setFont(body_font)
            painter.drawText(
                plot,
                Qt.AlignmentFlag.AlignCenter,
                "Risk trend appears after the first analysis finding.",
            )
            painter.end()
            return

        count = len(self._points)
        positions: list[QPointF] = []
        for index, finding in enumerate(self._points):
            x = (
                plot.center().x()
                if count == 1
                else plot.left() + plot.width() * index / (count - 1)
            )
            y = plot.bottom() - plot.height() * max(0, min(100, finding.score)) / 100
            positions.append(QPointF(x, y))

        path = QPainterPath(positions[0])
        for point in positions[1:]:
            path.lineTo(point)
        painter.setPen(QPen(QColor(theme.ACCENT), 2))
        painter.drawPath(path)

        if len(positions) > 1:
            fill = QPainterPath(path)
            fill.lineTo(positions[-1].x(), plot.bottom())
            fill.lineTo(positions[0].x(), plot.bottom())
            fill.closeSubpath()
            painter.fillPath(fill, QColor(176, 32, 43, 34))

        for finding, point in zip(self._points, positions):
            painter.setPen(QPen(QColor(theme.tone(finding.level.tone).text), 2))
            painter.setBrush(QColor(theme.tone(finding.level.tone).text))
            painter.drawEllipse(point, 3.5, 3.5)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        painter.setPen(QColor(theme.TEXT_FAINT))
        first = self._points[0].created_at.strftime("%H:%M")
        last = self._points[-1].created_at.strftime("%H:%M")
        painter.drawText(
            QRectF(plot.left(), plot.bottom() + 6, 80, 16),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            first,
        )
        painter.drawText(
            QRectF(plot.right() - 80, plot.bottom() + 6, 80, 16),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            last,
        )
        painter.end()
