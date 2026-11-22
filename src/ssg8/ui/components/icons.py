"""Vector icon set for SSG8, drawn with QPainter.

Icons are generated at runtime so the interface needs no image files and no
icon font, and so every icon can be tinted to match its state. All paths are
authored on a 24x24 grid and stroked with round caps for a consistent,
enterprise look.
"""

from __future__ import annotations

import math
from collections.abc import Callable

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap, QPolygonF

from ssg8.ui import theme

CANONICAL_SIZE = 24.0
DEFAULT_SIZE = 18
DEFAULT_STROKE = 1.7

_Drawable = Callable[[QPainter, str], None]


def _stroke(painter: QPainter, color: str, width: float = DEFAULT_STROKE) -> None:
    pen = QPen(QColor(color))
    pen.setWidthF(width)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)


def _fill_dot(painter: QPainter, color: str, x: float, y: float, radius: float) -> None:
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(color))
    painter.drawEllipse(QPointF(x, y), radius, radius)
    painter.setBrush(Qt.BrushStyle.NoBrush)


def _polyline(painter: QPainter, points: list[tuple[float, float]]) -> None:
    painter.drawPolyline(QPolygonF([QPointF(x, y) for x, y in points]))


def _arrow_head(painter: QPainter, tip: QPointF, angle_deg: float, color: str, length: float = 4.4) -> None:
    """Draw a filled arrowhead at ``tip`` pointing along ``angle_deg``."""
    radians = math.radians(angle_deg)
    back_x, back_y = -math.cos(radians) * length, math.sin(radians) * length
    spread = math.radians(24)
    path = QPainterPath(tip)
    for sign in (1, -1):
        angle = spread * sign
        x = back_x * math.cos(angle) - back_y * math.sin(angle)
        y = back_x * math.sin(angle) + back_y * math.cos(angle)
        path.lineTo(tip.x() + x, tip.y() + y)
    path.closeSubpath()
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(color))
    painter.drawPath(path)
    painter.setBrush(Qt.BrushStyle.NoBrush)


def _icon_dashboard(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    for rect in ((3.5, 3.5, 7, 7), (13.5, 3.5, 7, 7), (3.5, 13.5, 7, 7), (13.5, 13.5, 7, 7)):
        painter.drawRoundedRect(QRectF(*rect), 1.8, 1.8)


def _icon_globe(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    painter.drawEllipse(QRectF(3, 3, 18, 18))
    painter.drawLine(QPointF(3, 12), QPointF(21, 12))
    painter.drawEllipse(QRectF(8.2, 3, 7.6, 18))


def _icon_download(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    painter.drawLine(QPointF(12, 3.5), QPointF(12, 14.5))
    _polyline(painter, [(7, 10), (12, 15), (17, 10)])
    _polyline(painter, [(4, 16.5), (4, 20.5), (20, 20.5), (20, 16.5)])


def _icon_apps(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    painter.drawRoundedRect(QRectF(3, 4, 18, 16), 2.2, 2.2)
    painter.drawLine(QPointF(3, 8.4), QPointF(21, 8.4))
    painter.drawRoundedRect(QRectF(6.5, 11.5, 4.2, 4.2), 1.0, 1.0)
    painter.drawLine(QPointF(13.5, 12.2), QPointF(17.8, 12.2))
    painter.drawLine(QPointF(13.5, 14.9), QPointF(17.8, 14.9))


def _icon_bell(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    path = QPainterPath(QPointF(7.5, 16.4))
    path.lineTo(7.5, 11.0)
    path.cubicTo(7.5, 7.1, 16.5, 7.1, 16.5, 11.0)
    path.lineTo(16.5, 16.4)
    painter.drawPath(path)
    painter.drawLine(QPointF(4.8, 16.4), QPointF(19.2, 16.4))
    clapper = QPainterPath(QPointF(10.7, 17.1))
    clapper.cubicTo(11.0, 19.2, 13.0, 19.2, 13.3, 17.1)
    painter.drawPath(clapper)


def _icon_activity(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    _polyline(
        painter,
        [(3, 13), (7.4, 13), (9.7, 6.8), (12.4, 17.4), (15.0, 10.4), (16.8, 13), (21, 13)],
    )


def _icon_logs(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    painter.drawRoundedRect(QRectF(4.5, 3, 15, 18), 2.2, 2.2)
    for y in (8.0, 12.0, 16.0):
        painter.drawLine(QPointF(8, y), QPointF(16, y))


def _icon_lock(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    painter.drawRoundedRect(QRectF(5, 10.5, 14, 9.5), 2.0, 2.0)
    painter.drawArc(QRectF(8, 4, 8, 9), 0, 180 * 16)
    painter.drawLine(QPointF(8, 8.6), QPointF(8, 10.5))
    painter.drawLine(QPointF(16, 8.6), QPointF(16, 10.5))


def _icon_sliders(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    for y, knob in ((7.0, 9.0), (12.0, 15.0), (17.0, 7.5)):
        painter.drawLine(QPointF(3.5, y), QPointF(20.5, y))
        painter.setBrush(QColor(color))
        painter.drawEllipse(QPointF(knob, y), 2.2, 2.2)
        painter.setBrush(Qt.BrushStyle.NoBrush)


def _icon_info(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    painter.drawEllipse(QRectF(3, 3, 18, 18))
    painter.drawLine(QPointF(12, 11), QPointF(12, 16.6))
    _fill_dot(painter, color, 12, 7.9, 1.15)


def _icon_search(painter: QPainter, color: str) -> None:
    _stroke(painter, color, 1.8)
    painter.drawEllipse(QRectF(4.2, 4.2, 12, 12))
    painter.drawLine(QPointF(15.9, 15.9), QPointF(20.4, 20.4))


def _icon_plus(painter: QPainter, color: str) -> None:
    _stroke(painter, color, 1.9)
    painter.drawLine(QPointF(12, 5), QPointF(12, 19))
    painter.drawLine(QPointF(5, 12), QPointF(19, 12))


def _icon_trash(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    painter.drawLine(QPointF(4.5, 7), QPointF(19.5, 7))
    _polyline(painter, [(9.6, 7), (9.6, 4.6), (14.4, 4.6), (14.4, 7)])
    _polyline(painter, [(7, 7.2), (8, 20), (16, 20), (17, 7.2)])
    painter.drawLine(QPointF(10.6, 10.6), QPointF(11.0, 16.8))
    painter.drawLine(QPointF(13.4, 10.6), QPointF(13.0, 16.8))


def _icon_refresh(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    painter.drawArc(QRectF(4.5, 4.5, 15, 15), 60 * 16, 300 * 16)
    _arrow_head(painter, QPointF(19.5, 12.0), 90, color, length=4.0)


def _icon_check(painter: QPainter, color: str) -> None:
    _stroke(painter, color, 1.9)
    _polyline(painter, [(5.2, 12.6), (9.8, 17.2), (18.8, 6.8)])


def _icon_close(painter: QPainter, color: str) -> None:
    _stroke(painter, color, 1.8)
    painter.drawLine(QPointF(6.4, 6.4), QPointF(17.6, 17.6))
    painter.drawLine(QPointF(17.6, 6.4), QPointF(6.4, 17.6))


def _icon_alert(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    path = QPainterPath(QPointF(12, 4.2))
    path.lineTo(20.8, 19.6)
    path.lineTo(3.2, 19.6)
    path.closeSubpath()
    painter.drawPath(path)
    painter.drawLine(QPointF(12, 10.0), QPointF(12, 14.2))
    _fill_dot(painter, color, 12, 16.8, 1.15)


def _icon_power(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    painter.drawArc(QRectF(4.5, 4.5, 15, 15), 118 * 16, 304 * 16)
    painter.drawLine(QPointF(12, 3.2), QPointF(12, 10.4))


def _icon_shield(painter: QPainter, color: str) -> None:
    _stroke(painter, color)
    path = QPainterPath(QPointF(12, 3.2))
    path.lineTo(19.6, 5.9)
    path.lineTo(19.6, 11.6)
    path.cubicTo(19.6, 16.4, 15.9, 19.7, 12, 20.8)
    path.cubicTo(8.1, 19.7, 4.4, 16.4, 4.4, 11.6)
    path.lineTo(4.4, 5.9)
    path.closeSubpath()
    painter.drawPath(path)


def _icon_chevron_down(painter: QPainter, color: str) -> None:
    _stroke(painter, color, 1.8)
    _polyline(painter, [(7.2, 9.8), (12, 14.6), (16.8, 9.8)])


_BUILDERS: dict[str, _Drawable] = {
    "dashboard": _icon_dashboard,
    "globe": _icon_globe,
    "download": _icon_download,
    "apps": _icon_apps,
    "bell": _icon_bell,
    "activity": _icon_activity,
    "logs": _icon_logs,
    "lock": _icon_lock,
    "sliders": _icon_sliders,
    "info": _icon_info,
    "search": _icon_search,
    "plus": _icon_plus,
    "trash": _icon_trash,
    "refresh": _icon_refresh,
    "check": _icon_check,
    "close": _icon_close,
    "alert": _icon_alert,
    "power": _icon_power,
    "shield": _icon_shield,
    "chevron-down": _icon_chevron_down,
}

AVAILABLE_ICONS = frozenset(_BUILDERS)


def make_pixmap(
    name: str,
    color: str = theme.TEXT_SECONDARY,
    size: int = DEFAULT_SIZE,
    stroke: float = DEFAULT_STROKE,
) -> QPixmap:
    """Render the icon ``name`` to a device-pixel-ratio aware pixmap."""
    builder = _BUILDERS.get(name)
    ratio = 2.0
    pixmap = QPixmap(int(size * ratio), int(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.GlobalColor.transparent)

    if builder is None:
        return pixmap

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    scale = size / CANONICAL_SIZE
    painter.scale(scale, scale)
    builder(painter, color)
    painter.end()
    return pixmap


def make_icon(
    name: str,
    color: str = theme.TEXT_SECONDARY,
    size: int = DEFAULT_SIZE,
    stroke: float = DEFAULT_STROKE,
) -> QIcon:
    """Return the icon ``name`` tinted with ``color``."""
    return QIcon(make_pixmap(name, color, size, stroke))


def make_app_icon(size: int = 64) -> QIcon:
    """Return the SSG8 application icon: a shield on the accent colour."""
    ratio = 2.0
    pixmap = QPixmap(int(size * ratio), int(size * ratio))
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.GlobalColor.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.setPen(Qt.PenStyle.NoPen)
    painter.setBrush(QColor(theme.ACCENT))
    painter.drawRoundedRect(QRectF(0, 0, size, size), size * 0.22, size * 0.22)
    painter.scale(size / CANONICAL_SIZE, size / CANONICAL_SIZE)
    painter.translate(2.4, 2.4)
    painter.scale(0.8, 0.8)
    _icon_shield(painter, "#FFFFFF")
    painter.end()
    return QIcon(pixmap)
