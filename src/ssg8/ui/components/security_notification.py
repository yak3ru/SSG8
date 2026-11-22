"""Frameless desktop alert shown after SSG8 sends an application a close request."""

from __future__ import annotations

from pathlib import PureWindowsPath

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt
from PySide6.QtGui import QColor, QFontMetrics, QMouseEvent
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ssg8.ui.components.icons import make_app_icon, make_icon, make_pixmap

WIDTH = 520
SHADOW_MARGIN = 16
PAD = 24
# Width left for values: card - padding - badge column - ident padding - key column.
VALUE_WIDTH = WIDTH - 2 * PAD - (40 + 16) - 2 * 16 - (80 + 16)

_STYLE = """
#card { background: #111114; border: 1px solid #303038; border-radius: 12px; }
#header { border-bottom: 1px solid #24242B; }
#footer { background: #0D0D10; border-top: 1px solid #24242B;
          border-bottom-left-radius: 12px; border-bottom-right-radius: 12px; }
QLabel { color: #F4F4F6; background: transparent; }
#brand { font-size: 14px; font-weight: 600; letter-spacing: 0.5px; }
#status { color: #D8404A; font-size: 10px; font-weight: 600; letter-spacing: 1.4px; }
#heading { font-size: 17px; font-weight: 600; }
#body { color: #92929D; font-size: 13px; }
#badge { background: #2A1215; border: 1px solid #4A1C22; border-radius: 10px; }
#ident { background: #19191E; border: 1px solid #26262D; border-radius: 8px; }
#key { color: #6E6E78; font-size: 11px; font-weight: 600; letter-spacing: 0.8px; }
#value { font-size: 13px; }
#mono { color: #C9C9D1; font-family: "Cascadia Mono", Consolas, monospace; font-size: 12px; }
#hint { color: #6E6E78; font-size: 12px; }
#dot { background: #3FB950; border-radius: 3px; }
#close { background: transparent; border: none; border-radius: 6px; padding: 0; }
#close:hover { background: #22222A; color: #F4F4F6; }
#close:pressed { background: #2A2A33; }
#ok { background: #A51D2D; color: #FFFFFF; border: 1px solid #B8283A; border-radius: 7px;
      padding: 0 26px; min-height: 34px; font-size: 13px; font-weight: 600; }
#ok:hover { background: #BA2536; border-color: #CC3446; }
#ok:pressed { background: #861724; border-color: #861724; }
#ok:focus { outline: none; border-color: #E06A74; }
"""


def _label(text: str, name: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName(name)
    return label


class SecurityNotification(QDialog):
    """Nonmodal, always-on-top notice for one close-request result."""

    def __init__(self, name: str, closed: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowFlags(
            Qt.WindowType.Window
            | Qt.WindowType.FramelessWindowHint
            | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.setWindowIcon(make_app_icon())
        self.setWindowTitle("SSG8 - Application Blocked")
        self.setStyleSheet(_STYLE)
        self._drag_offset = None

        executable = PureWindowsPath(name).name or name
        stem = executable[:-4] if executable.lower().endswith(".exe") else executable
        app_name = stem.replace("_", " ").replace("-", " ").strip()
        app_name = app_name[:1].upper() + app_name[1:] if app_name else executable

        card = QFrame(objectName="card")
        card.setFixedWidth(WIDTH)
        shadow = QGraphicsDropShadowEffect(card)
        shadow.setBlurRadius(28)
        shadow.setOffset(0, 6)
        shadow.setColor(QColor(0, 0, 0, 150))
        card.setGraphicsEffect(shadow)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(SHADOW_MARGIN, SHADOW_MARGIN, SHADOW_MARGIN, SHADOW_MARGIN)
        outer.addWidget(card)
        root = QVBoxLayout(card)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header: brand, status, close.
        header = QFrame(objectName="header")
        self._header = header
        row = QHBoxLayout(header)
        row.setContentsMargins(PAD, 14, 14, 14)
        row.setSpacing(10)
        logo = QLabel()
        logo.setPixmap(make_app_icon(22).pixmap(22, 22))
        row.addWidget(logo)
        row.addWidget(_label("SSG8", "brand"))
        sep = _label("•", "hint")
        row.addWidget(sep)
        row.addWidget(_label("APPLICATION BLOCKED", "status"))
        row.addStretch(1)
        close = QPushButton(objectName="close")
        close.setIcon(make_icon("close", "#92929D", 16))
        close.setFixedSize(28, 28)
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.setToolTip("Dismiss")
        close.setAccessibleName("Dismiss notification")
        close.clicked.connect(self.reject)
        row.addWidget(close)
        root.addWidget(header)

        # Content: indicator beside heading, description and identity card.
        content = QHBoxLayout()
        content.setContentsMargins(PAD, 22, PAD, 22)
        content.setSpacing(16)
        badge = QFrame(objectName="badge")
        badge.setFixedSize(40, 40)
        badge_layout = QVBoxLayout(badge)
        badge_layout.setContentsMargins(0, 0, 0, 0)
        icon = QLabel()
        icon.setPixmap(make_pixmap("alert", "#D8404A", 20))
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge_layout.addWidget(icon)
        content.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)

        text = QVBoxLayout()
        text.setSpacing(6)
        heading = _label(
            "Application window closed" if closed else "Close requested", "heading"
        )
        heading.setWordWrap(True)
        text.addWidget(heading)
        body = _label(
            "The window disappeared after a standard Windows close request."
            if closed else
            "The window may still be open or may be showing a save prompt.",
            "body",
        )
        body.setWordWrap(True)
        text.addWidget(body)
        text.addSpacing(10)

        ident = QFrame(objectName="ident")
        grid = QGridLayout(ident)
        grid.setContentsMargins(16, 12, 16, 12)
        grid.setHorizontalSpacing(16)
        grid.setVerticalSpacing(8)
        grid.setColumnStretch(1, 1)
        values = []
        for row_index, (key, value, style) in enumerate(
            (("APPLICATION", app_name, "value"), ("EXECUTABLE", executable, "mono"))
        ):
            key_label = _label(key, "key")
            key_label.setFixedWidth(80)
            grid.addWidget(key_label, row_index, 0, Qt.AlignmentFlag.AlignVCenter)
            value_label = _label(value, style)
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value_label.setToolTip(name)
            grid.addWidget(value_label, row_index, 1)
            values.append((value_label, value))
        text.addWidget(ident)
        content.addLayout(text, 1)
        root.addLayout(content)

        # Footer: protection status and acknowledgement.
        footer = QFrame(objectName="footer")
        foot = QHBoxLayout(footer)
        foot.setContentsMargins(PAD, 12, PAD, 12)
        foot.setSpacing(8)
        dot = QFrame(objectName="dot")
        dot.setFixedSize(6, 6)
        foot.addWidget(dot, 0, Qt.AlignmentFlag.AlignVCenter)
        foot.addWidget(_label("Application Protection active", "hint"))
        foot.addStretch(1)
        ok = QPushButton("OK", objectName="ok")
        ok.setCursor(Qt.CursorShape.PointingHandCursor)
        ok.setDefault(True)
        ok.clicked.connect(self.accept)
        foot.addWidget(ok)
        root.addWidget(footer)

        # Elide long names so the dialog keeps its width; the full value is in the
        # tooltip. Measured only now, once the style sheet fonts have been applied.
        for value_label, value in values:
            value_label.ensurePolished()
            value_label.setText(
                QFontMetrics(value_label.font()).elidedText(
                    value, Qt.TextElideMode.ElideMiddle, VALUE_WIDTH
                )
            )
        self.adjustSize()
        self._fade = QPropertyAnimation(self, b"windowOpacity", self)
        self._fade.setDuration(180)
        self._fade.setStartValue(0.0)
        self._fade.setEndValue(1.0)
        self._fade.setEasingCurve(QEasingCurve.Type.OutCubic)

    def showEvent(self, event) -> None:  # noqa: N802 - Qt override
        super().showEvent(event)
        self._fade.start()

    # Frameless window: let the header act as the drag handle.
    def mousePressEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton and self._header.geometry().contains(
            self._header.parentWidget().mapFrom(self, event.position().toPoint())
        ):
            self._drag_offset = event.globalPosition().toPoint() - self.pos()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if self._drag_offset is not None:
            self.move(event.globalPosition().toPoint() - self._drag_offset)
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        self._drag_offset = None
        super().mouseReleaseEvent(event)
