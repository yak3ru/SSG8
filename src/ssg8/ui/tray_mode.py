"""Visible Windows tray mode for SSG8.

X hides the dashboard and pauses application window-closing. The program
remains running until the user selects Quit SSG8 from the tray menu.
Existing MainWindow code and cleanup are intentionally left unchanged.
"""
from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, QTimer
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from ssg8.ui.components.icons import make_app_icon


class TrayMode(QObject):
    """Make the window hide on X, with visible restore and quit controls."""

    def __init__(self, app, window) -> None:
        super().__init__(app)
        self.app = app
        self.window = window
        self._quitting = False
        self.tray = None

        # Without a system tray, preserve standard X-to-exit behavior.
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        self.app.setQuitOnLastWindowClosed(False)
        self.tray = QSystemTrayIcon(make_app_icon(), self)
        self.tray.setToolTip("SSG8 — Running (protection paused while hidden)")

        self.menu = QMenu()
        open_action = self.menu.addAction("Open SSG8")
        open_action.triggered.connect(self.restore)
        self.menu.addSeparator()

        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self._on_tray_clicked)
        self.tray.show()
        self.window.installEventFilter(self)

    def eventFilter(self, watched, event):  # noqa: N802 - Qt naming
        if watched is self.window and event.type() == QEvent.Type.Close:
            if self._quitting:
                return False

            # The existing self-quarantine finale must still exit normally.
            if getattr(self.window, "_finale", None) is not None:
                self._quitting = True
                if self.tray is not None:
                    self.tray.hide()
                QTimer.singleShot(0, self.app.quit)
                return False

            if self.tray is not None and self.tray.isVisible():
                # Prevent interfering with Windows after the main UI is hidden.
                # Other app state and existing GUI code remain unchanged.
                self.window.context.protection.set_module_enabled("application", False)
                event.ignore()
                self.window.hide()
                return True
        return super().eventFilter(watched, event)

    def _on_tray_clicked(self, reason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self.restore()

    def restore(self) -> None:
        if self.window.isMinimized():
            self.window.showNormal()
        else:
            self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    def quit(self) -> None:
        """Exit through MainWindow's existing cleanup path."""
        if self._quitting:
            return
        self._quitting = True
        self.window.context.protection.set_module_enabled("application", False)
        if self.tray is not None:
            self.tray.hide()
        self.window.close()
        self.app.quit()
