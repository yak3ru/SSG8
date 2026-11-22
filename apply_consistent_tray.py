"""Align SSG8's foreground/tray behavior for approved demo applications.

Run from the outer SSG8 project folder (the one containing src/ssg8).
This alters ONLY:
  src/ssg8/ui/tray_mode.py
  src/ssg8/ui/main_window.py
  src/ssg8/services/approved_window_closer.py
It creates .before_tray_consistency.bak backups before the first change.

No separate process, service, watchdog, privilege elevation, or startup task.
Windows shell, administration, and recovery windows remain usable.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path.cwd()
MAIN = ROOT / "src/ssg8/ui/main_window.py"
TRAY = ROOT / "src/ssg8/ui/tray_mode.py"
CLOSER = ROOT / "src/ssg8/services/approved_window_closer.py"

TRAY_CODE = '''"""Single-process system-tray mode for SSG8.

Closing the dashboard hides it, without changing the module setting or
pausing the observer. One foreground/tray policy applies to approved
nonessential test apps. Pause and Quit are always available in the tray.
"""
from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, QTimer
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from ssg8.ui.components.icons import make_app_icon


class TrayMode(QObject):
    """Keep SSG8 available in the same process after the dashboard hides."""

    def __init__(self, app, window) -> None:
        super().__init__(app)
        self.app = app
        self.window = window
        self._quitting = False
        self._first_hide = True
        self.tray: QSystemTrayIcon | None = None

        # Without a working tray, allow the usual X-to-exit behavior.
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        self.app.setQuitOnLastWindowClosed(False)
        self.tray = QSystemTrayIcon(make_app_icon(), self)
        self.tray.setToolTip("SSG8 — Running in this Windows session")

        self.menu = QMenu()
        self.open_action = self.menu.addAction("Open SSG8")
        self.open_action.triggered.connect(self.restore)
        self.pause_action = self.menu.addAction("Pause Application Protection")
        self.pause_action.triggered.connect(self.pause_protection)
        self.menu.addSeparator()
        self.status_action = self.menu.addAction("Application Protection: OFF")
        self.status_action.setEnabled(False)  # bool, not the string "False"
        self.menu.addSeparator()
        self.quit_action = self.menu.addAction("Quit SSG8")
        self.quit_action.triggered.connect(self.quit)

        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self._on_tray_clicked)
        self.window.context.protection.modules_changed.connect(self._refresh_status)
        observer = getattr(self.window, "window_observer", None)
        if observer is not None and hasattr(observer, "changed"):
            observer.changed.connect(self._refresh_status)
        self.window.installEventFilter(self)
        self.app.aboutToQuit.connect(self._on_app_quit)
        self.tray.show()
        self._refresh_status()

    def eventFilter(self, watched, event):  # noqa: N802 - Qt override
        if watched is self.window and event.type() == QEvent.Type.Close:
            if self._quitting:
                return False  # Allow MainWindow.closeEvent to clean up.

            # Self-audit finale is an intentional genuine exit.
            if getattr(self.window, "_finale", None) is not None:
                self._quitting = True
                self.pause_protection()
                if self.tray is not None:
                    self.tray.hide()
                QTimer.singleShot(0, self.app.quit)
                return False

            if self.tray is not None and self.tray.isVisible():
                # Do not touch protection state or observer. Hide UI only.
                event.ignore()
                self.window.hide()
                self._refresh_status()
                if self._first_hide and self.tray.supportsMessages():
                    self._first_hide = False
                    self.tray.showMessage(
                        "SSG8 is still running",
                        "Use the tray to Open SSG8, Pause Protection, or Quit.",
                        QSystemTrayIcon.MessageIcon.Information,
                        4500,
                    )
                return True
        return super().eventFilter(watched, event)

    def _on_tray_clicked(self, reason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self.restore()

    def restore(self) -> None:
        if self._quitting:
            return
        if self.window.isMinimized():
            self.window.showNormal()
        else:
            self.window.show()
        self.window.raise_()
        self.window.activateWindow()
        # The observer was never stopped, so do not restart/reset its baseline.
        self._refresh_status()

    def pause_protection(self) -> None:
        """Explicit, user-controlled stop for application protection."""
        protection = self.window.context.protection
        if protection.is_module_enabled("application"):
            protection.set_module_enabled("application", False)
        observer = getattr(self.window, "window_observer", None)
        if observer is not None and observer.enabled():
            observer.stop()
        self._refresh_status()

    def _refresh_status(self) -> None:
        if self.tray is None:
            return
        enabled = self.window.context.protection.is_module_enabled("application")
        observer = getattr(self.window, "window_observer", None)
        active = bool(observer is not None and observer.enabled())
        if enabled and active:
            status = "Application Protection: ON (monitoring)"
        elif enabled:
            status = "Application Protection: ON (observer inactive)"
        else:
            status = "Application Protection: OFF"
        self.status_action.setText(status)
        self.pause_action.setEnabled(enabled)
        self.tray.setToolTip("SSG8 — " + status)

    def quit(self) -> None:
        if self._quitting:
            return
        self.pause_protection()
        self._quitting = True
        if self.tray is not None:
            self.tray.hide()
        self.window.close()
        self.app.quit()

    def _on_app_quit(self) -> None:
        if self._quitting:
            return
        self._quitting = True
        if self.tray is not None:
            self.tray.hide()
        self.window.close()
'''

MAIN_HANDLER = '''    def _on_window_opened(self, window) -> None:
        """Use one approved test-app close policy in dashboard and tray modes."""
        if not self.context.protection.is_module_enabled("application"):
            return
        key = (window.handle, window.process_id)
        if key in self._close_requests:
            return
        # Approved_window_closer applies the same nonessential-app safety
        # policy regardless of whether the SSG8 dashboard is hidden.
        if not request_normal_close(window):
            return
        self._close_requests.add(key)
        QTimer.singleShot(400, lambda w=window: self._check_close_request(w))

'''

CLOSER_POLICY = '''# Only explicitly approved, nonessential test applications can be closed
# automatically, whether SSG8 is visible or running in the tray.
APPROVED_TEST_APPS = frozenset({
    "calc.exe", "calculatorapp.exe", "notepad.exe", "mspaint.exe",
})


def can_request_close(executable: str, title: str, window_class: str = "") -> bool:
    """Never close Windows shell, administration, or recovery windows."""
    exe = ntpath.basename(executable.replace("/", "\\\\")).casefold().strip()
    title = title.strip()
    if not exe or not title or window_class in SHELL_CLASSES:
        return False
    if exe in APPROVED_TEST_APPS:
        return True
    # A Windows 11 Calculator frame can be hosted by ApplicationFrameHost.
    # The exact title constraint avoids indiscriminately closing hosted apps.
    if exe == "applicationframehost.exe":
        return title.casefold() == "calculator"
    return False


'''


def update_main(text: str) -> str:
    start_label = "    def _on_window_opened(self, window) -> None:"
    end_label = "    def _check_close_request(self, window) -> None:"
    if text.count(start_label) != 1 or text.count(end_label) != 1:
        raise RuntimeError("Couldn't locate the expected MainWindow handler; no files changed")
    i = text.index(start_label)
    j = text.index(end_label, i)
    return text[:i] + MAIN_HANDLER + text[j:]


def update_closer(text: str) -> str:
    start_label = "def can_request_close(executable: str, title: str, window_class: str = \"\") -> bool:"
    end_label = "def _win32_target(window: WindowRecord):"
    if text.count(start_label) != 1 or text.count(end_label) != 1:
        raise RuntimeError("Couldn't locate the expected closer policy; no files changed")
    i = text.index(start_label)
    # Include our prior inserted policy header for repeatable, idempotent runs.
    marker = "# Only explicitly approved, nonessential test applications can be closed"
    if marker in text[:i]:
        i = text.rindex(marker, 0, i)
    j = text.index(end_label, i)
    return text[:i] + CLOSER_POLICY + text[j:]


def main() -> None:
    targets = (MAIN, TRAY, CLOSER)
    missing = [str(p) for p in targets if not p.is_file()]
    if missing:
        raise SystemExit("Run this from your outer SSG8 folder. Missing: " + ", ".join(missing))
    original = {p: p.read_text(encoding="utf-8") for p in targets}
    updated = {
        MAIN: update_main(original[MAIN]),
        TRAY: TRAY_CODE,
        CLOSER: update_closer(original[CLOSER]),
    }
    for path, source in updated.items():
        compile(source, str(path), "exec")

    # Only write files after all three syntax checks pass.
    for path in targets:
        if original[path] == updated[path]:
            print("Unchanged:", path.relative_to(ROOT))
            continue
        backup = path.with_suffix(path.suffix + ".before_tray_consistency.bak")
        if not backup.exists():
            backup.write_text(original[path], encoding="utf-8")
        path.write_text(updated[path], encoding="utf-8")
        print("Updated:", path.relative_to(ROOT))
    print("Done: the same approved test-app policy works in the dashboard and tray.")
    print("Pause and Quit remain in the tray; no hidden process is created.")


if __name__ == "__main__":
    main()
