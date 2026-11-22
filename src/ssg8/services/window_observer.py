"""Read-only observation of newly opened Windows top-level application windows.

Never requests elevated privileges and NEVER closes, terminates or restricts an
external process. Windows titles, document names and command lines aren't logged.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import sys

from PySide6.QtCore import QObject, QTimer, Signal


@dataclass(frozen=True)
class WindowRecord:
    handle: int
    process_id: int
    executable: str


def new_windows(before: tuple[WindowRecord, ...], after: tuple[WindowRecord, ...], own_pid: int) -> tuple[WindowRecord, ...]:
    """Return newly seen windows; exclude our own process and incomplete records."""
    seen = {(w.handle, w.process_id) for w in before}
    return tuple(
        w for w in after if (w.handle, w.process_id) not in seen
        and w.process_id != own_pid and w.executable
    )


def windows_snapshot() -> tuple[WindowRecord, ...]:
    """Read nonempty, visible top-level window owners using Win32 APIs."""
    if sys.platform != 'win32':
        return ()
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    func = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    enum = user32.EnumWindows
    enum.argtypes = [func, wintypes.LPARAM]
    enum.restype = wintypes.BOOL
    visible = user32.IsWindowVisible
    visible.argtypes = [wintypes.HWND]
    visible.restype = wintypes.BOOL
    title_len = user32.GetWindowTextLengthW
    title_len.argtypes = [wintypes.HWND]
    title_len.restype = ctypes.c_int
    owner = user32.GetWindowThreadProcessId
    owner.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    owner.restype = wintypes.DWORD
    get_class = user32.GetClassNameW
    get_class.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    get_class.restype = ctypes.c_int
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    query_name = kernel32.QueryFullProcessImageNameW
    query_name.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    query_name.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    ignore_classes = {'Shell_TrayWnd','Shell_SecondaryTrayWnd','Progman','WorkerW'}
    out: list[WindowRecord] = []
    names: dict[int,str] = {}
    @func
    def callback(hwnd, _):
        try:
            if not visible(hwnd) or title_len(hwnd) <= 0:
                return True
            buffer = ctypes.create_unicode_buffer(256)
            get_class(hwnd, buffer, len(buffer))
            if buffer.value in ignore_classes:
                return True
            pid = wintypes.DWORD()
            owner(hwnd, ctypes.byref(pid))
            if not pid.value:
                return True
            if pid.value not in names:
                handle = open_process(0x1000, False, pid.value) # PROCESS_QUERY_LIMITED_INFORMATION
                name = ''
                if handle:
                    try:
                        path = ctypes.create_unicode_buffer(32768)
                        size = wintypes.DWORD(len(path))
                        if query_name(handle, 0, path, ctypes.byref(size)):
                            name = os.path.basename(path.value)
                    finally:
                        close_handle(handle)
                names[pid.value] = name
            if names[pid.value]:
                out.append(WindowRecord(int(hwnd), pid.value, names[pid.value]))
        except Exception:
            pass
        return True
    enum(callback, 0)
    return tuple(out)


class WindowObserver(QObject):
    """Observe only; never sends WM_CLOSE, termination or other commands."""
    opened = Signal(object)
    changed = Signal(bool)
    def __init__(self, parent=None, *, snapshot=windows_snapshot):
        super().__init__(parent)
        self._snapshot = snapshot
        self._baseline: tuple[WindowRecord,...] = ()
        self._enabled = False
        self._timer = QTimer(self)
        self._timer.setInterval(300)
        self._timer.timeout.connect(self.poll)
    def enabled(self) -> bool:
        return self._enabled
    def set_enabled(self, enabled: bool) -> None:
        enabled = bool(enabled) and sys.platform == 'win32'
        if enabled == self._enabled:
            return
        self._enabled = enabled
        if enabled:
            self._baseline = self._snapshot()  # Never flag preexisting windows.
            self._timer.start()
        else:
            self._timer.stop()
            self._baseline = ()
        self.changed.emit(enabled)
    def poll(self) -> None:
        if not self._enabled:
            return
        try:
            current = self._snapshot()
        except Exception:
            return
        fresh = new_windows(self._baseline, current, os.getpid())
        self._baseline = current
        for window in fresh[:24]:  # Keep the UI responsive during bursts.
            self.opened.emit(window)
    def stop(self) -> None:
        self.set_enabled(False)
