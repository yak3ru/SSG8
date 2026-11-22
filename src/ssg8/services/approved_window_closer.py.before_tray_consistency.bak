"""Graceful requests for ordinary app windows, including Explorer folders.

This module is intentionally *not* a Windows lockout: it never closes
administration/recovery tools, shell/taskbar windows, or the SSG8/VS Code
window.  No process termination, injection, privilege changes or persistence.
"""
from __future__ import annotations

import ctypes
import ntpath
import os
import sys
from ctypes import wintypes

from ssg8.services.window_observer import WindowRecord

WM_CLOSE = 0x0010

# The shell and system recovery/administration controls must stay usable.
EXEMPT_EXECUTABLES = frozenset({
    "code.exe", "code - insiders.exe", "code-insiders.exe",
    "ssg8.exe", "python.exe", "pythonw.exe",
    "cmd.exe", "conhost.exe", "powershell.exe", "pwsh.exe",
    "windowsterminal.exe", "wt.exe", "regedit.exe", "mmc.exe",
    "services.exe", "control.exe", "eventvwr.exe",
    "utilman.exe", "sethc.exe", "osk.exe",
    "magnify.exe", "narrator.exe", "consent.exe", "logonui.exe",
    "winlogon.exe", "csrss.exe", "dwm.exe", "sihost.exe",
    "startmenuexperiencehost.exe", "shellexperiencehost.exe",
    "searchhost.exe", "searchapp.exe", "securityhealthsystray.exe",
    "securityhealthservice.exe", "taskhostw.exe", "fontdrvhost.exe",
})
SHELL_CLASSES = frozenset({
    "Shell_TrayWnd", "Shell_SecondaryTrayWnd", "Progman", "WorkerW",
})
EXPLORER_FOLDER_CLASSES = frozenset({"CabinetWClass", "ExploreWClass"})


def can_request_close(executable: str, title: str, window_class: str = "") -> bool:
    """Decide whether a standard close request is appropriate for this window.

    Explorer *folder* windows are eligible, not the desktop or shell.
    Hosted UWP frames are eligible only for Calculator/Settings by title to
    avoid closing unrelated apps hosted in the same process.
    """
    exe = ntpath.basename(executable.replace("/", "\\")).casefold().strip()
    title = title.strip()
    if not exe or not title or window_class in SHELL_CLASSES:
        return False
    if exe in EXEMPT_EXECUTABLES:
        return False
    if exe == "explorer.exe":
        return window_class in EXPLORER_FOLDER_CLASSES
    if exe == "applicationframehost.exe":
        return title.casefold() in {"calculator", "settings", "paint"}
    return True


def _win32_target(window: WindowRecord):
    """Validate HWND and PID immediately before making a close request."""
    if sys.platform != "win32" or window.process_id == os.getpid():
        return None
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.IsWindow.argtypes = [wintypes.HWND]
    user32.IsWindow.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int
    user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetWindow.restype = wintypes.HWND

    hwnd = wintypes.HWND(window.handle)
    if not user32.IsWindow(hwnd) or not user32.IsWindowVisible(hwnd):
        return None
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value != window.process_id:
        return None
    # Never close an owned popup (including save/confirmation dialogs).
    if user32.GetWindow(hwnd, 4):  # GW_OWNER
        return None
    length = user32.GetWindowTextLengthW(hwnd)
    if length <= 0:
        return None
    text = ctypes.create_unicode_buffer(min(length + 1, 32768))
    user32.GetWindowTextW(hwnd, text, len(text))
    window_class = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, window_class, len(window_class))
    if not can_request_close(window.executable, text.value, window_class.value):
        return None
    return user32, hwnd


def request_normal_close(window: WindowRecord) -> bool:
    """Post WM_CLOSE; True means *requested*, not necessarily completed."""
    target = _win32_target(window)
    if target is None:
        return False
    user32, hwnd = target
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.PostMessageW.restype = wintypes.BOOL
    return bool(user32.PostMessageW(hwnd, WM_CLOSE, 0, 0))


def window_still_open(window: WindowRecord) -> bool:
    """Return True while the same window remains visible and owned by PID."""
    if sys.platform != "win32":
        return False
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.IsWindow.argtypes = [wintypes.HWND]
    user32.IsWindow.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    hwnd = wintypes.HWND(window.handle)
    if not user32.IsWindow(hwnd) or not user32.IsWindowVisible(hwnd):
        return False
    owner = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
    return owner.value == window.process_id
