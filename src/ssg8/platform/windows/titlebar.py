"""Windows specific window chrome for SSG8.

Qt paints its own client area, but the native title bar is drawn by Windows.
These helpers ask the Desktop Window Manager for the immersive dark title bar
so the whole window matches the dark interface.

Everything here is purely cosmetic and strictly optional: any failure is
swallowed and the application keeps its default window frame.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from PySide6.QtWidgets import QWidget

# DWMWA_USE_IMMERSIVE_DARK_MODE from Windows 10 20H1 onwards; older builds
# expose the same behaviour under attribute 19.
_DWMWA_USE_IMMERSIVE_DARK_MODE = 20
_DWMWA_USE_IMMERSIVE_DARK_MODE_LEGACY = 19


def apply_dark_title_bar(window: QWidget) -> bool:
    """Request a dark native title bar for ``window``.

    Returns ``True`` when Windows accepted the request, ``False`` otherwise.
    """
    if sys.platform != "win32":
        return False

    try:
        hwnd = wintypes.HWND(int(window.winId()))
        enabled = ctypes.c_int(1)
        dwmapi = ctypes.windll.dwmapi

        for attribute in (_DWMWA_USE_IMMERSIVE_DARK_MODE, _DWMWA_USE_IMMERSIVE_DARK_MODE_LEGACY):
            result = dwmapi.DwmSetWindowAttribute(
                hwnd,
                ctypes.c_uint(attribute),
                ctypes.byref(enabled),
                ctypes.sizeof(enabled),
            )
            if result == 0:
                return True
    except Exception:  # pragma: no cover - cosmetic only, never fatal
        return False

    return False
