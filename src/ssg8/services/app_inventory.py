"""Read-only Windows application inventory for SSG8's fictional malware scanner.

This module never opens, deletes, quarantines, or modifies any application.
The word MALWARE is a UI joke and is not a security verdict.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class InstalledApplication:
    name: str
    source: str


def _from_registry() -> list[InstalledApplication]:
    """Read installed-program records for current-user and machine scopes."""
    import winreg

    apps: list[InstalledApplication] = []
    uninstall = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                base = winreg.OpenKey(root, uninstall, 0, winreg.KEY_READ | view)
            except OSError:
                continue
            with base:
                index = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(base, index)
                        index += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(base, subkey) as item:
                            name = str(winreg.QueryValueEx(item, "DisplayName")[0]).strip()
                        if name:
                            apps.append(InstalledApplication(name, "Installed programs"))
                    except (OSError, ValueError, TypeError):
                        continue
    return apps


def _from_start_menu() -> list[InstalledApplication]:
    """Include programs launched from either Windows Start Menu scope."""
    locations: list[Path] = []
    program_data = os.environ.get("PROGRAMDATA")
    app_data = os.environ.get("APPDATA")
    if program_data:
        locations.append(Path(program_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs")
    if app_data:
        locations.append(Path(app_data) / "Microsoft" / "Windows" / "Start Menu" / "Programs")

    apps: list[InstalledApplication] = []
    for directory in locations:
        try:
            for entry in directory.rglob("*"):
                if entry.suffix.lower() not in {".lnk", ".url"}:
                    continue
                name = entry.stem.strip()
                if name and not name.casefold().startswith(("uninstall", "remove ")):
                    apps.append(InstalledApplication(name, "Start Menu"))
        except (OSError, PermissionError):
            continue
    return apps


def _from_store_packages() -> list[InstalledApplication]:
    """Best-effort inventory of Microsoft Store / packaged applications.

    Run hidden and with a timeout. Some managed PCs restrict PowerShell;
    failure here doesn't prevent registry/Start Menu enumeration.
    """
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    command = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "Get-AppxPackage | Select-Object -ExpandProperty Name",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True,
            errors="replace", timeout=20, creationflags=flags,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    return [
        InstalledApplication(line.strip(), "Microsoft Store / Windows package")
        for line in result.stdout.splitlines() if line.strip()
    ]


def _from_running_processes() -> list[InstalledApplication]:
    """Supplement installed applications with active executable names.

    This reads a Toolhelp snapshot, not Task Manager, and does not touch the
    running processes. Services may appear as well as ordinary applications.
    """
    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot is None or snapshot == ctypes.c_void_p(-1).value:
        return []
    apps: list[InstalledApplication] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            while True:
                if entry.szExeFile:
                    apps.append(InstalledApplication(entry.szExeFile, "Running process"))
                if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snapshot)
    return apps


def inventory_windows_apps() -> list[InstalledApplication]:
    """Return a best-effort deduplicated list of available Windows programs."""
    if sys.platform != "win32":
        return []
    records: dict[str, InstalledApplication] = {}
    # Sources are ordered by human-readable name preference.
    for reader in (
        _from_registry, _from_start_menu,
        _from_store_packages, _from_running_processes,
    ):
        try:
            entries = reader()
        except Exception:  # One denied/malformed source should not stop the scan.
            continue
        for app in entries:
            if app.name and (key := app.name.casefold().strip()) not in records:
                records[key] = app
    return sorted(records.values(), key=lambda app: app.name.casefold())
