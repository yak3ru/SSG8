"""Optional, read-only Windows process awareness for the demonstration.

This component is deliberately small and strictly observational. It reads the
process identifier and executable name from the documented Toolhelp32 snapshot
API and nothing else. It never reads command lines, file contents, keystrokes,
screenshots, browser history or credentials, never intercepts network traffic,
never terminates a process and never changes process permissions.

Monitoring is disabled by default and must be started explicitly by the user.
If the platform or API is unavailable the monitor reports the limitation and
the rest of the demonstration continues in demonstration-only mode.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from datetime import datetime

from PySide6.QtCore import QObject, Signal

from ssg8.core.models import EventCategory, Severity
from ssg8.services.event_log import EventLog

TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260
MAX_PROCESSES = 500
INVALID_HANDLE_VALUE = -1


@dataclass(frozen=True, slots=True)
class ObservedProcess:
    """The only process data SSG8 collects: an id and an executable name."""

    pid: int
    name: str

    def describe(self) -> str:
        return f"{self.name} (pid {self.pid})"


@dataclass(frozen=True, slots=True)
class ProcessChange:
    """One observed start or exit between two snapshots."""

    timestamp: datetime
    kind: str
    process: ObservedProcess


class WindowsActivityMonitor(QObject):
    """Opt-in, read-only process name observer with a safe fallback."""

    changed = Signal()
    monitoring_changed = Signal(bool)
    observation_recorded = Signal(object)

    def __init__(
        self,
        events: EventLog | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._events = events
        self._enabled = False
        self._baseline: dict[tuple[int, str], ObservedProcess] = {}
        self._last_error = ""

    # --- availability ------------------------------------------------------

    def available(self) -> bool:
        """Whether the documented read-only process snapshot API can be used."""
        return sys.platform.startswith("win")

    def availability_note(self) -> str:
        if self.available():
            return (
                "Read-only process awareness is available. Only process identifiers and "
                "executable names are read, and only while monitoring is started."
            )
        return (
            "Read-only process awareness is unavailable on this platform. CyberLockdown "
            "continues in demonstration-only mode."
        )

    def last_error(self) -> str:
        return self._last_error

    # --- lifecycle ---------------------------------------------------------

    def enabled(self) -> bool:
        return self._enabled

    def start(self) -> bool:
        """Start observing process names. Returns ``False`` safely if unsupported."""
        if self._enabled:
            return True
        if not self.available():
            self._last_error = "Process awareness is not available on this platform."
            self._record(
                EventCategory.MONITORING,
                Severity.INFO,
                "Windows activity monitoring could not start; demonstration-only mode is active.",
                "The required read-only Windows API is unavailable.",
            )
            return False

        current = self.snapshot()
        if not current:
            self._last_error = (
                "The read-only process snapshot returned no processes; monitoring was not started."
            )
            self._record(
                EventCategory.MONITORING,
                Severity.MEDIUM,
                "Windows activity monitoring could not read process metadata; demonstration-only mode is active.",
                self._last_error,
            )
            return False

        self._last_error = ""
        self._baseline = {(process.pid, process.name): process for process in current}
        self._enabled = True
        self._record(
            EventCategory.MONITORING,
            Severity.INFO,
            (
                "Optional read-only Windows activity monitoring started: process identifiers "
                f"and names only ({len(current)} processes recorded as a baseline)."
            ),
            "Explicit user opt-in.",
        )
        self.monitoring_changed.emit(True)
        self.changed.emit()
        return True

    def stop(self) -> bool:
        """Stop observing. Safe to call repeatedly."""
        if not self._enabled:
            return False
        self._enabled = False
        self._baseline.clear()
        self._record(
            EventCategory.MONITORING,
            Severity.INFO,
            "Optional Windows activity monitoring stopped.",
            "User requested monitoring to stop.",
        )
        self.monitoring_changed.emit(False)
        self.changed.emit()
        return True

    def reset(self) -> None:
        """Stop monitoring without recording a user action (recovery safety)."""
        self._enabled = False
        self._baseline.clear()

    # --- observation -------------------------------------------------------

    def snapshot(self) -> tuple[ObservedProcess, ...]:
        """Return a sorted snapshot of process ids and executable names."""
        if not self.available():
            return ()
        try:
            return _snapshot_windows_processes()
        except OSError as exc:
            self._last_error = f"The process snapshot failed: {exc}"
            return ()
        except Exception as exc:  # noqa: BLE001 - observation must never crash the demo
            self._last_error = f"The process snapshot failed safely: {type(exc).__name__}"
            return ()

    def observe(self) -> tuple[ObservedProcess, ...]:
        """Return the current snapshot and record start/exit changes while enabled."""
        current = self.snapshot()
        if not self._enabled:
            return current

        now = datetime.now()
        current_map = {(process.pid, process.name): process for process in current}
        started = [
            process for key, process in current_map.items() if key not in self._baseline
        ]
        exited = [
            process for key, process in self._baseline.items() if key not in current_map
        ]
        changes = tuple(
            [ProcessChange(now, "started", process) for process in started]
            + [ProcessChange(now, "exited", process) for process in exited]
        )
        self._baseline = current_map
        for change in changes:
            self.observation_recorded.emit(change)
        if changes:
            started_names = ", ".join(process.name for process in started[:5]) or "none"
            exited_names = ", ".join(process.name for process in exited[:5]) or "none"
            self._record(
                EventCategory.MONITORING,
                Severity.INFO,
                "Windows process change observed (read-only): "
                f"started [{started_names}], exited [{exited_names}].",
                "Process id and executable name only; no command line or file data was read.",
            )
        self.changed.emit()
        return current

    def baseline_size(self) -> int:
        return len(self._baseline)

    # --- internals ---------------------------------------------------------

    def _record(
        self,
        category: EventCategory,
        severity: Severity,
        message: str,
        reason: str,
    ) -> None:
        if self._events is None:
            return
        self._events.record(
            category,
            severity,
            message,
            source="Windows activity monitor",
            reason=reason,
            action="monitoring",
        )


def _snapshot_windows_processes() -> tuple[ObservedProcess, ...]:
    """Read process ids and names with the documented Toolhelp32 API."""
    import ctypes
    from ctypes import wintypes

    class ProcessEntry32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * MAX_PATH),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ProcessEntry32W),
    ]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ProcessEntry32W),
    ]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE or not snapshot:
        raise OSError("CreateToolhelp32Snapshot failed")

    processes: list[ObservedProcess] = []
    try:
        entry = ProcessEntry32W()
        entry.dwSize = ctypes.sizeof(ProcessEntry32W)
        more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more and len(processes) < MAX_PROCESSES:
            name = str(entry.szExeFile or "").strip()
            pid = int(entry.th32ProcessID)
            if name and pid > 0:
                processes.append(ObservedProcess(pid=pid, name=name))
            more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)

    return tuple(sorted(processes, key=lambda process: (process.name.casefold(), process.pid)))
