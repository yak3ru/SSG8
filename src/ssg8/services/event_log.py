"""Application event log for SSG8.

The log records events produced by the SSG8 interface itself, such as page
navigation, protection decisions, threat-analysis findings, generated alerts
and incident status changes. It never reads Windows event logs and never
reports operating system security telemetry.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime

from PySide6.QtCore import QObject, Signal

from ssg8.core.models import EventCategory, LogEntry, Severity


class EventLog(QObject):
    """An in-memory, bounded collection of application events."""

    changed = Signal()

    def __init__(self, limit: int = 500, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._entries: deque[LogEntry] = deque(maxlen=limit)

    def record(
        self,
        category: EventCategory,
        severity: Severity,
        message: str,
        *,
        module_id: str = "",
        action: str = "",
        target: str = "",
        source: str = "",
        reason: str = "",
        previous_state: str = "",
        new_state: str = "",
        activity: str = "",
    ) -> LogEntry:
        entry = LogEntry(
            timestamp=datetime.now(),
            category=category,
            severity=severity,
            message=message,
            module_id=module_id,
            action=action,
            target=target,
            source=source,
            reason=reason,
            previous_state=previous_state,
            new_state=new_state,
            activity=activity,
        )
        self._entries.append(entry)
        self.changed.emit()
        return entry

    def entries(self) -> tuple[LogEntry, ...]:
        """Return entries newest first."""
        return tuple(reversed(self._entries))

    def count(self) -> int:
        return len(self._entries)

    def clear(self) -> None:
        if not self._entries:
            return
        self._entries.clear()
        self.changed.emit()

    def filtered(
        self,
        search: str = "",
        severity: Severity | None = None,
        category: EventCategory | None = None,
        *,
        module_id: str | None = None,
        action: str | None = None,
        since: datetime | None = None,
    ) -> tuple[LogEntry, ...]:
        text = search.strip().casefold()
        results = []
        for entry in self.entries():
            if severity is not None and entry.severity is not severity:
                continue
            if category is not None and entry.category is not category:
                continue
            if module_id is not None and entry.module_id != module_id:
                continue
            if action is not None and entry.action != action:
                continue
            if since is not None and entry.timestamp < since:
                continue
            if (
                text
                and text not in entry.message.casefold()
                and text not in entry.category.value.casefold()
                and text not in entry.target.casefold()
            ):
                continue
            results.append(entry)
        return tuple(results)
