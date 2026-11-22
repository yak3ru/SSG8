"""In-memory demonstration state for the SSG8 interface.

Everything here is interface configuration. No Windows setting, process,
service, firewall rule or registry key is read or modified.
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QObject, Signal

from ssg8.core.models import (
    ApplicationEntry,
    LockdownEvent,
    NotificationTarget,
    WebsiteEntry,
)
from ssg8.utils.validation import normalise_domain

WEBSITE_LIST_TYPES: tuple[str, ...] = ("block", "allow")
APPLICATION_POLICIES: tuple[str, ...] = ("block", "allow")

NOTIFICATION_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("security_alerts", "Security Alerts"),
    ("system_warnings", "System Warnings"),
    ("application_updates", "Application Updates"),
    ("general", "General Notifications"),
    ("promotional", "Promotional Notifications"),
)


class AppState(QObject):
    """Holds the demonstration configuration shown by the interface."""

    websites_changed = Signal()
    applications_changed = Signal()
    notifications_changed = Signal()
    lockdown_changed = Signal(bool)
    lockdown_history_changed = Signal()

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._websites: list[WebsiteEntry] = []
        self._applications: list[ApplicationEntry] = []
        self._notification_targets: list[NotificationTarget] = []
        self._notification_control_enabled = False
        self._notification_preferences: dict[str, bool] = {
            "toast_notifications": True,
            "tray_notifications": True,
            "critical_alerts": True,
        }
        self._notification_categories: dict[str, bool] = {
            key: True for key, _label in NOTIFICATION_CATEGORIES
        }
        self._lockdown_active = False
        self._lockdown_reason = ""
        self._lockdown_started: datetime | None = None
        self._lockdown_history: list[LockdownEvent] = []

    # --- websites ----------------------------------------------------------

    def websites(self, list_type: str | None = None) -> tuple[WebsiteEntry, ...]:
        if list_type is None:
            return tuple(self._websites)
        return tuple(e for e in self._websites if e.list_type == list_type)

    def has_website(self, domain: str, list_type: str | None = "block") -> bool:
        target = normalise_domain(domain)
        return any(
            entry.domain.casefold() == target.casefold()
            and (list_type is None or entry.list_type == list_type)
            for entry in self._websites
        )

    def add_website(self, domain: str, list_type: str = "block") -> WebsiteEntry | None:
        """Add a website rule. Returns ``None`` for duplicates."""
        if list_type not in WEBSITE_LIST_TYPES:
            raise ValueError(f"Unknown website list type: {list_type}")
        normalised = normalise_domain(domain)
        if not normalised or self.has_website(normalised, list_type):
            return None
        entry = WebsiteEntry(domain=normalised, added=datetime.now(), list_type=list_type)
        self._websites.append(entry)
        self.websites_changed.emit()
        return entry

    def remove_website(self, domain: str, list_type: str | None = None) -> bool:
        target = normalise_domain(domain)
        remaining = [
            e
            for e in self._websites
            if not (
                e.domain.casefold() == target.casefold()
                and (list_type is None or e.list_type == list_type)
            )
        ]
        if len(remaining) == len(self._websites):
            return False
        self._websites = remaining
        self.websites_changed.emit()
        return True

    def restore_websites(self, entries: list[WebsiteEntry]) -> None:
        """Replace the website rules with previously persisted entries."""
        self._websites = list(entries)
        self.websites_changed.emit()

    # --- applications ------------------------------------------------------

    def applications(self, policy: str | None = None) -> tuple[ApplicationEntry, ...]:
        if policy is None:
            return tuple(self._applications)
        return tuple(e for e in self._applications if e.policy == policy)

    def add_application(
        self, name: str, path: str, policy: str = "block"
    ) -> ApplicationEntry:
        if policy not in APPLICATION_POLICIES:
            raise ValueError(f"Unknown application policy: {policy}")
        entry = ApplicationEntry(
            name=name.strip(), path=path.strip(), added=datetime.now(), policy=policy
        )
        self._applications.append(entry)
        self.applications_changed.emit()
        return entry

    def remove_application(
        self, path: str, policy: str | None = None, name: str | None = None
    ) -> bool:
        remaining = [
            e
            for e in self._applications
            if not (
                e.path == path
                and (policy is None or e.policy == policy)
                and (name is None or e.name == name)
            )
        ]
        if len(remaining) == len(self._applications):
            return False
        self._applications = remaining
        self.applications_changed.emit()
        return True

    def restore_applications(self, entries: list[ApplicationEntry]) -> None:
        """Replace the application rules with previously persisted entries."""
        self._applications = list(entries)
        self.applications_changed.emit()

    # --- notification control ---------------------------------------------

    def notification_control_enabled(self) -> bool:
        return self._notification_control_enabled

    def set_notification_control_enabled(self, enabled: bool) -> None:
        if enabled == self._notification_control_enabled:
            return
        self._notification_control_enabled = enabled
        self.notifications_changed.emit()

    def notification_targets(self) -> tuple[NotificationTarget, ...]:
        return tuple(self._notification_targets)

    def add_notification_target(self, application: str) -> NotificationTarget | None:
        name = application.strip()
        if not name:
            return None
        if any(t.application.casefold() == name.casefold() for t in self._notification_targets):
            return None
        target = NotificationTarget(
            application=name,
            suppress=self._notification_control_enabled,
            added=datetime.now(),
        )
        self._notification_targets.append(target)
        self.notifications_changed.emit()
        return target

    def remove_notification_target(self, application: str) -> bool:
        remaining = [
            t for t in self._notification_targets if t.application.casefold() != application.casefold()
        ]
        if len(remaining) == len(self._notification_targets):
            return False
        self._notification_targets = remaining
        self.notifications_changed.emit()
        return True

    def set_notification_suppressed(self, application: str, suppress: bool) -> None:
        updated: list[NotificationTarget] = []
        changed = False
        for target in self._notification_targets:
            if target.application.casefold() == application.casefold():
                if target.suppress != suppress:
                    changed = True
                updated.append(
                    NotificationTarget(
                        application=target.application,
                        suppress=suppress,
                        added=target.added,
                    )
                )
            else:
                updated.append(target)
        if changed:
            self._notification_targets = updated
            self.notifications_changed.emit()

    def notification_preferences(self) -> dict[str, bool]:
        return dict(self._notification_preferences)

    def set_notification_preference(self, key: str, enabled: bool) -> None:
        if key in self._notification_preferences and self._notification_preferences[key] != enabled:
            self._notification_preferences[key] = enabled
            self.notifications_changed.emit()

    def notification_categories(self) -> dict[str, bool]:
        return dict(self._notification_categories)

    def set_notification_category_enabled(self, key: str, enabled: bool) -> None:
        if key in self._notification_categories and self._notification_categories[key] != enabled:
            self._notification_categories[key] = enabled
            self.notifications_changed.emit()

    # --- simulated lockdown ------------------------------------------------

    def lockdown_active(self) -> bool:
        return self._lockdown_active

    def lockdown_reason(self) -> str:
        return self._lockdown_reason

    def set_lockdown(self, active: bool, reason: str = "") -> LockdownEvent | None:
        """Toggle the *simulated* lockdown state.

        This only changes an in-application flag. It never affects Windows.
        """
        if active == self._lockdown_active:
            return None

        now = datetime.now()
        if active:
            self._lockdown_active = True
            self._lockdown_reason = reason.strip() or "No reason provided"
            self._lockdown_started = now
            event = LockdownEvent(now, "Simulated lockdown started", self._lockdown_reason)
        else:
            duration = ""
            if self._lockdown_started is not None:
                seconds = max(0, int((now - self._lockdown_started).total_seconds()))
                duration = f" (after {seconds}s)"
            reason = reason.strip() or self._lockdown_reason or "No reason provided"
            self._lockdown_active = False
            self._lockdown_started = None
            self._lockdown_reason = ""
            event = LockdownEvent(now, f"Simulated recovery{duration}", reason)

        self._lockdown_history.append(event)
        self.lockdown_changed.emit(self._lockdown_active)
        self.lockdown_history_changed.emit()
        return event

    def lockdown_history(self) -> tuple[LockdownEvent, ...]:
        return tuple(reversed(self._lockdown_history))
