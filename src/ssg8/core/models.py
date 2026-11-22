"""Plain data models shared across the SSG8 interface.

These models describe *interface configuration* only. Nothing in this module
represents real Windows security telemetry.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """Severity of an application level event."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class EventCategory(str, Enum):
    """Category of an application level event."""

    NAVIGATION = "Navigation"
    CONFIGURATION = "Configuration"
    PREFERENCE = "Preference"
    LOCKDOWN = "Lockdown"
    APPLICATION = "Application"
    PROTECTION = "Protection"
    ANALYSIS = "Analysis"
    ALERT = "Alert"
    INCIDENT = "Incident"
    PARANOIA = "Paranoia"
    SELF_AUDIT = "Self-Audit"
    DEMO = "Demonstration"
    MONITORING = "Monitoring"
    RECOVERY = "Recovery"


@dataclass(frozen=True, slots=True)
class WebsiteEntry:
    """One website rule held by the internal protection engine."""

    domain: str
    added: datetime
    list_type: str = "block"


@dataclass(frozen=True, slots=True)
class ApplicationEntry:
    """One application rule held by the internal protection engine."""

    name: str
    path: str
    added: datetime
    policy: str = "block"


@dataclass(frozen=True, slots=True)
class NotificationTarget:
    """An application whose notifications are configured in the interface."""

    application: str
    suppress: bool
    added: datetime


@dataclass(frozen=True, slots=True)
class LockdownEvent:
    """One entry of the simulated lockdown history."""

    timestamp: datetime
    action: str
    reason: str


@dataclass(frozen=True, slots=True)
class LogEntry:
    """One application event shown in Security Logs."""

    timestamp: datetime
    category: EventCategory
    severity: Severity
    message: str
    module_id: str = ""
    action: str = ""
    target: str = ""
    source: str = ""
    reason: str = ""
    previous_state: str = ""
    new_state: str = ""
    activity: str = ""
