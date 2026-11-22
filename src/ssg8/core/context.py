"""Shared application context handed to every page.

Passing a single context object keeps pages free of global state and avoids
circular imports between the window, the pages and the services.
"""

from __future__ import annotations

from dataclasses import dataclass

from pathlib import Path

from ssg8.core.app_state import AppState
from ssg8.security.analysis.service import AnalysisService
from ssg8.security.protection_manager import ProtectionManager
from ssg8.services.event_log import EventLog
from ssg8.services.paranoia.demo import ControlledEnvironment
from ssg8.services.paranoia.manager import ParanoiaManager
from ssg8.services.paranoia.monitor import WindowsActivityMonitor
from ssg8.storage.analysis_store import AnalysisStore
from ssg8.storage.paranoia_store import ParanoiaStore
from ssg8.storage.preferences import Preferences
from ssg8.storage.protection_store import ProtectionStore


@dataclass(frozen=True, slots=True)
class AppContext:
    """The state, event log, preferences, protection engine and analysis."""

    state: AppState
    events: EventLog
    preferences: Preferences
    protection: ProtectionManager
    analysis: AnalysisService
    monitor: WindowsActivityMonitor
    paranoia: ParanoiaManager
    demo: ControlledEnvironment


def build_context(
    preferences: Preferences | None = None,
    store: ProtectionStore | None = None,
    analysis_store: AnalysisStore | None = None,
    paranoia_store: ParanoiaStore | None = None,
    demo_root: Path | None = None,
) -> AppContext:
    """Create a fresh context for a running application instance."""
    state = AppState()
    events = EventLog()
    protection_store = store or ProtectionStore()
    protection = ProtectionManager(state, events, protection_store)
    analysis = AnalysisService(
        protection,
        events,
        analysis_store or AnalysisStore(protection_store.root),
    )
    monitor = WindowsActivityMonitor(events)
    paranoia = ParanoiaManager(
        events,
        protection,
        analysis,
        paranoia_store or ParanoiaStore(protection_store.root),
        monitor=monitor,
    )
    demo = ControlledEnvironment(
        protection,
        paranoia,
        events,
        demo_root=demo_root,
    )
    return AppContext(
        state=state,
        events=events,
        preferences=preferences or Preferences(),
        protection=protection,
        analysis=analysis,
        monitor=monitor,
        paranoia=paranoia,
        demo=demo,
    )
