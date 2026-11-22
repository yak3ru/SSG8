"""Tests for the simulated lockdown's control over protection modules."""

from __future__ import annotations

import pytest

from ssg8.core.app_state import AppState
from ssg8.core.models import EventCategory
from ssg8.security.protection_manager import ProtectionManager
from ssg8.services.event_log import EventLog
from ssg8.storage.protection_store import ProtectionStore


@pytest.fixture
def harness(tmp_path):
    state = AppState()
    events = EventLog()
    manager = ProtectionManager(state, events, ProtectionStore(tmp_path))
    return manager, state, events


def test_lockdown_enables_every_module(harness) -> None:
    manager, state, _events = harness
    manager.set_module_enabled("website", False)
    manager.set_module_enabled("notification", False)

    state.set_lockdown(True, "Exercise")

    assert all(manager.module_states().values())
    assert manager.lockdown_snapshot_active


def test_recovery_restores_previous_states(harness) -> None:
    manager, state, _events = harness
    manager.set_module_enabled("website", False)
    manager.set_module_enabled("notification", False)

    state.set_lockdown(True, "Exercise")
    state.set_lockdown(False, "Recovery")

    states = manager.module_states()
    assert states["website"] is False
    assert states["notification"] is False
    assert states["download"] is True
    assert states["application"] is True
    assert not manager.lockdown_snapshot_active


def test_repeated_activation_and_recovery(harness) -> None:
    manager, state, _events = harness
    manager.set_module_enabled("download", False)

    for _ in range(3):
        state.set_lockdown(True, "Cycle")
        assert all(manager.module_states().values())
        state.set_lockdown(False, "Cycle end")
        assert manager.module_states()["download"] is False
        assert manager.is_module_enabled("website")


def test_lockdown_events_are_recorded(harness) -> None:
    _manager, state, events = harness

    state.set_lockdown(True, "Event check")
    state.set_lockdown(False, "Event check end")

    lockdown_events = [
        entry for entry in events.entries() if entry.category is EventCategory.LOCKDOWN
    ]
    messages = " ".join(entry.message for entry in lockdown_events)
    assert "enabled all internal protection modules" in messages
    assert "restored" in messages


def test_lockdown_keeps_rules_and_categories(harness) -> None:
    manager, state, _events = harness
    manager.add_website_rule("blocked.test", "block")
    manager.add_application_rule("Tool", "", "block")
    state.set_notification_category_enabled("promotional", False)
    state.set_notification_control_enabled(True)

    state.set_lockdown(True, "Exercise")
    state.set_lockdown(False, "Recovery")

    assert [entry.domain for entry in state.websites()] == ["blocked.test"]
    assert [entry.name for entry in state.applications()] == ["Tool"]
    assert state.notification_categories()["promotional"] is False
    assert state.notification_control_enabled() is True


def test_evaluation_works_during_lockdown(harness) -> None:
    manager, state, _events = harness
    manager.set_module_enabled("website", False)
    manager.add_website_rule("blocked.test", "block")

    state.set_lockdown(True, "Exercise")

    assert manager.evaluate_website("https://blocked.test/").action.value == "block"

    state.set_lockdown(False, "Recovery")
    blocked = manager.evaluate_website("https://blocked.test/")
    assert blocked.metadata["policy"] == "module-disabled"
