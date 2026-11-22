"""Tests for the unified protection manager."""

from __future__ import annotations

import pytest

from ssg8.core.app_state import AppState
from ssg8.core.models import EventCategory, Severity
from ssg8.security.decisions import ProtectionAction
from ssg8.security.protection_manager import ProtectionManager
from ssg8.services.event_log import EventLog
from ssg8.storage.protection_store import ProtectionStore


@pytest.fixture
def harness(tmp_path):
    state = AppState()
    events = EventLog()
    store = ProtectionStore(tmp_path / "SSG8")
    manager = ProtectionManager(state, events, store)
    return manager, state, events, store


def protection_events(events: EventLog):
    return [entry for entry in events.entries() if entry.category is EventCategory.PROTECTION]


def test_module_routing(harness, tmp_path) -> None:
    manager, state, _events, _store = harness

    state.add_application("Calculator", "", "block")
    sample = tmp_path / "note.txt"
    sample.write_text("data", encoding="utf-8")

    assert manager.evaluate_website("https://example.com/").module == "Website Protection"
    assert manager.evaluate_download(str(sample)).module == "Download Protection"
    assert manager.evaluate_application("Calculator").module == "Application Control"
    assert (
        manager.evaluate_notification("general", "hello").module
        == "Notification Control"
    )


def test_every_evaluation_is_logged(harness) -> None:
    manager, _state, events, _store = harness
    before = len(protection_events(events))

    manager.evaluate_website("https://example.com/")

    recorded = protection_events(events)
    assert len(recorded) == before + 1
    assert "Website Protection" in recorded[0].message
    assert recorded[0].severity is Severity.INFO


def test_blocked_decision_uses_high_severity(harness) -> None:
    manager, _state, events, _store = harness
    manager.add_website_rule("blocked.test", "block")

    manager.evaluate_website("https://blocked.test/")

    entry = protection_events(events)[0]
    assert entry.severity is Severity.HIGH
    assert "BLOCKED" in entry.message


def test_duplicate_website_rule_is_rejected(harness) -> None:
    manager, _state, _events, _store = harness
    assert manager.add_website_rule("example.com", "block")[0]
    ok, message = manager.add_website_rule("EXAMPLE.com", "block")
    assert not ok
    assert "already" in message


def test_same_domain_can_be_blocked_and_allowed(harness) -> None:
    manager, state, _events, _store = harness
    assert manager.add_website_rule("example.com", "block")[0]
    assert manager.add_website_rule("example.com", "allow")[0]
    assert len(state.websites()) == 2


def test_website_rules_are_persisted_and_reloaded(harness, tmp_path) -> None:
    manager, _state, _events, store = harness
    manager.add_website_rule("persisted.example", "block")

    assert store.website_path.exists()

    reloaded_state = AppState()
    reloaded = ProtectionManager(reloaded_state, EventLog(), store)

    assert [entry.domain for entry in reloaded_state.websites()] == [
        "persisted.example"
    ]
    assert reloaded.evaluate_website("https://persisted.example/").action is (
        ProtectionAction.BLOCK
    )


def test_application_duplicate_is_rejected(harness) -> None:
    manager, _state, _events, _store = harness
    assert manager.add_application_rule("Tool", r"C:\Apps\Tool.exe", "block")[0]
    ok, message = manager.add_application_rule(
        "Tool", r"c:\apps\tool.exe", "block"
    )
    assert not ok
    assert "already" in message


def test_application_rules_are_persisted(harness) -> None:
    manager, _state, _events, store = harness
    manager.add_application_rule("Calculator", r"C:\Windows\calc.exe", "block")

    assert store.application_path.exists()
    reloaded_state = AppState()
    ProtectionManager(reloaded_state, EventLog(), store)

    assert reloaded_state.applications()[0].name == "Calculator"
    assert reloaded_state.applications()[0].policy == "block"


def test_rule_removal_is_logged(harness) -> None:
    manager, state, events, _store = harness
    manager.add_website_rule("remove.example", "block")
    entry = state.websites()[0]

    assert manager.remove_website_rule(entry)
    assert "removed" in events.entries()[0].message.lower()
    assert events.entries()[0].category is EventCategory.CONFIGURATION
    assert state.websites() == ()


def test_disabled_module_blocks_without_evaluating(harness) -> None:
    manager, _state, _events, _store = harness
    manager.set_module_enabled("website", False)

    decision = manager.evaluate_website("https://example.com/")

    assert decision.action is ProtectionAction.BLOCK
    assert "module is disabled" in decision.reason
    assert decision.metadata["policy"] == "module-disabled"


def test_module_failure_is_isolated(harness) -> None:
    manager, state, events, _store = harness

    def boom(*_args, **_kwargs):
        raise RuntimeError("engine exploded")

    manager._engines["website"].evaluate = boom  # type: ignore[method-assign]

    broken = manager.evaluate_website("https://example.com/")
    healthy = manager.evaluate_application("Anything")

    assert broken.action is ProtectionAction.REVIEW
    assert broken.metadata["policy"] == "module-error"
    assert "could not evaluate" in broken.reason
    assert healthy.action is ProtectionAction.REVIEW
    assert any("exploded" in entry.message for entry in protection_events(events))
    assert manager.is_module_enabled("application")


def test_duplicate_download_hash_is_reviewed(harness, tmp_path) -> None:
    manager, _state, _events, _store = harness
    sample = tmp_path / "duplicate.txt"
    sample.write_text("same bytes", encoding="utf-8")

    first = manager.evaluate_download(str(sample))
    second = manager.evaluate_download(str(sample))

    assert first.action is ProtectionAction.ALLOW
    assert second.action is ProtectionAction.REVIEW
    assert "duplicate" in second.reason.lower()


def test_statistics_track_decisions(harness) -> None:
    manager, _state, _events, _store = harness
    manager.add_website_rule("blocked.test", "block")

    manager.evaluate_website("https://blocked.test/")
    manager.evaluate_website("https://allowed.test/")
    manager.evaluate_website("not a url")

    stats = manager.stats()
    assert stats["evaluations"] == 3
    assert stats["blocked"] == 1
    assert stats["allowed"] == 1
    assert stats["review"] == 1


def test_decision_history_filters(harness) -> None:
    manager, state, _events, _store = harness
    state.set_notification_control_enabled(True)
    manager.evaluate_website("https://example.com/")
    manager.evaluate_notification("general", "hello")

    assert len(manager.decisions()) == 2
    assert len(manager.decisions("website")) == 1
    assert len(manager.decisions(actions=[ProtectionAction.BLOCK])) == 0
    assert manager.decisions(limit=1)[0].module == "Notification Control"


def test_settings_update_is_validated_and_persisted(harness) -> None:
    manager, _state, _events, store = harness

    ok, _message = manager.update_settings(max_file_size_mb=64)
    assert ok
    assert manager.settings().max_file_size_mb == 64
    assert store.settings_path.exists()

    ok, message = manager.update_settings(max_file_size_mb=0)
    assert not ok
    assert "between" in message
    assert manager.settings().max_file_size_mb == 64


def test_invalid_extension_setting_is_rejected(harness) -> None:
    manager, _state, _events, _store = harness
    original = manager.settings().blocked_extensions

    ok, message = manager.update_prohibited_extensions(".exe, not valid!")

    assert not ok
    assert "not a valid extension" in message
    assert manager.settings().blocked_extensions == original


def test_settings_reload(harness) -> None:
    manager, _state, _events, store = harness
    manager.update_prohibited_extensions(".exe, .ps1")
    manager.update_settings(subdomain_matching="exact")

    reloaded = ProtectionManager(AppState(), EventLog(), store)

    assert reloaded.settings().subdomain_matching == "exact"
    assert reloaded.settings().blocked_extensions == (".exe", ".ps1")


def test_notification_category_wrapper(harness) -> None:
    manager, state, events, _store = harness
    assert manager.set_notification_category("promotional", False)
    assert state.notification_categories()["promotional"] is False

    decision = manager.evaluate_notification("promotional", "Sale")
    assert decision.action is ProtectionAction.BLOCK
    assert any(entry.category is EventCategory.PREFERENCE for entry in events.entries())


def test_removing_one_name_only_rule_keeps_siblings(harness) -> None:
    manager, state, _events, _store = harness
    manager.add_application_rule("Calculator", "", "block")
    manager.add_application_rule("Notepad", "", "block")

    target = next(entry for entry in state.applications() if entry.name == "Calculator")
    assert manager.remove_application_rule(target)

    assert [entry.name for entry in state.applications()] == ["Notepad"]


def test_unknown_module_id_is_ignored(harness) -> None:
    manager, _state, _events, _store = harness
    assert not manager.set_module_enabled("nonexistent", False)
    assert not manager.is_module_enabled("nonexistent")
