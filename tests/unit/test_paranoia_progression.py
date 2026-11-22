"""Paranoia score and state-machine tests."""

from __future__ import annotations

import json

from ssg8.core.models import EventCategory, Severity
from ssg8.services.paranoia.manager import ParanoiaManager
from ssg8.services.paranoia.models import ParanoiaSettings
from ssg8.services.paranoia.states import (
    ParanoiaState,
    state_for_score,
)
from ssg8.storage.paranoia_store import ParanoiaStore


def _manager(app_context) -> ParanoiaManager:
    return app_context.paranoia


def _transitions(paranoia: ParanoiaManager) -> list[tuple[ParanoiaState, ParanoiaState]]:
    # ``transitions()`` is newest first; these tests assert chronological order.
    return [
        (item.previous_state, item.new_state)
        for item in reversed(paranoia.transitions())
    ]


def test_initial_score_and_state_are_clean(app_context) -> None:
    paranoia = _manager(app_context)

    assert paranoia.score() == 0
    assert paranoia.state() is ParanoiaState.NORMAL
    assert paranoia.profile.restriction_level == 0
    assert paranoia.transitions() == ()
    assert paranoia.activities() == ()


def test_score_increases_with_explanation_and_clamps_at_100(app_context) -> None:
    paranoia = _manager(app_context)

    event = paranoia.record_activity("browser_open", target="https://demo.test")
    assert paranoia.score() == 3
    assert event is not None
    assert event.delta == 3
    assert event.activity == "browser_open"
    assert "controlled browser" in event.reason.casefold()

    paranoia.record_activity("unfamiliar_website", points=100)
    assert paranoia.score() == 100
    paranoia.record_activity("browser_open")
    assert paranoia.score() == 100


def test_thresholds_transition_in_order_without_skipping(app_context) -> None:
    paranoia = _manager(app_context)

    paranoia.record_activity("browser_open", points=20)
    assert paranoia.state() is ParanoiaState.SUSPICIOUS

    paranoia.record_activity("download_request", points=20)
    assert paranoia.state() is ParanoiaState.RESTRICTIVE

    paranoia.record_activity("launch_calculator", points=30)
    assert paranoia.state() is ParanoiaState.MAXIMUM_PARANOIA

    assert _transitions(paranoia) == [
        (ParanoiaState.NORMAL, ParanoiaState.SUSPICIOUS),
        (ParanoiaState.SUSPICIOUS, ParanoiaState.RESTRICTIVE),
        (ParanoiaState.RESTRICTIVE, ParanoiaState.MAXIMUM_PARANOIA),
    ]


def test_large_jump_cascades_through_every_state(app_context) -> None:
    paranoia = _manager(app_context)

    paranoia.record_activity("browser_open", points=100)

    assert paranoia.score() == 100
    assert paranoia.state() is ParanoiaState.MAXIMUM_PARANOIA
    assert len(paranoia.transitions()) == 3
    assert _transitions(paranoia)[0][0] is ParanoiaState.NORMAL
    assert _transitions(paranoia)[-1][1] is ParanoiaState.MAXIMUM_PARANOIA


def test_invalid_and_duplicate_transitions_are_rejected(app_context) -> None:
    paranoia = _manager(app_context)

    assert paranoia.transition_to(ParanoiaState.RESTRICTIVE, "skip ahead") is None
    assert paranoia.state() is ParanoiaState.NORMAL

    paranoia.record_activity("browser_open", points=20)
    count = len(paranoia.transitions())
    assert paranoia.transition_to(ParanoiaState.SUSPICIOUS, "duplicate") is None
    assert len(paranoia.transitions()) == count

    rejected = [
        entry
        for entry in app_context.events.entries()
        if entry.category is EventCategory.PARANOIA
        and entry.action in ("transition-rejected", "paranoia")
        and "rejected" in entry.message.casefold()
    ]
    assert rejected


def test_reset_returns_to_normal_and_is_idempotent(app_context) -> None:
    paranoia = _manager(app_context)
    paranoia.record_activity("browser_open", points=55)

    assert paranoia.quick_reset("test reset") is True
    assert paranoia.score() == 0
    assert paranoia.state() is ParanoiaState.NORMAL
    assert paranoia.quick_reset("again") is False
    assert paranoia.score() == 0


def test_repeated_activity_uses_deterministic_reduced_weight(app_context) -> None:
    paranoia = _manager(app_context)

    paranoia.record_activity("browser_open")
    paranoia.record_activity("browser_open")
    paranoia.record_activity("browser_open")

    # 3 + 3 + max(1, 3 // 3)
    assert paranoia.score() == 7


def test_demo_mode_and_configurable_points(app_context) -> None:
    paranoia = _manager(app_context)

    ok, message = paranoia.update_settings(
        point_overrides={"browser_open": 7}, demo_acceleration=2
    )
    assert ok, message
    assert paranoia.points_for("browser_open") == 7

    paranoia.set_demo_mode(True)
    assert paranoia.points_for("browser_open") == 14
    paranoia.record_activity("browser_open")
    assert paranoia.score() == 14

    bad, _ = paranoia.update_settings(point_overrides={"not-an-activity": 5})
    assert bad is False


def test_transition_history_is_persisted(app_context, tmp_path) -> None:
    paranoia = _manager(app_context)
    paranoia.record_activity("browser_open", points=20)

    second = ParanoiaManager(
        app_context.events,
        store=ParanoiaStore(tmp_path / "data"),
        settings=ParanoiaSettings(),
    )

    assert second.score() == 20
    assert second.state() is ParanoiaState.SUSPICIOUS
    assert len(second.transitions()) == 1


def test_interrupted_terminal_state_is_recovered_at_startup(tmp_path) -> None:
    store = ParanoiaStore(tmp_path)
    assert store.save(100, ParanoiaState.SELF_AUDIT, (), ())

    from ssg8.services.event_log import EventLog

    events = EventLog()
    paranoia = ParanoiaManager(events, store=store)

    assert paranoia.score() == 0
    assert paranoia.state() is ParanoiaState.NORMAL
    assert any(
        "Interrupted demonstration recovered" in entry.message
        for entry in events.entries()
    )


def test_corrupted_persistence_falls_back_safely(tmp_path) -> None:
    store = ParanoiaStore(tmp_path)
    store.state_path.parent.mkdir(parents=True, exist_ok=True)
    store.state_path.write_text("{not valid json", encoding="utf-8")

    from ssg8.services.event_log import EventLog

    events = EventLog()
    paranoia = ParanoiaManager(events, store=store)

    assert paranoia.score() == 0
    assert paranoia.state() is ParanoiaState.NORMAL
    assert any(
        "persistence warning" in entry.message.casefold()
        for entry in events.entries()
    )


def test_score_to_state_boundaries() -> None:
    assert state_for_score(0) is ParanoiaState.NORMAL
    assert state_for_score(19) is ParanoiaState.NORMAL
    assert state_for_score(20) is ParanoiaState.SUSPICIOUS
    assert state_for_score(39) is ParanoiaState.SUSPICIOUS
    assert state_for_score(40) is ParanoiaState.RESTRICTIVE
    assert state_for_score(69) is ParanoiaState.RESTRICTIVE
    assert state_for_score(70) is ParanoiaState.MAXIMUM_PARANOIA
    assert state_for_score(100) is ParanoiaState.MAXIMUM_PARANOIA


def test_maximum_notice_is_recorded_once(app_context) -> None:
    paranoia = _manager(app_context)
    paranoia.advance_to_maximum_paranoia()

    notices = [
        entry
        for entry in app_context.events.entries()
        if "reached maximum paranoia" in entry.message.casefold()
    ]
    assert len(notices) == 1
    assert notices[0].severity is Severity.CRITICAL

    paranoia.advance_to_maximum_paranoia()
    notices = [
        entry
        for entry in app_context.events.entries()
        if "reached maximum paranoia" in entry.message.casefold()
    ]
    assert len(notices) == 1


def test_persistence_file_is_valid_json(app_context, tmp_path) -> None:
    paranoia = _manager(app_context)
    paranoia.record_activity("settings_open")

    path = tmp_path / "data" / "paranoia_state.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["score"] == 4
    assert payload["state"] == "NORMAL"
