"""Recovery Center behaviour: quick reset, full reset and emergency exit."""

from __future__ import annotations

from pathlib import Path

from ssg8.core.models import EventCategory
from ssg8.services.paranoia.states import ParanoiaState


def test_quick_reset_from_restrictive(app_context) -> None:
    paranoia = app_context.paranoia
    paranoia.record_activity("browser_open", points=45)
    assert paranoia.state() is ParanoiaState.RESTRICTIVE

    assert paranoia.quick_reset("unit test")
    assert paranoia.state() is ParanoiaState.NORMAL
    assert paranoia.score() == 0
    assert paranoia.recovery_status() == "Ready"
    assert paranoia.recovery_actions()


def test_full_reset_preserves_permanent_audit_reports(app_context) -> None:
    paranoia = app_context.paranoia
    paranoia.advance_to_maximum_paranoia()
    app_context.demo.launch_application("calculator")
    report, _message = paranoia.run_self_audit()
    assert report is not None
    audits_before = len(paranoia.audit_reports())
    assert audits_before == 1

    assert paranoia.full_demo_reset("unit full reset")

    assert paranoia.state() is ParanoiaState.NORMAL
    assert paranoia.score() == 0
    assert paranoia.transitions() == ()
    assert paranoia.activities() == ()
    assert paranoia.restriction_records() == ()
    assert len(paranoia.audit_reports()) == audits_before
    assert paranoia.audit_reports()[0].id == report.id


def test_emergency_exit_preparation_is_safe_and_idempotent(app_context) -> None:
    paranoia = app_context.paranoia
    paranoia.record_activity("browser_open", points=45)

    assert paranoia.prepare_emergency_exit("unit test") is True
    assert paranoia.prepare_emergency_exit("unit test again") is True
    assert paranoia.restrictions_released()
    assert paranoia.recovery_available() is True

    entries = [
        entry
        for entry in app_context.events.entries()
        if entry.category is EventCategory.RECOVERY
    ]
    assert any("emergency exit" in entry.message.casefold() for entry in entries)


def test_quick_reset_stops_optional_monitoring_when_started(app_context) -> None:
    monitor = app_context.monitor
    started = monitor.start()
    if not started:
        assert monitor.enabled() is False
        return

    app_context.paranoia.record_activity("browser_open", points=45)
    app_context.paranoia.quick_reset("unit test")

    assert monitor.enabled() is False


def test_recovery_never_deletes_application_or_user_files(app_context, tmp_path) -> None:
    sentinel = tmp_path / "important-user-file.txt"
    sentinel.write_text("keep me", encoding="utf-8")
    source_file = Path("src/ssg8/main.py")
    assert source_file.exists()

    app_context.demo.request_download("quarterly-report.pdf")
    app_context.paranoia.record_activity("browser_open", points=45)
    app_context.paranoia.quick_reset("unit test")
    app_context.paranoia.prepare_emergency_exit("unit test")
    app_context.demo.cleanup()

    assert sentinel.read_text(encoding="utf-8") == "keep me"
    assert source_file.exists()
    assert (Path("src") / "ssg8" / "main.py").exists()


def test_full_reset_clears_session_but_keeps_security_log(app_context) -> None:
    app_context.paranoia.record_activity("settings_open")
    before = app_context.events.count()
    assert before > 0

    app_context.paranoia.full_demo_reset("unit test")

    assert app_context.events.count() >= before
    assert any(
        "full demo reset" in entry.message.casefold()
        for entry in app_context.events.entries()
    )


def test_recovery_after_exception_in_restriction_evaluation(app_context) -> None:
    def broken(_decision):
        raise ValueError("simulated profile failure")

    app_context.protection.set_decision_escalator(broken)
    app_context.paranoia.record_activity("browser_open", points=45)
    # Protection keeps working even while the paranoia escalator is broken.
    assert app_context.protection.evaluate_website("https://example.test/").action.value == "allow"

    assert app_context.paranoia.quick_reset("recover after failure")
    assert app_context.paranoia.state() is ParanoiaState.NORMAL
    assert app_context.paranoia.score() == 0
