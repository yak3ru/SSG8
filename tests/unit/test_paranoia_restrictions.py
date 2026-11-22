"""Progressive restriction tests across all four states."""

from __future__ import annotations

from ssg8.core.models import EventCategory
from ssg8.security.decisions import ProtectionAction
from ssg8.services.paranoia.states import ParanoiaState


def _to_suspicious(paranoia) -> None:
    paranoia.record_activity("browser_open", points=20)


def _to_restrictive(paranoia) -> None:
    paranoia.record_activity("browser_open", points=40)


def _to_maximum(paranoia) -> None:
    paranoia.advance_to_maximum_paranoia()


def test_normal_state_permits_all_controlled_activities(app_context) -> None:
    demo = app_context.demo

    website = demo.open_website("https://example.test/")
    assert website.action == "allow"

    download = demo.request_download("quarterly-report.pdf")
    assert download.action == "allow"

    launcher = demo.launch_application("calculator")
    assert launcher.action == "allow"
    assert launcher.simulated

    wallpaper = demo.change_wallpaper("ocean")
    assert wallpaper.action == "allow"

    assert app_context.paranoia.restriction_records() == ()
    assert app_context.paranoia.score() == 20


def test_suspicious_state_flags_unfamiliar_websites_and_downloads(app_context) -> None:
    _to_suspicious(app_context.paranoia)

    website = app_context.demo.open_website("https://unknown-demo.test/")
    assert website.action == "review"
    assert "unfamiliar" in website.message.casefold()

    download = app_context.demo.request_download("quarterly-report.pdf")
    assert download.action == "review"
    assert "scrutiny" in download.message.casefold()

    assert app_context.paranoia.state() is ParanoiaState.SUSPICIOUS


def test_restrictive_state_blocks_unfamiliar_websites_and_launches(app_context) -> None:
    _to_restrictive(app_context.paranoia)

    website = app_context.demo.open_website("https://unknown-demo.test/")
    assert website.action == "block"

    launcher = app_context.demo.launch_application("calculator")
    assert launcher.action == "block"
    assert "unauthorized mathematical" in launcher.warning.casefold()

    wallpaper = app_context.demo.change_wallpaper("ember")
    assert wallpaper.action == "block"
    assert "windows wallpaper was never touched" in wallpaper.message.casefold()

    settings = app_context.demo.open_settings()
    assert settings.action == "block"

    assert app_context.paranoia.blocked_count() >= 3
    assert app_context.paranoia.state() is ParanoiaState.RESTRICTIVE


def test_restrictive_state_suppresses_demonstration_notifications(app_context) -> None:
    app_context.state.set_notification_control_enabled(True)
    app_context.state.set_notification_category_enabled("general", True)
    _to_restrictive(app_context.paranoia)

    result = app_context.demo.send_notification("general", "Hello")

    assert result.action == "block"
    assert "suppressed" in result.message.casefold()


def test_maximum_state_blocks_allowlisted_websites_and_every_launcher(app_context) -> None:
    app_context.state.add_website("trusted-demo.test", "allow")
    assert (
        app_context.protection.evaluate_website("https://trusted-demo.test/").action
        is ProtectionAction.ALLOW
    )

    _to_maximum(app_context.paranoia)

    blocked = app_context.protection.evaluate_website("https://trusted-demo.test/")
    assert blocked.action is ProtectionAction.BLOCK
    assert blocked.metadata["paranoia_state"] == ParanoiaState.MAXIMUM_PARANOIA.value

    for app_key in ("calculator", "notepad", "paint"):
        result = app_context.demo.launch_application(app_key)
        assert result.action == "block", app_key

    assert app_context.demo.request_download("team-photo.jpg").action == "block"
    assert app_context.demo.change_wallpaper("forest").action == "block"
    assert app_context.demo.open_settings().action == "block"


def test_restriction_records_are_logged(app_context) -> None:
    _to_maximum(app_context.paranoia)
    app_context.demo.open_website("https://example.test/")

    records = app_context.paranoia.restriction_records()
    assert records
    assert any(record.module == "website" for record in records)

    paranoia_entries = [
        entry
        for entry in app_context.events.entries()
        if entry.category is EventCategory.PARANOIA
    ]
    assert any("restriction applied" in entry.message.casefold() for entry in paranoia_entries)


def test_quick_reset_releases_every_restriction(app_context) -> None:
    _to_maximum(app_context.paranoia)
    assert app_context.demo.change_wallpaper("ocean").action == "block"

    assert app_context.paranoia.quick_reset("restriction test")

    assert app_context.paranoia.state() is ParanoiaState.NORMAL
    assert app_context.demo.open_website("https://example.test/").action == "allow"
    assert app_context.demo.change_wallpaper("ocean").action == "allow"
    assert app_context.demo.launch_application("notepad").action == "allow"
    assert app_context.paranoia.profile.restriction_level == 0


def test_escalator_failure_keeps_the_original_decision(app_context) -> None:
    def broken(_decision):
        raise RuntimeError("simulated escalation failure")

    app_context.protection.set_decision_escalator(broken)
    decision = app_context.protection.evaluate_website("https://example.test/")

    assert decision.action is ProtectionAction.ALLOW
    assert any(
        "failed safely" in entry.message.casefold()
        for entry in app_context.events.entries()
    )


def test_repeated_blocked_launch_creates_finding_at_maximum(app_context) -> None:
    _to_maximum(app_context.paranoia)

    for _ in range(3):
        result = app_context.demo.launch_application("calculator")
        assert result.action == "block"

    findings = [
        finding
        for finding in app_context.analysis.findings()
        if finding.key == "paranoia-blocked|launch_calculator"
    ]
    assert len(findings) == 1
    assert findings[0].score >= 70
    assert "mathematical" in findings[0].title.casefold()
