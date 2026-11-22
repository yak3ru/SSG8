"""Self-audit, self-threat detection and self-quarantine tests."""

from __future__ import annotations

from dataclasses import replace

from ssg8.services.paranoia.states import ParanoiaState


def _make_dirty_maximum(app_context) -> None:
    paranoia = app_context.paranoia
    paranoia.advance_to_maximum_paranoia()
    for _ in range(3):
        app_context.demo.launch_application("calculator")


def test_self_audit_requires_maximum_paranoia(app_context) -> None:
    report, message = app_context.paranoia.run_self_audit()

    assert report is None
    assert "maximum paranoia" in message.casefold()
    assert app_context.paranoia.state() is ParanoiaState.NORMAL


def test_audit_reads_actual_recorded_activity(app_context) -> None:
    _make_dirty_maximum(app_context)
    paranoia = app_context.paranoia
    expected_activities = len(paranoia.activities())
    expected_restrictions = len(paranoia.restriction_records())

    report, message = paranoia.run_self_audit()

    assert report is not None
    assert message == "Self-audit complete."
    assert report.activities_monitored == expected_activities
    assert report.restrictions_applied == expected_restrictions
    assert report.restrictions_applied >= 3
    assert report.legitimate_blocked >= 3
    assert report.has_violations is True
    assert report.compliance_result == "Failed"
    assert paranoia.state() is ParanoiaState.SELF_THREAT_DETECTED


def test_audit_identifies_excessive_restrictions_and_recovery(app_context) -> None:
    _make_dirty_maximum(app_context)
    report, _message = app_context.paranoia.run_self_audit()

    assert report is not None
    assert report.row("Legitimate activities blocked").result == "Detected"
    assert report.row("Excessive restrictions").result == "Detected"
    assert report.row("Recovery availability").result == "Available"
    assert report.row("User control restrictions").result == "None at OS level"
    assert report.row("Self-policy compliance").result == "Failed"


def test_clean_audit_does_not_invent_a_self_threat(app_context) -> None:
    app_context.paranoia.advance_to_maximum_paranoia()
    report, _message = app_context.paranoia.run_self_audit()

    assert report is not None
    assert report.has_violations is False
    assert app_context.paranoia.state() is ParanoiaState.MAXIMUM_PARANOIA
    assert not any(
        finding.key.startswith("self-threat|")
        for finding in app_context.analysis.findings()
    )


def test_self_threat_creates_finding_alert_and_incident(app_context) -> None:
    _make_dirty_maximum(app_context)
    report, _message = app_context.paranoia.run_self_audit()

    assert report is not None
    findings = [
        finding
        for finding in app_context.analysis.findings()
        if finding.key.startswith("self-threat|")
    ]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.level.value == "CRITICAL"
    assert "SELF-THREAT DETECTED" in finding.title
    assert report.finding_id == finding.id
    assert app_context.analysis.alert(finding.alert_id) is not None
    assert any(
        finding.id in incident.finding_ids
        for incident in app_context.analysis.incidents()
    )


def test_repeated_self_threat_registration_is_idempotent(app_context) -> None:
    _make_dirty_maximum(app_context)
    report, _message = app_context.paranoia.run_self_audit()
    assert report is not None

    first = len(app_context.analysis.findings())
    again = app_context.analysis.register_audit_finding(
        replace(report, id="AUD-9999")
    )
    assert again is not None
    # A new report id is a new audit record, but the exact report is not duplicated.
    app_context.analysis.register_audit_finding(report)
    assert len(app_context.analysis.findings()) == first + 1


def test_quarantine_releases_restrictions_and_is_idempotent(app_context) -> None:
    _make_dirty_maximum(app_context)
    app_context.paranoia.run_self_audit()
    paranoia = app_context.paranoia
    assert paranoia.state() is ParanoiaState.SELF_THREAT_DETECTED

    assert paranoia.begin_quarantine() is not None
    assert paranoia.state() is ParanoiaState.SELF_QUARANTINE
    assert paranoia.profile.restrictions_released
    assert paranoia.begin_quarantine() is None
    assert paranoia.state() is ParanoiaState.SELF_QUARANTINE

    assert app_context.demo.open_website("https://example.test/").action == "allow"
    assert app_context.demo.change_wallpaper("forest").action == "allow"


def test_recovery_completes_the_sequence(app_context) -> None:
    _make_dirty_maximum(app_context)
    app_context.paranoia.run_self_audit()
    app_context.paranoia.begin_quarantine()

    assert app_context.paranoia.complete_recovery() is not None
    assert app_context.paranoia.state() is ParanoiaState.RECOVERY
    assert app_context.paranoia.score() == 0
    assert app_context.paranoia.complete_recovery() is None


def test_audit_failure_fails_safe(app_context, monkeypatch) -> None:
    app_context.paranoia.advance_to_maximum_paranoia()

    def explode(_self, _report_id):
        raise RuntimeError("simulated audit failure")

    monkeypatch.setattr(
        "ssg8.services.paranoia.audit.SelfAuditService.run", explode
    )
    report, message = app_context.paranoia.run_self_audit()

    assert report is None
    assert "released" in message.casefold()
    assert app_context.paranoia.state() is ParanoiaState.NORMAL
    assert app_context.paranoia.score() == 0
