"""Tests for alert lifecycle, incident grouping and persistence."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime

import pytest

from ssg8.core.app_state import AppState
from ssg8.core.models import EventCategory
from ssg8.security.analysis.alert_manager import SecurityAlertManager
from ssg8.security.analysis.incident_manager import IncidentManager
from ssg8.security.analysis.models import (
    AlertStatus,
    IncidentStatus,
    RiskLevel,
    ThreatFinding,
)
from ssg8.security.analysis.service import AnalysisService
from ssg8.security.protection_manager import ProtectionManager
from ssg8.services.event_log import EventLog
from ssg8.storage.analysis_store import AnalysisStore
from ssg8.storage.protection_store import ProtectionStore


@pytest.fixture
def pipeline(tmp_path):
    events = EventLog()
    protection = ProtectionManager(
        AppState(), events, ProtectionStore(tmp_path / "data")
    )
    analysis = AnalysisService(
        protection, events, AnalysisStore(tmp_path / "data")
    )
    return protection, analysis, events, tmp_path / "data"


def trigger_website(protection, count: int = 3) -> None:
    protection.add_website_rule("bad.test", "block")
    for _ in range(count):
        protection.evaluate_website("https://bad.test/login")


def make_finding(
    finding_id: str,
    *,
    target: str = "bad.test",
    module_ids: tuple[str, ...] = ("website",),
    score: int = 45,
    level: RiskLevel = RiskLevel.MEDIUM,
) -> ThreatFinding:
    now = datetime.now()
    return ThreatFinding(
        id=finding_id,
        key=f"test|{finding_id}",
        title="Repeated website policy violations",
        description="Internal policy pattern.",
        pattern="repeated_block",
        module_ids=module_ids,
        target=target,
        score=score,
        level=level,
        factors=(),
        created_at=now,
        last_seen=now,
        event_count=3,
    )


def test_pipeline_creates_finding_alert_and_incident(pipeline) -> None:
    protection, analysis, _events, _root = pipeline
    trigger_website(protection)

    findings = analysis.findings()
    alerts = analysis.alerts()
    incidents = analysis.incidents()

    assert len(findings) == 1
    assert findings[0].id == "FND-0001"
    assert findings[0].alert_id == "ALR-0001"
    assert len(alerts) == 1
    assert alerts[0].status is AlertStatus.NEW
    assert alerts[0].finding_id == findings[0].id
    assert len(incidents) == 1
    assert incidents[0].status is IncidentStatus.OPEN
    assert incidents[0].finding_ids == ("FND-0001",)
    assert incidents[0].alert_ids == ("ALR-0001",)


def test_analysis_activity_is_logged(pipeline) -> None:
    protection, analysis, events, _root = pipeline
    trigger_website(protection)

    categories = {entry.category for entry in events.entries()}
    assert EventCategory.ANALYSIS in categories
    assert EventCategory.ALERT in categories
    assert EventCategory.INCIDENT in categories

    module_events = events.filtered(module_id="website", action="block")
    assert module_events
    analysis_events = events.filtered(category=EventCategory.ANALYSIS)
    assert analysis_events and "FND-" in analysis_events[0].message


def test_alert_duplicate_prevention(pipeline) -> None:
    protection, analysis, _events, _root = pipeline
    trigger_website(protection)
    finding = analysis.findings()[0]
    existing = analysis.alerts()[0]

    duplicate, created = analysis.alert_manager.create_for_finding(finding)
    assert created is False
    assert duplicate is not None
    assert duplicate.id == existing.id
    assert len(analysis.alerts()) == 1


def test_alert_acknowledge_resolve_and_filters(pipeline) -> None:
    protection, analysis, _events, _root = pipeline
    trigger_website(protection)
    alert = analysis.alerts()[0]

    assert analysis.acknowledge_alert(alert.id)
    assert analysis.alert(alert.id).status is AlertStatus.ACKNOWLEDGED
    assert analysis.alerts(status=AlertStatus.ACKNOWLEDGED)
    assert not analysis.alerts(status=AlertStatus.NEW)

    assert analysis.resolve_alert(alert.id)
    assert analysis.alert(alert.id).status is AlertStatus.RESOLVED
    assert not analysis.dismiss_alert(alert.id)
    assert analysis.alerts(level=RiskLevel.MEDIUM)
    assert analysis.alerts(search="repeated")
    assert analysis.alerts(search="no-such-alert") == ()


def test_alert_dismissal(pipeline) -> None:
    protection, analysis, _events, _root = pipeline
    trigger_website(protection)
    alert = analysis.alerts()[0]

    assert analysis.dismiss_alert(alert.id)
    assert analysis.alert(alert.id).status is AlertStatus.DISMISSED
    assert not analysis.acknowledge_alert(alert.id)


def test_alert_persistence(pipeline) -> None:
    protection, analysis, _events, root = pipeline
    trigger_website(protection)
    alert = analysis.alerts()[0]
    assert analysis.acknowledge_alert(alert.id)

    store = AnalysisStore(root)
    manager = SecurityAlertManager(store)
    restored = manager.find(alert.id)
    assert restored is not None
    assert restored.status is AlertStatus.ACKNOWLEDGED


def test_incident_groups_related_findings_and_separates_unrelated(tmp_path) -> None:
    manager = IncidentManager(AnalysisStore(tmp_path / "data"))
    first = make_finding("FND-0001")
    second = make_finding("FND-0002")
    unrelated = make_finding(
        "FND-0003",
        target="other.test",
        module_ids=("application",),
    )

    incident, created = manager.attach(first, None, window_minutes=30)
    assert created
    same, created_same = manager.attach(second, None, window_minutes=30)
    assert not created_same
    assert same.id == incident.id
    assert same.finding_ids == ("FND-0001", "FND-0002")

    other, created_other = manager.attach(unrelated, None, window_minutes=30)
    assert created_other
    assert other.id != incident.id
    assert len(manager.all_incidents()) == 2


def test_incident_investigation_notes_resolution_and_closure(tmp_path) -> None:
    manager = IncidentManager(AnalysisStore(tmp_path / "data"))
    incident, _created = manager.attach(make_finding("FND-0001"), None)

    assert manager.start_investigation(incident.id)
    assert manager.find(incident.id).status is IncidentStatus.INVESTIGATING

    assert manager.add_note(incident.id, "Checked the relevant SSG8 policy.")
    assert manager.find(incident.id).notes[0].text.startswith("Checked")
    assert not manager.add_note(incident.id, "   ")
    assert not manager.add_note(incident.id, "x" * 501)

    assert manager.set_severity(incident.id, RiskLevel.HIGH)
    assert manager.find(incident.id).level is RiskLevel.HIGH

    assert manager.resolve(incident.id)
    assert manager.find(incident.id).status is IncidentStatus.RESOLVED
    assert manager.close(incident.id)
    assert manager.find(incident.id).status is IncidentStatus.CLOSED
    assert not manager.add_note(incident.id, "Closed incident note")
    assert not manager.start_investigation(incident.id)


def test_incident_persistence_and_filters(tmp_path) -> None:
    root = tmp_path / "data"
    manager = IncidentManager(AnalysisStore(root))
    incident, _created = manager.attach(make_finding("FND-0001"), None)
    assert manager.add_note(incident.id, "Persisted note")

    restored = IncidentManager(AnalysisStore(root))
    saved = restored.find(incident.id)
    assert saved is not None
    assert saved.notes[0].text == "Persisted note"
    assert restored.incidents(status=IncidentStatus.OPEN)
    assert restored.incidents(search="repeated")
    assert restored.incidents(search="missing") == ()


def test_incident_merges_alert_ids(pipeline) -> None:
    protection, analysis, _events, _root = pipeline
    trigger_website(protection)
    incident = analysis.incidents()[0]
    assert incident.alert_ids == ("ALR-0001",)

    # Attaching the same finding again must not duplicate IDs.
    manager = analysis.incident_manager
    updated, created = manager.attach(
        analysis.findings()[0],
        analysis.alerts()[0],
        window_minutes=30,
    )
    assert not created
    assert updated.alert_ids == ("ALR-0001",)
    assert updated.finding_ids == ("FND-0001",)


def test_replacing_alert_status_keeps_timestamp_order(pipeline) -> None:
    protection, analysis, _events, _root = pipeline
    trigger_website(protection)
    alert = analysis.alerts()[0]
    before = alert.updated_at
    assert analysis.acknowledge_alert(alert.id)
    after = analysis.alert(alert.id)
    assert after.updated_at >= before
    assert after.created_at == alert.created_at


def test_alert_and_incident_severity_states(pipeline) -> None:
    protection, analysis, _events, _root = pipeline
    trigger_website(protection)
    incident = analysis.incidents()[0]

    assert analysis.set_incident_severity(incident.id, RiskLevel.CRITICAL)
    assert analysis.incident(incident.id).level is RiskLevel.CRITICAL
    assert analysis.start_investigation(incident.id)
    assert analysis.add_incident_note(incident.id, "Reviewed in unit test")
    assert analysis.resolve_incident(incident.id)
    assert analysis.close_incident(incident.id)
    assert analysis.incident(incident.id).status is IncidentStatus.CLOSED


def test_incident_closed_cannot_change_severity(pipeline) -> None:
    protection, analysis, _events, _root = pipeline
    trigger_website(protection)
    incident = analysis.incidents()[0]
    analysis.close_incident(incident.id)
    assert not analysis.set_incident_severity(incident.id, RiskLevel.LOW)
    assert not analysis.resolve_incident(incident.id)


def test_replacing_finding_is_allowed_for_future_alert_creation(pipeline) -> None:
    protection, analysis, _events, _root = pipeline
    trigger_website(protection)
    finding = analysis.findings()[0]
    # A finding without an alert can be attached to an incident on its own.
    without_alert = replace(finding, alert_id="")
    incident, _created = analysis.incident_manager.attach(without_alert, None)
    assert incident.finding_ids


def test_alert_filters_by_level_and_search(pipeline) -> None:
    protection, analysis, _events, _root = pipeline
    trigger_website(protection)
    assert analysis.alerts(level=RiskLevel.MEDIUM)
    assert analysis.alerts(level=RiskLevel.CRITICAL) == ()
    assert analysis.alerts(search="website")


def test_analysis_settings_are_validated_and_persisted(pipeline) -> None:
    _protection, analysis, _events, root = pipeline

    ok, _message = analysis.update_settings(
        window_minutes=30,
        repeat_threshold=4,
        multi_module_threshold=3,
        alert_min_score=40,
    )
    assert ok
    assert analysis.settings().window_minutes == 30
    assert analysis.settings().repeat_threshold == 4
    assert (root / "analysis_settings.json").exists()

    ok, message = analysis.update_settings(window_minutes=0)
    assert not ok
    assert "between" in message
    assert analysis.settings().window_minutes == 30

    reloaded = AnalysisService(
        _protection,
        EventLog(),
        AnalysisStore(root),
    )
    assert reloaded.settings().alert_min_score == 40
