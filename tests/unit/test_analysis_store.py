"""Tests for validation and resilience of the analysis JSON store."""

from __future__ import annotations

import json
from datetime import datetime

from ssg8.security.analysis.models import (
    IncidentStatus,
    RiskLevel,
    SecurityAlert,
    SecurityIncident,
    ThreatFinding,
)
from ssg8.security.analysis.rules import AnalysisSettings
from ssg8.storage.analysis_store import AnalysisStore


def finding(finding_id: str = "FND-0001") -> ThreatFinding:
    now = datetime.now().replace(microsecond=0)
    return ThreatFinding(
        id=finding_id,
        key="repeated_block|website|bad.test",
        title="Repeated website policy violations",
        description="Internal policy pattern.",
        pattern="repeated_block",
        module_ids=("website",),
        target="bad.test",
        score=45,
        level=RiskLevel.MEDIUM,
        factors=(),
        created_at=now,
        last_seen=now,
        event_count=3,
        alert_id="ALR-0001",
    )


def test_round_trip_findings_alerts_incidents(tmp_path) -> None:
    store = AnalysisStore(tmp_path)
    item = finding()
    alert = SecurityAlert(
        id="ALR-0001",
        title=item.title,
        description=item.description,
        level=item.level,
        score=item.score,
        module_id="website",
        target=item.target,
        finding_id=item.id,
        created_at=item.created_at,
        updated_at=item.last_seen,
    )
    incident = SecurityIncident(
        id="INC-0001",
        group_key="website:bad.test",
        title="Incident",
        summary="Summary",
        level=item.level,
        score=item.score,
        created_at=item.created_at,
        updated_at=item.last_seen,
        alert_ids=(alert.id,),
        finding_ids=(item.id,),
        module_ids=("website",),
        status=IncidentStatus.INVESTIGATING,
    )

    assert store.save_findings([item])
    assert store.save_alerts([alert])
    assert store.save_incidents([incident])

    restored = AnalysisStore(tmp_path)
    assert restored.load_findings() == [item]
    assert restored.load_alerts() == [alert]
    assert restored.load_incidents() == [incident]
    assert not list(tmp_path.glob("*.tmp"))


def test_missing_files_return_empty_data(tmp_path) -> None:
    store = AnalysisStore(tmp_path / "missing")
    assert store.load_findings() == []
    assert store.load_alerts() == []
    assert store.load_incidents() == []
    assert store.load_settings() == AnalysisSettings()


def test_corrupted_json_is_reported_not_raised(tmp_path) -> None:
    store = AnalysisStore(tmp_path)
    store.findings_path.write_text("{not valid json", encoding="utf-8")

    assert store.load_findings() == []
    assert store.errors()


def test_invalid_records_and_duplicate_ids_are_skipped(tmp_path) -> None:
    store = AnalysisStore(tmp_path)
    valid = finding().to_dict()
    payload = [valid, valid, {"id": "FND-0002"}, "not an object"]
    store.findings_path.write_text(json.dumps(payload), encoding="utf-8")

    loaded = store.load_findings()

    assert len(loaded) == 1
    assert loaded[0].id == "FND-0001"
    assert len(store.errors()) == 3


def test_score_is_bounded_when_loading(tmp_path) -> None:
    store = AnalysisStore(tmp_path)
    payload = finding().to_dict()
    payload["score"] = 9999
    store.findings_path.write_text(json.dumps([payload]), encoding="utf-8")

    loaded = store.load_findings()[0]
    assert loaded.score == 100
    assert loaded.level is RiskLevel.CRITICAL


def test_invalid_settings_fall_back_per_field(tmp_path) -> None:
    store = AnalysisStore(tmp_path)
    store.settings_path.write_text(
        json.dumps(
            {
                "window_minutes": 0,
                "repeat_threshold": 4,
                "multi_module_threshold": "bad",
                "alert_min_score": 30,
                "dedupe_minutes": 60,
            }
        ),
        encoding="utf-8",
    )

    settings = store.load_settings()

    assert settings.window_minutes == AnalysisSettings().window_minutes
    assert settings.repeat_threshold == 4
    assert settings.multi_module_threshold == AnalysisSettings().multi_module_threshold
    assert settings.alert_min_score == 30
    assert settings.dedupe_minutes == 60
    assert len(store.errors()) == 2


def test_settings_round_trip(tmp_path) -> None:
    store = AnalysisStore(tmp_path)
    settings = AnalysisSettings(
        window_minutes=30,
        repeat_threshold=4,
        multi_module_threshold=3,
        alert_min_score=40,
        dedupe_minutes=90,
    )
    assert store.save_settings(settings)
    assert AnalysisStore(tmp_path).load_settings() == settings


def test_non_list_payload_is_ignored(tmp_path) -> None:
    store = AnalysisStore(tmp_path)
    store.alerts_path.write_text(json.dumps({"alert": "nope"}), encoding="utf-8")
    assert store.load_alerts() == []
    assert store.errors()
