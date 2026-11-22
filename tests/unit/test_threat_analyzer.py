"""Tests for deterministic pattern detection in the threat analyzer."""

from __future__ import annotations

from datetime import datetime, timedelta

from ssg8.security.analysis.analyzer import ThreatAnalyzer
from ssg8.security.analysis.patterns import detect_patterns
from ssg8.security.analysis.rules import (
    AnalysisSettings,
    PATTERN_DOWNLOAD_VOLUME,
    PATTERN_MULTI_MODULE,
    PATTERN_REPEATED_BLOCK,
    PATTERN_REVIEW_CONCENTRATION,
)
from ssg8.security.decisions import ProtectionAction, ProtectionDecision

MODULES = {
    "website": "Website Protection",
    "download": "Download Protection",
    "application": "Application Control",
    "notification": "Notification Control",
}


def decision(
    module_id: str,
    target: str,
    action: ProtectionAction,
    *,
    seconds_ago: int = 0,
    host: str = "",
) -> ProtectionDecision:
    metadata = {"host": host} if host else {}
    return ProtectionDecision(
        action=action,
        module=MODULES[module_id],
        target=target,
        reason=f"test {action.value}",
        timestamp=datetime.now() - timedelta(seconds=seconds_ago),
        metadata=metadata,
    )


def test_detects_repeated_website_blocks_by_host() -> None:
    now = datetime.now()
    decisions = [
        ProtectionDecision(
            ProtectionAction.BLOCK,
            MODULES["website"],
            f"https://bad.test/{index}",
            "blocked",
            now - timedelta(seconds=index),
            metadata={"host": "bad.test"},
        )
        for index in range(3)
    ]

    findings = ThreatAnalyzer().analyze(decisions, AnalysisSettings())

    assert len(findings) == 1
    finding = findings[0]
    assert finding.pattern == PATTERN_REPEATED_BLOCK
    assert finding.target == "bad.test"
    assert finding.event_count == 3
    assert finding.level.value == "MEDIUM"


def test_detects_repeated_download_blocks() -> None:
    decisions = [
        decision("download", r"C:\Downloads\bad.exe", ProtectionAction.BLOCK, seconds_ago=i)
        for i in range(3)
    ]
    findings = ThreatAnalyzer().analyze(decisions, AnalysisSettings())
    repeated = [f for f in findings if f.pattern == PATTERN_REPEATED_BLOCK]
    assert len(repeated) == 1
    assert repeated[0].level.value == "HIGH"


def test_detects_blocks_across_different_downloads() -> None:
    decisions = [
        decision("download", rf"C:\Downloads\file-{index}.exe", ProtectionAction.BLOCK, seconds_ago=index)
        for index in range(3)
    ]
    findings = ThreatAnalyzer().analyze(decisions, AnalysisSettings())
    volume = [f for f in findings if f.pattern == PATTERN_DOWNLOAD_VOLUME]
    assert len(volume) == 1
    assert volume[0].target == "multiple files"
    assert volume[0].level.value == "HIGH"


def test_repeated_single_download_does_not_add_volume_finding() -> None:
    decisions = [
        decision("download", r"C:\Downloads\same.exe", ProtectionAction.BLOCK, seconds_ago=i)
        for i in range(3)
    ]
    findings = ThreatAnalyzer().analyze(decisions, AnalysisSettings())
    assert not any(f.pattern == PATTERN_DOWNLOAD_VOLUME for f in findings)
    assert any(f.pattern == PATTERN_REPEATED_BLOCK for f in findings)


def test_detects_repeated_application_blocks() -> None:
    decisions = [
        decision("application", "Tool", ProtectionAction.BLOCK, seconds_ago=i)
        for i in range(3)
    ]
    findings = ThreatAnalyzer().analyze(decisions, AnalysisSettings())
    assert any(f.pattern == PATTERN_REPEATED_BLOCK for f in findings)
    assert any("application" in f.title for f in findings)


def test_detects_multiple_related_modules() -> None:
    decisions = [
        decision("website", "one.test", ProtectionAction.BLOCK, seconds_ago=3, host="one.test"),
        decision("application", "Tool", ProtectionAction.BLOCK, seconds_ago=2),
    ]
    findings = ThreatAnalyzer().analyze(decisions, AnalysisSettings())
    multi = [f for f in findings if f.pattern == PATTERN_MULTI_MODULE]
    assert len(multi) == 1
    assert multi[0].module_ids == ("application", "website")
    assert multi[0].level.value == "HIGH"


def test_detects_review_concentration() -> None:
    decisions = [
        decision("website", f"review-{i}.test", ProtectionAction.REVIEW, seconds_ago=i)
        for i in range(3)
    ]
    findings = ThreatAnalyzer().analyze(decisions, AnalysisSettings())
    reviews = [f for f in findings if f.pattern == PATTERN_REVIEW_CONCENTRATION]
    assert len(reviews) == 1
    assert reviews[0].event_count == 3


def test_ignores_allowed_and_unrelated_events() -> None:
    decisions = [
        decision("website", "ok.test", ProtectionAction.ALLOW, host="ok.test"),
        decision("website", "ok.test", ProtectionAction.ALLOW, host="ok.test"),
        decision("website", "ok.test", ProtectionAction.ALLOW, host="ok.test"),
    ]
    assert ThreatAnalyzer().analyze(decisions, AnalysisSettings()) == ()


def test_empty_history_produces_no_findings() -> None:
    assert ThreatAnalyzer().analyze([], AnalysisSettings()) == ()
    assert detect_patterns([], AnalysisSettings()) == ()


def test_malformed_records_are_ignored() -> None:
    decisions = [
        object(),
        decision("website", "", ProtectionAction.BLOCK),
        decision("website", "bad.test", ProtectionAction.BLOCK, host="bad.test"),
    ]
    findings = ThreatAnalyzer().analyze(decisions, AnalysisSettings())
    assert findings == ()


def test_events_outside_the_window_are_ignored() -> None:
    decisions = [
        decision("website", "old.test", ProtectionAction.BLOCK, seconds_ago=4000, host="old.test"),
        decision("website", "old.test", ProtectionAction.BLOCK, seconds_ago=3000, host="old.test"),
        decision("website", "old.test", ProtectionAction.BLOCK, seconds_ago=1, host="old.test"),
    ]
    assert ThreatAnalyzer().analyze(decisions, AnalysisSettings()) == ()


def test_reanalysis_does_not_duplicate_findings() -> None:
    decisions = [
        decision("website", "bad.test", ProtectionAction.BLOCK, seconds_ago=i, host="bad.test")
        for i in range(3)
    ]
    analyzer = ThreatAnalyzer()
    first = analyzer.analyze(decisions, AnalysisSettings())
    second = analyzer.analyze(
        decisions, AnalysisSettings(), existing_findings=first
    )
    assert len(first) == 1
    assert second == ()


def test_new_events_update_existing_finding_and_score() -> None:
    initial = [
        decision("website", "bad.test", ProtectionAction.BLOCK, seconds_ago=10 - i, host="bad.test")
        for i in range(3)
    ]
    analyzer = ThreatAnalyzer()
    first = analyzer.analyze(initial, AnalysisSettings())
    assert len(first) == 1

    more = initial + [
        decision("website", "bad.test", ProtectionAction.BLOCK, seconds_ago=i, host="bad.test")
        for i in range(2)
    ]
    updated = analyzer.analyze(
        more, AnalysisSettings(), existing_findings=first
    )
    assert len(updated) == 1
    assert updated[0].id == first[0].id
    assert updated[0].event_count == 5
    assert updated[0].score >= first[0].score


def test_custom_threshold_controls_detection() -> None:
    decisions = [
        decision("website", "bad.test", ProtectionAction.BLOCK, seconds_ago=i, host="bad.test")
        for i in range(2)
    ]
    assert detect_patterns(decisions, AnalysisSettings(repeat_threshold=3)) == ()
    assert detect_patterns(decisions, AnalysisSettings(repeat_threshold=2))
