"""Tests for deterministic risk classification and scoring."""

from __future__ import annotations

from ssg8.security.analysis.models import RiskLevel
from ssg8.security.analysis.risk import calculate_risk, level_for_score
from ssg8.security.analysis.rules import (
    PATTERN_MULTI_MODULE,
    PATTERN_REPEATED_BLOCK,
    PATTERN_REVIEW_CONCENTRATION,
)


def test_score_boundaries() -> None:
    assert level_for_score(0) is RiskLevel.LOW
    assert level_for_score(24) is RiskLevel.LOW
    assert level_for_score(25) is RiskLevel.MEDIUM
    assert level_for_score(49) is RiskLevel.MEDIUM
    assert level_for_score(50) is RiskLevel.HIGH
    assert level_for_score(74) is RiskLevel.HIGH
    assert level_for_score(75) is RiskLevel.CRITICAL
    assert level_for_score(100) is RiskLevel.CRITICAL


def test_scores_are_clamped() -> None:
    assert level_for_score(-50) is RiskLevel.LOW
    assert level_for_score(250) is RiskLevel.CRITICAL


def test_repeated_website_blocks_score_medium() -> None:
    assessment = calculate_risk(
        pattern=PATTERN_REPEATED_BLOCK,
        module_ids=("website",),
        count=3,
        block_count=3,
        review_count=0,
        span_seconds=5,
    )
    assert assessment.score == 45
    assert assessment.level is RiskLevel.MEDIUM


def test_repeated_download_blocks_score_high() -> None:
    assessment = calculate_risk(
        pattern=PATTERN_REPEATED_BLOCK,
        module_ids=("download",),
        count=3,
        block_count=3,
        review_count=0,
        span_seconds=5,
    )
    assert assessment.score == 65
    assert assessment.level is RiskLevel.HIGH


def test_cross_module_pattern_is_high() -> None:
    assessment = calculate_risk(
        pattern=PATTERN_MULTI_MODULE,
        module_ids=("website", "application"),
        count=2,
        block_count=2,
        review_count=0,
        span_seconds=5,
    )
    assert assessment.score == 53
    assert assessment.level is RiskLevel.HIGH


def test_review_concentration_is_medium() -> None:
    assessment = calculate_risk(
        pattern=PATTERN_REVIEW_CONCENTRATION,
        module_ids=("website",),
        count=3,
        block_count=0,
        review_count=3,
        span_seconds=30,
    )
    assert assessment.score == 38
    assert assessment.level is RiskLevel.MEDIUM


def test_identical_inputs_produce_identical_scores() -> None:
    kwargs = dict(
        pattern=PATTERN_REPEATED_BLOCK,
        module_ids=("download",),
        count=4,
        block_count=3,
        review_count=1,
        span_seconds=90,
    )
    first = calculate_risk(**kwargs)
    second = calculate_risk(**kwargs)
    assert first.score == second.score
    assert first.level is second.level
    assert first.factors == second.factors


def test_score_cannot_exceed_100_even_with_many_events() -> None:
    assessment = calculate_risk(
        pattern=PATTERN_MULTI_MODULE,
        module_ids=("website", "download", "application", "notification"),
        count=100,
        block_count=80,
        review_count=20,
        span_seconds=0,
    )
    assert assessment.score <= 100
    assert assessment.level in RiskLevel


def test_explanation_lists_scoring_factors() -> None:
    assessment = calculate_risk(
        pattern=PATTERN_REPEATED_BLOCK,
        module_ids=("website",),
        count=3,
        block_count=3,
        review_count=0,
        span_seconds=5,
    )
    explanation = assessment.explanation
    assert "Detection basis: +15" in explanation
    assert "Repeated policy events: +10" in explanation
    assert "Time concentration: +10" in explanation
    assert "Final score: 45/100 (MEDIUM)" in explanation
