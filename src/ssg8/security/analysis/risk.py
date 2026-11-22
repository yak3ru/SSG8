"""Deterministic, explainable risk scoring for analysis findings.

Scores are derived only from the events SSG8 observed: how many policy
violations occurred, which modules were involved, how concentrated they were
in time, and whether one target repeated. No random numbers, external threat
feeds or opaque models are used.
"""

from __future__ import annotations

from ssg8.security.analysis.models import RiskAssessment, RiskFactor, RiskLevel
from ssg8.security.analysis.rules import (
    PATTERN_DOWNLOAD_VOLUME,
    PATTERN_MULTI_MODULE,
    PATTERN_REPEATED_BLOCK,
    PATTERN_REVIEW_CONCENTRATION,
)

LOW_MAX = 24
MEDIUM_MAX = 49
HIGH_MAX = 74

_PATTERN_BASE: dict[str, int] = {
    PATTERN_REPEATED_BLOCK: 15,
    PATTERN_DOWNLOAD_VOLUME: 15,
    PATTERN_REVIEW_CONCENTRATION: 18,
    PATTERN_MULTI_MODULE: 20,
}

_MODULE_WEIGHT: dict[str, int] = {
    "website": 0,
    "application": 3,
    "download": 20,
    "notification": -5,
}


def level_for_score(score: int) -> RiskLevel:
    """Classify a clamped score into a risk level."""
    score = max(0, min(100, int(score)))
    if score <= LOW_MAX:
        return RiskLevel.LOW
    if score <= MEDIUM_MAX:
        return RiskLevel.MEDIUM
    if score <= HIGH_MAX:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


def calculate_risk(
    *,
    pattern: str,
    module_ids: tuple[str, ...],
    count: int,
    block_count: int,
    review_count: int,
    span_seconds: float,
) -> RiskAssessment:
    """Return a reproducible assessment for one pattern candidate."""
    factors: list[RiskFactor] = []

    base = _PATTERN_BASE.get(pattern, 15)
    factors.append(RiskFactor("Detection basis", base, _basis_label(pattern)))

    volume = 5 * min(6, max(0, count - 1))
    if volume:
        factors.append(RiskFactor("Repeated policy events", volume, f"{count} events"))

    weight = max((_MODULE_WEIGHT.get(module_id, 0) for module_id in module_ids), default=0)
    if weight:
        factors.append(
            RiskFactor(
                "Protection module impact",
                weight,
                ", ".join(sorted(module_ids)) or "internal module",
            )
        )

    if span_seconds <= 120:
        concentration = 10
    elif span_seconds <= 600:
        concentration = 5
    else:
        concentration = 0
    if concentration:
        minutes = max(0.0, span_seconds) / 60
        factors.append(
            RiskFactor(
                "Time concentration",
                concentration,
                f"{count} events within {minutes:.1f} minutes",
            )
        )

    if pattern == PATTERN_REPEATED_BLOCK:
        factors.append(RiskFactor("Same target repeated", 5, "one target triggered the pattern"))

    if pattern == PATTERN_MULTI_MODULE and len(module_ids) > 1:
        points = min(30, 10 * (len(module_ids) - 1))
        factors.append(
            RiskFactor(
                "Multiple protection modules",
                points,
                f"{len(module_ids)} modules affected",
            )
        )

    if review_count and pattern != PATTERN_REVIEW_CONCENTRATION:
        factors.append(RiskFactor("Review decisions involved", 5, f"{review_count} reviews"))

    if block_count and block_count >= review_count:
        factors.append(RiskFactor("Block decisions dominant", 5, f"{block_count} blocks"))

    raw_score = sum(factor.points for factor in factors)
    score = max(0, min(100, raw_score))
    return RiskAssessment(score=score, level=level_for_score(score), factors=tuple(factors))


def _basis_label(pattern: str) -> str:
    if pattern in (PATTERN_REPEATED_BLOCK, PATTERN_DOWNLOAD_VOLUME):
        return "repeated BLOCK decisions for download requests" if pattern == PATTERN_DOWNLOAD_VOLUME else "repeated BLOCK decisions for one target"
    if pattern == PATTERN_REVIEW_CONCENTRATION:
        return "concentrated REVIEW decisions in one module"
    if pattern == PATTERN_MULTI_MODULE:
        return "policy violations across several modules"
    return "internal policy pattern"
