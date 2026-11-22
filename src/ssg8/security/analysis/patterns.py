"""Pattern detection over SSG8 protection decisions.

Only decisions produced by SSG8's four internal modules are considered. Every
candidate is a *suspicious policy pattern*; it is deliberately not described as
malware or a confirmed attack.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta

from ssg8.security.analysis.models import RiskAssessment
from ssg8.security.analysis.risk import calculate_risk
from ssg8.security.analysis.rules import (
    AnalysisSettings,
    MODULE_SUBJECTS,
    PATTERN_DOWNLOAD_VOLUME,
    PATTERN_MULTI_MODULE,
    PATTERN_REPEATED_BLOCK,
    PATTERN_REVIEW_CONCENTRATION,
)
from ssg8.security.decisions import ProtectionAction, ProtectionDecision

MODULE_LABELS: dict[str, str] = {
    "website": "Website Protection",
    "download": "Download Protection",
    "application": "Application Control",
    "notification": "Notification Control",
}

MODULE_IDS_BY_LABEL: dict[str, str] = {
    label: module_id for module_id, label in MODULE_LABELS.items()
}


@dataclass(frozen=True, slots=True)
class PatternCandidate:
    """A detected pattern before it becomes a persisted finding."""

    key: str
    pattern: str
    title: str
    description: str
    module_ids: tuple[str, ...]
    target: str
    decisions: tuple[ProtectionDecision, ...]
    assessment: RiskAssessment

    @property
    def score(self) -> int:
        return self.assessment.score

    @property
    def first_seen(self) -> datetime:
        return min(decision.timestamp for decision in self.decisions)

    @property
    def last_seen(self) -> datetime:
        return max(decision.timestamp for decision in self.decisions)


def detect_patterns(
    decisions: tuple[ProtectionDecision, ...] | list[ProtectionDecision],
    settings: AnalysisSettings,
) -> tuple[PatternCandidate, ...]:
    """Return deterministic pattern candidates for the configured window."""
    valid = _valid_decisions(decisions)
    if not valid:
        return ()

    anchor = max(decision.timestamp for decision in valid)
    cutoff = anchor - timedelta(minutes=settings.window_minutes)
    recent = [decision for decision in valid if decision.timestamp >= cutoff]
    violations = [
        decision
        for decision in recent
        if decision.action in (ProtectionAction.BLOCK, ProtectionAction.REVIEW)
    ]
    if not violations:
        return ()

    candidates: dict[str, PatternCandidate] = {}

    # Pattern A/B/C: repeated BLOCK decisions for one target in one module.
    blocks_by_target: dict[tuple[str, str], list[ProtectionDecision]] = defaultdict(list)
    for decision in violations:
        if decision.action is not ProtectionAction.BLOCK:
            continue
        target = _target(decision)
        if not target:
            continue
        blocks_by_target[(_module_id(decision), target.casefold())].append(decision)

    for (module_id, _target_key), block_decisions in blocks_by_target.items():
        if len(block_decisions) < settings.repeat_threshold:
            continue
        target = _target(block_decisions[-1])
        span = _span_seconds(block_decisions)
        assessment = calculate_risk(
            pattern=PATTERN_REPEATED_BLOCK,
            module_ids=(module_id,),
            count=len(block_decisions),
            block_count=len(block_decisions),
            review_count=0,
            span_seconds=span,
        )
        subject = MODULE_SUBJECTS.get(module_id, module_id)
        key = f"{PATTERN_REPEATED_BLOCK}|{module_id}|{target.casefold()}"
        candidates[key] = PatternCandidate(
            key=key,
            pattern=PATTERN_REPEATED_BLOCK,
            title=f"Repeated {subject} policy violations",
            description=(
                f"{len(block_decisions)} BLOCK decisions for {target} occurred within "
                f"the {settings.window_minutes}-minute analysis window. This is an "
                "internal policy pattern, not confirmed malware or an external attack."
            ),
            module_ids=(module_id,),
            target=target,
            decisions=tuple(block_decisions),
            assessment=assessment,
        )

    # Pattern B: several different downloads blocked inside the window.
    download_blocks = [
        decision
        for decision in violations
        if _module_id(decision) == "download"
        and decision.action is ProtectionAction.BLOCK
    ]
    if len(download_blocks) >= settings.repeat_threshold:
        per_target = Counter(_target(decision).casefold() for decision in download_blocks)
        if not per_target or max(per_target.values()) < settings.repeat_threshold:
            assessment = calculate_risk(
                pattern=PATTERN_DOWNLOAD_VOLUME,
                module_ids=("download",),
                count=len(download_blocks),
                block_count=len(download_blocks),
                review_count=0,
                span_seconds=_span_seconds(download_blocks),
            )
            key = f"{PATTERN_DOWNLOAD_VOLUME}|download"
            candidates[key] = PatternCandidate(
                key=key,
                pattern=PATTERN_DOWNLOAD_VOLUME,
                title="Repeated download policy violations",
                description=(
                    f"{len(download_blocks)} different download requests were "
                    f"BLOCKED within the {settings.window_minutes}-minute analysis "
                    f"window. This is repeated internal download policy activity, not "
                    "a malware verdict."
                ),
                module_ids=("download",),
                target="multiple files",
                decisions=tuple(download_blocks),
                assessment=assessment,
            )

    # Review concentration: unusual numbers of REVIEW decisions in one module.
    reviews_by_module: dict[str, list[ProtectionDecision]] = defaultdict(list)
    for decision in violations:
        if decision.action is ProtectionAction.REVIEW:
            reviews_by_module[_module_id(decision)].append(decision)

    for module_id, review_decisions in reviews_by_module.items():
        if len(review_decisions) < settings.repeat_threshold:
            continue
        targets = {_target(decision).casefold() for decision in review_decisions}
        assessment = calculate_risk(
            pattern=PATTERN_REVIEW_CONCENTRATION,
            module_ids=(module_id,),
            count=len(review_decisions),
            block_count=0,
            review_count=len(review_decisions),
            span_seconds=_span_seconds(review_decisions),
        )
        label = MODULE_LABELS.get(module_id, module_id)
        key = f"{PATTERN_REVIEW_CONCENTRATION}|{module_id}"
        candidates[key] = PatternCandidate(
            key=key,
            pattern=PATTERN_REVIEW_CONCENTRATION,
            title=f"Repeated review decisions in {label}",
            description=(
                f"{len(review_decisions)} REVIEW decisions across {len(targets)} "
                f"target(s) occurred within the {settings.window_minutes}-minute "
                "analysis window. Review volume is elevated inside SSG8; this is "
                "not a malware verdict."
            ),
            module_ids=(module_id,),
            target="multiple targets" if len(targets) > 1 else _target(review_decisions[-1]),
            decisions=tuple(review_decisions),
            assessment=assessment,
        )

    # Pattern D: violations across several protection modules.
    active_modules = sorted({_module_id(decision) for decision in violations})
    if len(active_modules) >= settings.multi_module_threshold:
        module_ids = tuple(active_modules)
        block_count = sum(
            1 for decision in violations if decision.action is ProtectionAction.BLOCK
        )
        review_count = len(violations) - block_count
        assessment = calculate_risk(
            pattern=PATTERN_MULTI_MODULE,
            module_ids=module_ids,
            count=len(violations),
            block_count=block_count,
            review_count=review_count,
            span_seconds=_span_seconds(violations),
        )
        labels = ", ".join(MODULE_LABELS.get(module_id, module_id) for module_id in module_ids)
        key = f"{PATTERN_MULTI_MODULE}|{','.join(module_ids)}"
        candidates[key] = PatternCandidate(
            key=key,
            pattern=PATTERN_MULTI_MODULE,
            title="Multiple protection policy violations",
            description=(
                f"Policy violations were raised by {len(module_ids)} protection "
                f"modules ({labels}) within the {settings.window_minutes}-minute "
                "analysis window. Cross-module policy activity is prioritised for "
                "review, but it is not proof of a real cyberattack."
            ),
            module_ids=module_ids,
            target="multiple targets",
            decisions=tuple(violations),
            assessment=assessment,
        )

    return tuple(
        sorted(candidates.values(), key=lambda item: (-item.score, item.key))
    )


def _valid_decisions(
    decisions: tuple[ProtectionDecision, ...] | list[ProtectionDecision],
) -> list[ProtectionDecision]:
    """Ignore empty or malformed records without raising."""
    valid: list[ProtectionDecision] = []
    for decision in decisions:
        if not isinstance(decision, ProtectionDecision):
            continue
        if not isinstance(decision.timestamp, datetime):
            continue
        if not isinstance(decision.action, ProtectionAction):
            continue
        if not isinstance(decision.target, str) or not decision.target.strip():
            continue
        if not _module_id(decision):
            continue
        valid.append(decision)
    return valid


def _module_id(decision: ProtectionDecision) -> str:
    module = decision.module if isinstance(decision.module, str) else ""
    return MODULE_IDS_BY_LABEL.get(module, "")


def _target(decision: ProtectionDecision) -> str:
    """Return the analysis target, grouping website URLs by host name."""
    if _module_id(decision) == "website":
        host = decision.metadata.get("host")
        if isinstance(host, str) and host.strip():
            return host.strip().casefold()
    return decision.target.strip() if isinstance(decision.target, str) else ""


def _span_seconds(decisions: list[ProtectionDecision]) -> float:
    timestamps = [decision.timestamp for decision in decisions]
    return max(0.0, (max(timestamps) - min(timestamps)).total_seconds())
