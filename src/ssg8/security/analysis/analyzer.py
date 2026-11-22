"""Threat analysis engine for SSG8's internal policy decisions.

The analyzer is deliberately small and deterministic. It inspects recent
decisions, detects repeated policy patterns, scores them with transparent
factors and produces findings. It never reads Windows telemetry and never
claims that a pattern proves malware or an external attack.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Sequence
from dataclasses import replace
from datetime import datetime

from ssg8.security.analysis.models import FindingEvidence, ThreatFinding
from ssg8.security.analysis.patterns import (
    MODULE_IDS_BY_LABEL,
    PatternCandidate,
    detect_patterns,
)
from ssg8.security.analysis.rules import AnalysisSettings
from ssg8.security.decisions import ProtectionDecision

EVIDENCE_LIMIT = 20


class ThreatAnalyzer:
    """Detect and score suspicious patterns in SSG8 decisions."""

    def analyze(
        self,
        decisions: Iterable[ProtectionDecision],
        settings: AnalysisSettings,
        *,
        existing_findings: Sequence[ThreatFinding] = (),
        next_id: Callable[[], str] | None = None,
    ) -> tuple[ThreatFinding, ...]:
        """Return new or materially updated findings.

        Re-analysis of the same events is idempotent. A finding for the same
        pattern key is updated in place inside the duplicate-suppression window
        instead of producing a second record.
        """
        candidates = detect_patterns(tuple(decisions), settings)
        if not candidates:
            return ()

        latest_by_key: dict[str, ThreatFinding] = {}
        for finding in existing_findings:
            current = latest_by_key.get(finding.key)
            if current is None or finding.last_seen > current.last_seen:
                latest_by_key[finding.key] = finding

        results: list[ThreatFinding] = []
        for candidate in candidates:
            previous = latest_by_key.get(candidate.key)
            if previous is not None:
                seconds = (candidate.last_seen - previous.last_seen).total_seconds()
                if seconds < settings.dedupe_minutes * 60:
                    updated = self._update(previous, candidate)
                    if updated != previous:
                        results.append(updated)
                    continue

            finding_id = next_id() if next_id is not None else self._fallback_id(candidate)
            results.append(self._create(finding_id, candidate))
        return tuple(results)

    # --- construction ------------------------------------------------------

    def _create(self, finding_id: str, candidate: PatternCandidate) -> ThreatFinding:
        return ThreatFinding(
            id=finding_id,
            key=candidate.key,
            title=candidate.title,
            description=candidate.description,
            pattern=candidate.pattern,
            module_ids=candidate.module_ids,
            target=candidate.target,
            score=candidate.score,
            level=candidate.assessment.level,
            factors=candidate.assessment.factors,
            created_at=candidate.first_seen,
            last_seen=candidate.last_seen,
            event_count=len(candidate.decisions),
            evidence=self._evidence(candidate.decisions),
        )

    def _update(
        self, previous: ThreatFinding, candidate: PatternCandidate
    ) -> ThreatFinding:
        return replace(
            previous,
            title=candidate.title,
            description=candidate.description,
            module_ids=candidate.module_ids,
            target=candidate.target,
            score=candidate.score,
            level=candidate.assessment.level,
            factors=candidate.assessment.factors,
            last_seen=candidate.last_seen,
            event_count=len(candidate.decisions),
            evidence=self._evidence(candidate.decisions),
        )

    @staticmethod
    def _evidence(
        decisions: Sequence[ProtectionDecision],
    ) -> tuple[FindingEvidence, ...]:
        ordered = sorted(decisions, key=lambda decision: decision.timestamp)
        return tuple(
            FindingEvidence(
                timestamp=decision.timestamp,
                module_id=MODULE_IDS_BY_LABEL.get(decision.module, ""),
                target=decision.target,
                action=decision.action.value,
                reason=decision.reason,
            )
            for decision in ordered[-EVIDENCE_LIMIT:]
        )

    @staticmethod
    def _fallback_id(candidate: PatternCandidate) -> str:
        source = f"{candidate.key}|{candidate.last_seen.isoformat()}"
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()[:8].upper()
        return f"FND-{digest}"


def finding_is_recent(finding: ThreatFinding, now: datetime, minutes: int) -> bool:
    """Return whether a finding was last seen within ``minutes``."""
    return (now - finding.last_seen).total_seconds() <= minutes * 60
