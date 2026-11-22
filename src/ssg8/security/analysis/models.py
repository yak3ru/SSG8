"""Data models for the internal threat-analysis pipeline.

Everything in this module is derived from requests submitted to SSG8. A
finding, alert or incident is a *policy-analysis record*, never a claim of
malware, a real cyberattack or operating-system telemetry.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from ssg8.core.models import Severity


class RiskLevel(str, Enum):
    """Deterministic risk classification from 0 to 100."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _RISK_RANK[self]

    @property
    def severity(self) -> Severity:
        return _RISK_SEVERITY[self]

    @property
    def tone(self) -> str:
        return _RISK_TONE[self]


_RISK_RANK: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}

_RISK_SEVERITY: dict[RiskLevel, Severity] = {
    RiskLevel.LOW: Severity.LOW,
    RiskLevel.MEDIUM: Severity.MEDIUM,
    RiskLevel.HIGH: Severity.HIGH,
    RiskLevel.CRITICAL: Severity.CRITICAL,
}

_RISK_TONE: dict[RiskLevel, str] = {
    RiskLevel.LOW: "info",
    RiskLevel.MEDIUM: "warning",
    RiskLevel.HIGH: "accent",
    RiskLevel.CRITICAL: "danger",
}


class AlertStatus(str, Enum):
    """Lifecycle of a security alert."""

    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class IncidentStatus(str, Enum):
    """Lifecycle of an incident."""

    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


@dataclass(frozen=True, slots=True)
class RiskFactor:
    """One transparent contribution to a finding's risk score."""

    label: str
    points: int
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label, "points": self.points, "detail": self.detail}

    @classmethod
    def from_dict(cls, raw: Any) -> "RiskFactor":
        if not isinstance(raw, dict):
            raise ValueError("risk factor is not an object")
        label = raw.get("label")
        points = raw.get("points")
        detail = raw.get("detail", "")
        if not isinstance(label, str) or not label.strip():
            raise ValueError("risk factor label is invalid")
        if not isinstance(points, int) or isinstance(points, bool):
            raise ValueError("risk factor points are invalid")
        return cls(label.strip(), points, str(detail)[:300])


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """A score, its risk level and the factors that produced it."""

    score: int
    level: RiskLevel
    factors: tuple[RiskFactor, ...]

    @property
    def explanation(self) -> str:
        lines = [
            f"{factor.label}: {'+' if factor.points >= 0 else ''}{factor.points}"
            + (f" ({factor.detail})" if factor.detail else "")
            for factor in self.factors
        ]
        lines.append(f"Final score: {self.score}/100 ({self.level.value})")
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class FindingEvidence:
    """A bounded copy of one decision that supports a finding."""

    timestamp: datetime
    module_id: str
    target: str
    action: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(timespec="seconds"),
            "module_id": self.module_id,
            "target": self.target,
            "action": self.action,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "FindingEvidence":
        if not isinstance(raw, dict):
            raise ValueError("evidence is not an object")
        return cls(
            timestamp=_parse_timestamp(raw.get("timestamp")),
            module_id=str(raw.get("module_id", ""))[:40],
            target=str(raw.get("target", ""))[:260],
            action=str(raw.get("action", ""))[:20],
            reason=str(raw.get("reason", ""))[:500],
        )


@dataclass(frozen=True, slots=True)
class ThreatFinding:
    """One suspicious internal policy pattern detected by the analyzer."""

    id: str
    key: str
    title: str
    description: str
    pattern: str
    module_ids: tuple[str, ...]
    target: str
    score: int
    level: RiskLevel
    factors: tuple[RiskFactor, ...]
    created_at: datetime
    last_seen: datetime
    event_count: int
    evidence: tuple[FindingEvidence, ...] = ()
    alert_id: str = ""

    @property
    def module_id(self) -> str:
        return self.module_ids[0] if len(self.module_ids) == 1 else ""

    @property
    def explanation(self) -> str:
        return RiskAssessment(self.score, self.level, self.factors).explanation

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "key": self.key,
            "title": self.title,
            "description": self.description,
            "pattern": self.pattern,
            "module_ids": list(self.module_ids),
            "target": self.target,
            "score": self.score,
            "level": self.level.value,
            "factors": [factor.to_dict() for factor in self.factors],
            "created_at": self.created_at.isoformat(timespec="seconds"),
            "last_seen": self.last_seen.isoformat(timespec="seconds"),
            "event_count": self.event_count,
            "evidence": [item.to_dict() for item in self.evidence],
            "alert_id": self.alert_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "ThreatFinding":
        if not isinstance(raw, dict):
            raise ValueError("finding is not an object")
        finding_id = _required_text(raw.get("id"), "finding id")
        score = _bounded_score(raw.get("score"))
        # The score is canonical: reload always classifies it consistently.
        from ssg8.security.analysis.risk import level_for_score

        level = level_for_score(score)

        factors: list[RiskFactor] = []
        for item in _list(raw.get("factors")):
            try:
                factors.append(RiskFactor.from_dict(item))
            except ValueError:
                continue

        evidence: list[FindingEvidence] = []
        for item in _list(raw.get("evidence")):
            try:
                evidence.append(FindingEvidence.from_dict(item))
            except ValueError:
                continue

        return cls(
            id=finding_id,
            key=_required_text(raw.get("key"), "finding key"),
            title=_required_text(raw.get("title"), "finding title"),
            description=str(raw.get("description", ""))[:1200],
            pattern=str(raw.get("pattern", "unknown"))[:40],
            module_ids=tuple(_text_list(raw.get("module_ids"))),
            target=str(raw.get("target", ""))[:260],
            score=score,
            level=level,
            factors=tuple(factors),
            created_at=_parse_timestamp(raw.get("created_at")),
            last_seen=_parse_timestamp(raw.get("last_seen")),
            event_count=max(0, _integer(raw.get("event_count"), 0)),
            evidence=tuple(evidence[-20:]),
            alert_id=str(raw.get("alert_id", ""))[:40],
        )


@dataclass(frozen=True, slots=True)
class SecurityAlert:
    """An alert generated from a real SSG8 analysis finding."""

    id: str
    title: str
    description: str
    level: RiskLevel
    score: int
    module_id: str
    target: str
    finding_id: str
    created_at: datetime
    updated_at: datetime
    status: AlertStatus = AlertStatus.NEW

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "level": self.level.value,
            "score": self.score,
            "module_id": self.module_id,
            "target": self.target,
            "finding_id": self.finding_id,
            "created_at": self.created_at.isoformat(timespec="seconds"),
            "updated_at": self.updated_at.isoformat(timespec="seconds"),
            "status": self.status.value,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "SecurityAlert":
        if not isinstance(raw, dict):
            raise ValueError("alert is not an object")
        score = _bounded_score(raw.get("score"))
        from ssg8.security.analysis.risk import level_for_score

        level = level_for_score(score)
        return cls(
            id=_required_text(raw.get("id"), "alert id"),
            title=_required_text(raw.get("title"), "alert title"),
            description=str(raw.get("description", ""))[:1200],
            level=level,
            score=score,
            module_id=str(raw.get("module_id", ""))[:40],
            target=str(raw.get("target", ""))[:260],
            finding_id=str(raw.get("finding_id", ""))[:40],
            created_at=_parse_timestamp(raw.get("created_at")),
            updated_at=_parse_timestamp(raw.get("updated_at")),
            status=AlertStatus(raw.get("status", AlertStatus.NEW.value)),
        )


@dataclass(frozen=True, slots=True)
class IncidentNote:
    """One timestamped investigation note."""

    timestamp: datetime
    text: str

    def to_dict(self) -> dict[str, str]:
        return {
            "timestamp": self.timestamp.isoformat(timespec="seconds"),
            "text": self.text,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "IncidentNote":
        if not isinstance(raw, dict):
            raise ValueError("incident note is not an object")
        return cls(
            timestamp=_parse_timestamp(raw.get("timestamp")),
            text=_required_text(raw.get("text"), "incident note"),
        )


@dataclass(frozen=True, slots=True)
class SecurityIncident:
    """Related findings and alerts grouped into one investigation record."""

    id: str
    group_key: str
    title: str
    summary: str
    level: RiskLevel
    score: int
    created_at: datetime
    updated_at: datetime
    alert_ids: tuple[str, ...]
    finding_ids: tuple[str, ...]
    module_ids: tuple[str, ...]
    status: IncidentStatus = IncidentStatus.OPEN
    notes: tuple[IncidentNote, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "group_key": self.group_key,
            "title": self.title,
            "summary": self.summary,
            "level": self.level.value,
            "score": self.score,
            "created_at": self.created_at.isoformat(timespec="seconds"),
            "updated_at": self.updated_at.isoformat(timespec="seconds"),
            "alert_ids": list(self.alert_ids),
            "finding_ids": list(self.finding_ids),
            "module_ids": list(self.module_ids),
            "status": self.status.value,
            "notes": [note.to_dict() for note in self.notes],
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "SecurityIncident":
        if not isinstance(raw, dict):
            raise ValueError("incident is not an object")
        score = _bounded_score(raw.get("score"))
        try:
            level = RiskLevel(raw.get("level"))
        except ValueError:
            from ssg8.security.analysis.risk import level_for_score

            level = level_for_score(score)
        notes: list[IncidentNote] = []
        for item in _list(raw.get("notes")):
            try:
                notes.append(IncidentNote.from_dict(item))
            except ValueError:
                continue
        return cls(
            id=_required_text(raw.get("id"), "incident id"),
            group_key=str(raw.get("group_key", raw.get("id", "")))[:300],
            title=_required_text(raw.get("title"), "incident title"),
            summary=str(raw.get("summary", ""))[:1600],
            level=level,
            score=score,
            created_at=_parse_timestamp(raw.get("created_at")),
            updated_at=_parse_timestamp(raw.get("updated_at")),
            alert_ids=tuple(_text_list(raw.get("alert_ids"))),
            finding_ids=tuple(_text_list(raw.get("finding_ids"))),
            module_ids=tuple(_text_list(raw.get("module_ids"))),
            status=IncidentStatus(raw.get("status", IncidentStatus.OPEN.value)),
            notes=tuple(notes[-100:]),
        )


# --- parsing helpers ---------------------------------------------------------


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp is not a string")
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("timestamp is invalid") from exc


def _required_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is missing")
    return value.strip()[:400]


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _text_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item)[:300] for item in value if isinstance(item, str) and item][:100]


def _bounded_score(value: Any) -> int:
    score = _integer(value, 0)
    return max(0, min(100, score))


def _integer(value: Any, default: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return default
