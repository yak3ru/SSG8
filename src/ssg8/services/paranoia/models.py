"""Data models for the paranoia progression and self-audit demonstration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping

from ssg8.core.models import Severity
from ssg8.security.decisions import ProtectionAction
from ssg8.services.paranoia.states import ParanoiaState


@dataclass(frozen=True, slots=True)
class ParanoiaSettings:
    """Configurable scoring weights and demonstration acceleration."""

    point_overrides: Mapping[str, int] = field(default_factory=dict)
    demo_acceleration: int = 3

    def __post_init__(self) -> None:
        clean: dict[str, int] = {}
        for key, value in dict(self.point_overrides).items():
            try:
                points = int(value)
            except (TypeError, ValueError):
                continue
            if str(key).strip() and points >= 0:
                clean[str(key)] = points
        object.__setattr__(self, "point_overrides", MappingProxyType(clean))
        object.__setattr__(
            self, "demo_acceleration", max(1, min(10, int(self.demo_acceleration)))
        )

    def with_updates(
        self,
        *,
        point_overrides: Mapping[str, int] | None = None,
        demo_acceleration: int | None = None,
    ) -> "ParanoiaSettings":
        return ParanoiaSettings(
            point_overrides=(
                point_overrides
                if point_overrides is not None
                else dict(self.point_overrides)
            ),
            demo_acceleration=(
                demo_acceleration
                if demo_acceleration is not None
                else self.demo_acceleration
            ),
        )


@dataclass(frozen=True, slots=True)
class ParanoiaEvent:
    """One paranoia score change, restriction or notable demonstration event."""

    timestamp: datetime
    category: str
    severity: Severity
    description: str
    reason: str = ""
    source: str = "CyberLockdown"
    previous_state: str = ""
    new_state: str = ""
    activity: str = ""
    delta: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(timespec="seconds"),
            "category": self.category,
            "severity": self.severity.value,
            "description": self.description,
            "reason": self.reason,
            "source": self.source,
            "previous_state": self.previous_state,
            "new_state": self.new_state,
            "activity": self.activity,
            "delta": self.delta,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "ParanoiaEvent":
        if not isinstance(raw, dict):
            raise ValueError("paranoia event is not an object")
        return cls(
            timestamp=_timestamp(raw.get("timestamp")),
            category=str(raw.get("category", "Paranoia"))[:60],
            severity=_severity(raw.get("severity")),
            description=str(raw.get("description", ""))[:800],
            reason=str(raw.get("reason", ""))[:800],
            source=str(raw.get("source", "CyberLockdown"))[:80],
            previous_state=str(raw.get("previous_state", ""))[:40],
            new_state=str(raw.get("new_state", ""))[:40],
            activity=str(raw.get("activity", ""))[:60],
            delta=_integer(raw.get("delta"), 0),
        )


@dataclass(frozen=True, slots=True)
class ParanoiaTransition:
    """One validated state transition in the progression."""

    timestamp: datetime
    previous_state: ParanoiaState
    new_state: ParanoiaState
    reason: str
    score: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(timespec="seconds"),
            "previous_state": self.previous_state.value,
            "new_state": self.new_state.value,
            "reason": self.reason,
            "score": self.score,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "ParanoiaTransition":
        if not isinstance(raw, dict):
            raise ValueError("paranoia transition is not an object")
        previous = _state(raw.get("previous_state"))
        target = _state(raw.get("new_state"))
        return cls(
            timestamp=_timestamp(raw.get("timestamp")),
            previous_state=previous,
            new_state=target,
            reason=str(raw.get("reason", ""))[:800],
            score=_score(raw.get("score")),
        )


@dataclass(frozen=True, slots=True)
class RestrictionRecord:
    """A demonstration request that the paranoia profile escalated."""

    timestamp: datetime
    module: str
    target: str
    original_action: ProtectionAction
    applied_action: ProtectionAction
    reason: str
    state: ParanoiaState
    activity_key: str = ""

    @property
    def is_block(self) -> bool:
        return self.applied_action is ProtectionAction.BLOCK


@dataclass(frozen=True, slots=True)
class AuditRow:
    """One category in a self-audit report."""

    category: str
    result: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"category": self.category, "result": self.result, "detail": self.detail}

    @classmethod
    def from_dict(cls, raw: Any) -> "AuditRow":
        if not isinstance(raw, dict):
            raise ValueError("audit row is not an object")
        return cls(
            category=str(raw.get("category", ""))[:120],
            result=str(raw.get("result", ""))[:80],
            detail=str(raw.get("detail", ""))[:600],
        )


@dataclass(frozen=True, slots=True)
class AuditReport:
    """A deterministic audit of CyberLockdown's own recorded behaviour."""

    id: str
    timestamp: datetime
    score: int
    state: ParanoiaState
    rows: tuple[AuditRow, ...]
    summary: str
    legitimate_blocked: int
    restrictions_applied: int
    activities_monitored: int
    monitoring_enabled: bool
    has_violations: bool
    finding_id: str = ""

    @property
    def compliance_result(self) -> str:
        return "Failed" if self.has_violations else "Passed"

    def row(self, category: str) -> AuditRow | None:
        return next((row for row in self.rows if row.category == category), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(timespec="seconds"),
            "score": self.score,
            "state": self.state.value,
            "rows": [row.to_dict() for row in self.rows],
            "summary": self.summary,
            "legitimate_blocked": self.legitimate_blocked,
            "restrictions_applied": self.restrictions_applied,
            "activities_monitored": self.activities_monitored,
            "monitoring_enabled": self.monitoring_enabled,
            "has_violations": self.has_violations,
            "finding_id": self.finding_id,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> "AuditReport":
        if not isinstance(raw, dict):
            raise ValueError("audit report is not an object")
        rows: list[AuditRow] = []
        for item in raw.get("rows", []) if isinstance(raw.get("rows"), list) else []:
            try:
                rows.append(AuditRow.from_dict(item))
            except ValueError:
                continue
        return cls(
            id=str(raw.get("id", "AUD-0000"))[:40],
            timestamp=_timestamp(raw.get("timestamp")),
            score=_score(raw.get("score")),
            state=_state(raw.get("state")),
            rows=tuple(rows),
            summary=str(raw.get("summary", ""))[:1600],
            legitimate_blocked=_integer(raw.get("legitimate_blocked"), 0),
            restrictions_applied=_integer(raw.get("restrictions_applied"), 0),
            activities_monitored=_integer(raw.get("activities_monitored"), 0),
            monitoring_enabled=bool(raw.get("monitoring_enabled", False)),
            has_violations=bool(raw.get("has_violations", False)),
            finding_id=str(raw.get("finding_id", ""))[:40],
        )


@dataclass(frozen=True, slots=True)
class RecoveryAction:
    """One restoration step performed during quarantine or recovery."""

    timestamp: datetime
    action: str
    detail: str = ""
    restored: bool = True


# --- parsing helpers ---------------------------------------------------------


def _timestamp(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    raise ValueError("paranoia timestamp is invalid")


def _state(value: Any) -> ParanoiaState:
    try:
        return ParanoiaState(value)
    except ValueError as exc:
        raise ValueError(f"unknown paranoia state: {value!r}") from exc


def _severity(value: Any) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.INFO


def _score(value: Any) -> int:
    return max(0, min(100, _integer(value, 0)))


def _integer(value: Any, default: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return default
