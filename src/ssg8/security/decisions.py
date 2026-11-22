"""Structured decisions produced by the internal protection engines.

A decision describes what SSG8 decided about a request submitted to the
application. It never describes the state of Windows: no rule here blocks a
website, a process or a notification outside SSG8.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from types import MappingProxyType
from typing import Mapping


class ProtectionAction(str, Enum):
    """The outcome of one protection evaluation."""

    ALLOW = "allow"
    BLOCK = "block"
    REVIEW = "review"

    @property
    def label(self) -> str:
        return _ACTION_LABELS[self]


_ACTION_LABELS: dict[ProtectionAction, str] = {
    ProtectionAction.ALLOW: "Allowed",
    ProtectionAction.BLOCK: "Blocked",
    ProtectionAction.REVIEW: "Requires review",
}

# Block outranks review, which outranks allow. Used when several rules match.
_ACTION_RANK: dict[ProtectionAction, int] = {
    ProtectionAction.ALLOW: 0,
    ProtectionAction.REVIEW: 1,
    ProtectionAction.BLOCK: 2,
}


def strongest_action(actions: tuple[ProtectionAction, ...]) -> ProtectionAction | None:
    """Return the most restrictive action, or ``None`` for an empty sequence."""
    if not actions:
        return None
    return max(actions, key=lambda action: _ACTION_RANK[action])


@dataclass(frozen=True, slots=True)
class ProtectionRule:
    """A rule that matched a request."""

    kind: str
    value: str
    action: ProtectionAction
    detail: str = ""

    def describe(self) -> str:
        return self.detail or self.value


@dataclass(frozen=True, slots=True)
class ProtectionDecision:
    """One evaluation result shared by every protection module."""

    action: ProtectionAction
    module: str
    target: str
    reason: str
    timestamp: datetime
    rule: ProtectionRule | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Freeze the metadata mapping so callers cannot alter a past decision.
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    @property
    def action_label(self) -> str:
        return self.action.label

    @property
    def rule_label(self) -> str:
        return self.rule.describe() if self.rule is not None else "No rule matched"
