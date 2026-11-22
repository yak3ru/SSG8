"""Shared interface for the internal protection modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Mapping

from ssg8.security.decisions import (
    ProtectionAction,
    ProtectionDecision,
    ProtectionRule,
)


class ProtectionError(Exception):
    """Raised when a protection module cannot evaluate a request."""


class ProtectionModule(ABC):
    """Read-only evaluator that turns one request into a decision.

    Enablement is owned by :class:`~ssg8.security.protection_manager.ProtectionManager`
    so that every module can be switched off independently without losing its
    configuration.
    """

    module_id: str = ""
    label: str = ""

    def decision(
        self,
        action: ProtectionAction,
        target: str,
        reason: str,
        *,
        rule: ProtectionRule | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> ProtectionDecision:
        return ProtectionDecision(
            action=action,
            module=self.label,
            target=target,
            reason=reason,
            timestamp=datetime.now(),
            rule=rule,
            metadata=metadata or {},
        )

    @abstractmethod
    def evaluate(self, *args, **kwargs) -> ProtectionDecision:
        """Evaluate one request. Implemented by each module."""
