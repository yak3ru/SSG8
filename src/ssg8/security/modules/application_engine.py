"""Application control engine: evaluates launches requested inside SSG8.

This module never enumerates processes, never terminates anything and never
changes Windows policies or executable permissions.
"""

from __future__ import annotations

import ntpath
from collections.abc import Sequence

from ssg8.core.models import ApplicationEntry
from ssg8.security.decisions import ProtectionAction, ProtectionRule
from ssg8.security.engine import ProtectionModule

ALLOW = "allow"
BLOCK = "block"


def normalise_executable_path(value: str) -> str:
    """Return a comparable form of an executable path.

    Surrounding quotes and whitespace are removed, then the path is normalised
    for Windows consistently, even when tests run on Linux, so ``C:\\Apps\\Tool.exe`` and
    ``c:/apps/tool.exe`` compare equal on Windows.
    """
    cleaned = value.strip().strip('"').strip("'").strip()
    if not cleaned:
        return ""
    return ntpath.normcase(ntpath.normpath(cleaned))


class ApplicationEngine(ProtectionModule):
    """Evaluate an application request against allow and block rules."""

    module_id = "application"
    label = "Application Control"

    def evaluate(
        self,
        name: str,
        executable_path: str | None,
        rules: Sequence[ApplicationEntry],
    ):
        if not isinstance(name, str) or not name.strip():
            return self.decision(
                ProtectionAction.REVIEW,
                target=name if isinstance(name, str) else "",
                reason="Enter an application name to evaluate.",
                metadata={"policy": "invalid-input"},
            )

        requested_name = name.strip()
        raw_path = executable_path if isinstance(executable_path, str) else ""
        requested_path = normalise_executable_path(raw_path)

        blocked: ApplicationEntry | None = None
        allowed: ApplicationEntry | None = None
        for rule in rules:
            if not self._rule_matches(rule, requested_name, requested_path):
                continue
            if rule.policy == BLOCK and blocked is None:
                blocked = rule
            elif rule.policy == ALLOW and allowed is None:
                allowed = rule

        metadata = {
            "requested_name": requested_name,
            "requested_path": requested_path or "not provided",
        }

        if blocked is not None and allowed is not None:
            metadata["policy"] = "block-over-allow"
            return self.decision(
                ProtectionAction.BLOCK,
                target=requested_name,
                reason=(
                    "The application matches both a block and an allow rule; "
                    "block rules take priority."
                ),
                rule=self._rule(blocked),
                metadata=metadata,
            )

        if blocked is not None:
            metadata["policy"] = "blocklist"
            return self.decision(
                ProtectionAction.BLOCK,
                target=requested_name,
                reason=f"Application matches an active block rule ({blocked.name}).",
                rule=self._rule(blocked),
                metadata=metadata,
            )

        if allowed is not None:
            metadata["policy"] = "allowlist"
            return self.decision(
                ProtectionAction.ALLOW,
                target=requested_name,
                reason=f"Application matches an active allow rule ({allowed.name}).",
                rule=self._rule(allowed),
                metadata=metadata,
            )

        metadata["policy"] = "unmatched"
        reason = "No application rule matches this request."
        if raw_path.strip():
            reason += " The executable path is not covered by any rule."
        return self.decision(
            ProtectionAction.REVIEW,
            target=requested_name,
            reason=reason,
            metadata=metadata,
        )

    @staticmethod
    def _rule(entry: ApplicationEntry) -> ProtectionRule:
        action = (
            ProtectionAction.BLOCK if entry.policy == BLOCK else ProtectionAction.ALLOW
        )
        detail = f"{entry.policy.title()} rule: {entry.name}"
        if entry.path:
            detail += f" ({entry.path})"
        return ProtectionRule(
            f"application_{entry.policy}", entry.path or entry.name, action, detail
        )

    @staticmethod
    def _rule_matches(
        rule: ApplicationEntry, requested_name: str, requested_path: str
    ) -> bool:
        if rule.path:
            # A path-specific rule matches only an identical, provided path.
            return bool(requested_path) and (
                normalise_executable_path(rule.path) == requested_path
            )
        # A name-only rule matches the exact application name.
        return rule.name.casefold() == requested_name.casefold()
