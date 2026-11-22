"""Tests for the shared decision model."""

from __future__ import annotations

from datetime import datetime

import pytest

from ssg8.security.decisions import (
    ProtectionAction,
    ProtectionDecision,
    ProtectionRule,
    strongest_action,
)


def test_action_labels() -> None:
    assert ProtectionAction.ALLOW.label == "Allowed"
    assert ProtectionAction.BLOCK.label == "Blocked"
    assert ProtectionAction.REVIEW.label == "Requires review"


def test_strongest_action_priority() -> None:
    assert (
        strongest_action(
            (ProtectionAction.ALLOW, ProtectionAction.REVIEW, ProtectionAction.BLOCK)
        )
        is ProtectionAction.BLOCK
    )
    assert (
        strongest_action((ProtectionAction.ALLOW, ProtectionAction.REVIEW))
        is ProtectionAction.REVIEW
    )
    assert strongest_action((ProtectionAction.ALLOW,)) is ProtectionAction.ALLOW
    assert strongest_action(()) is None


def test_decision_fields_and_labels() -> None:
    rule = ProtectionRule("website_block", "example.com", ProtectionAction.BLOCK)
    decision = ProtectionDecision(
        action=ProtectionAction.BLOCK,
        module="Website Protection",
        target="https://example.com/",
        reason="Matched rule.",
        timestamp=datetime(2026, 1, 2, 3, 4, 5),
        rule=rule,
        metadata={"host": "example.com"},
    )
    assert decision.action_label == "Blocked"
    assert decision.rule_label == "example.com"
    assert decision.metadata["host"] == "example.com"


def test_decision_metadata_is_read_only() -> None:
    decision = ProtectionDecision(
        action=ProtectionAction.ALLOW,
        module="Download Protection",
        target="file.txt",
        reason="Allowed.",
        timestamp=datetime.now(),
        metadata={"name": "file.txt"},
    )
    with pytest.raises(TypeError):
        decision.metadata["name"] = "changed"  # type: ignore[index]


def test_decision_without_rule() -> None:
    decision = ProtectionDecision(
        action=ProtectionAction.REVIEW,
        module="Application Control",
        target="Tool",
        reason="No rule.",
        timestamp=datetime.now(),
    )
    assert decision.rule is None
    assert decision.rule_label == "No rule matched"
