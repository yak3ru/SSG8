"""Tests for the application control engine."""

from __future__ import annotations

import pytest

from ssg8.security.decisions import ProtectionAction
from ssg8.security.modules.application_engine import (
    ApplicationEngine,
    normalise_executable_path,
)


@pytest.fixture
def engine() -> ApplicationEngine:
    return ApplicationEngine()


def test_block_rule_by_name(engine, application_rule) -> None:
    decision = engine.evaluate(
        "Calculator", None, [application_rule("Calculator", policy="block")]
    )
    assert decision.action is ProtectionAction.BLOCK
    assert "matches an active block rule" in decision.reason


def test_allow_rule_by_name(engine, application_rule) -> None:
    decision = engine.evaluate(
        "Calculator", None, [application_rule("Calculator", policy="allow")]
    )
    assert decision.action is ProtectionAction.ALLOW
    assert "matches an active allow rule" in decision.reason


def test_block_wins_over_allow(engine, application_rule) -> None:
    rules = [
        application_rule("Tool", policy="allow"),
        application_rule("Tool", policy="block"),
    ]
    decision = engine.evaluate("Tool", None, rules)
    assert decision.action is ProtectionAction.BLOCK
    assert "block rules take priority" in decision.reason


def test_path_rule_matches_normalised_path(engine, application_rule) -> None:
    rules = [
        application_rule(
            "Calculator", r"C:\Windows\System32\calc.exe", policy="block"
        )
    ]
    decision = engine.evaluate("Calculator", r"c:/windows/system32/calc.exe", rules)
    assert decision.action is ProtectionAction.BLOCK


def test_path_rule_requires_the_path(engine, application_rule) -> None:
    rules = [
        application_rule(
            "Calculator", r"C:\Windows\System32\calc.exe", policy="block"
        )
    ]
    decision = engine.evaluate("Calculator", None, rules)
    assert decision.action is ProtectionAction.REVIEW
    assert decision.metadata["policy"] == "unmatched"


def test_different_path_does_not_match(engine, application_rule) -> None:
    rules = [
        application_rule("Tool", r"C:\Apps\Tool.exe", policy="block")
    ]
    decision = engine.evaluate("Tool", r"D:\Other\Tool.exe", rules)
    assert decision.action is ProtectionAction.REVIEW


def test_similar_name_does_not_match(engine, application_rule) -> None:
    rules = [application_rule("Calculator", policy="block")]
    decision = engine.evaluate("CalculatorPro", None, rules)
    assert decision.action is ProtectionAction.REVIEW


def test_unlisted_application_requires_review(engine) -> None:
    decision = engine.evaluate("UnknownApp", None, [])
    assert decision.action is ProtectionAction.REVIEW
    assert decision.metadata["policy"] == "unmatched"


@pytest.mark.parametrize("name", ["", "   ", None, 42])
def test_invalid_name_is_reviewed(engine, name) -> None:
    decision = engine.evaluate(name, None, [])
    assert decision.action is ProtectionAction.REVIEW
    assert decision.metadata["policy"] == "invalid-input"


def test_executable_path_normalisation() -> None:
    assert normalise_executable_path('"C:\\Apps\\Tool.exe"') == normalise_executable_path(
        "c:/apps/tool.exe"
    )
    assert normalise_executable_path("   ") == ""
