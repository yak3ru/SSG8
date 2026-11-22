"""Tests for the notification control engine."""

from __future__ import annotations

import pytest

from ssg8.core.app_state import NOTIFICATION_CATEGORIES
from ssg8.security.decisions import ProtectionAction
from ssg8.security.modules.notification_engine import NotificationEngine


@pytest.fixture
def engine() -> NotificationEngine:
    return NotificationEngine()


def categories(**overrides) -> dict[str, bool]:
    values = {key: True for key, _label in NOTIFICATION_CATEGORIES}
    values.update(overrides)
    return values


def test_master_enabled_category_enabled(engine) -> None:
    decision = engine.evaluate(
        "security_alerts",
        "Disk check complete",
        master_enabled=True,
        enabled_categories=categories(),
    )
    assert decision.action is ProtectionAction.ALLOW
    assert "enabled" in decision.reason


def test_master_disabled_blocks(engine) -> None:
    decision = engine.evaluate(
        "security_alerts",
        "Message",
        master_enabled=False,
        enabled_categories=categories(),
    )
    assert decision.action is ProtectionAction.BLOCK
    assert "Notification protection is disabled" in decision.reason


def test_category_disabled_blocks(engine) -> None:
    decision = engine.evaluate(
        "promotional",
        "Sale",
        master_enabled=True,
        enabled_categories=categories(promotional=False),
    )
    assert decision.action is ProtectionAction.BLOCK
    assert "Promotional Notifications" in decision.reason


def test_invalid_category_is_reviewed(engine) -> None:
    decision = engine.evaluate(
        "unknown_category",
        "Message",
        master_enabled=True,
        enabled_categories=categories(),
    )
    assert decision.action is ProtectionAction.REVIEW
    assert decision.metadata["policy"] == "invalid-category"


def test_category_list_matches_application_state() -> None:
    assert [key for key, _label in NOTIFICATION_CATEGORIES] == [
        "security_alerts",
        "system_warnings",
        "application_updates",
        "general",
        "promotional",
    ]
