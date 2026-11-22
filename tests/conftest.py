"""Shared pytest setup for the SSG8 test suite."""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import pytest  # noqa: E402

from ssg8.core.models import ApplicationEntry, WebsiteEntry  # noqa: E402
from ssg8.security.policies import ProtectionSettings  # noqa: E402


@pytest.fixture
def app_context(tmp_path):
    """A fully wired context with isolated JSON storage."""
    from ssg8.core.context import build_context
    from ssg8.storage.preferences import Preferences
    from ssg8.storage.protection_store import ProtectionStore

    return build_context(
        Preferences(tmp_path / "preferences.json"),
        ProtectionStore(tmp_path / "data"),
    )


@pytest.fixture
def website_rule():
    def make(domain: str, list_type: str = "block") -> WebsiteEntry:
        return WebsiteEntry(domain=domain, added=datetime.now(), list_type=list_type)

    return make


@pytest.fixture
def application_rule():
    def make(name: str, path: str = "", policy: str = "block") -> ApplicationEntry:
        return ApplicationEntry(
            name=name, path=path, added=datetime.now(), policy=policy
        )

    return make


@pytest.fixture
def settings_factory():
    def make(**overrides) -> ProtectionSettings:
        return ProtectionSettings(**overrides)

    return make
