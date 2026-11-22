"""Tests for protection rule and settings persistence."""

from __future__ import annotations

import json
from datetime import datetime

from ssg8.core.models import ApplicationEntry, WebsiteEntry
from ssg8.security.policies import ProtectionSettings
from ssg8.storage.protection_store import ProtectionStore


def website(domain: str, list_type: str = "block") -> WebsiteEntry:
    return WebsiteEntry(domain=domain, added=datetime(2026, 5, 4, 12, 30), list_type=list_type)


def application(name: str, path: str = "", policy: str = "block") -> ApplicationEntry:
    return ApplicationEntry(
        name=name, path=path, added=datetime(2026, 5, 4, 12, 30), policy=policy
    )


def test_website_rules_round_trip(tmp_path) -> None:
    store = ProtectionStore(tmp_path)
    entries = [website("example.com"), website("trusted.test", "allow")]

    assert store.save_websites(entries)
    loaded = store.load_websites()

    assert [(e.domain, e.list_type) for e in loaded] == [
        ("example.com", "block"),
        ("trusted.test", "allow"),
    ]
    assert loaded[0].added == datetime(2026, 5, 4, 12, 30)


def test_application_rules_round_trip(tmp_path) -> None:
    store = ProtectionStore(tmp_path)
    entries = [application("Tool", r"C:\Apps\tool.exe", "block"), application("Nameonly")]

    assert store.save_applications(entries)
    loaded = store.load_applications()

    assert [(e.name, e.path, e.policy) for e in loaded] == [
        ("Tool", r"C:\Apps\tool.exe", "block"),
        ("Nameonly", "", "block"),
    ]


def test_settings_round_trip(tmp_path) -> None:
    store = ProtectionStore(tmp_path)
    settings = ProtectionSettings(
        max_file_size_mb=32,
        subdomain_matching="exact",
        unknown_file_action="block",
        blocked_extensions=(".exe", ".ps1"),
    )

    assert store.save_settings(settings)
    loaded = store.load_settings()

    assert loaded == settings


def test_missing_files_use_defaults(tmp_path) -> None:
    store = ProtectionStore(tmp_path / "nothing")

    assert store.load_websites() == []
    assert store.load_applications() == []
    assert store.load_settings() == ProtectionSettings()
    assert store.errors() == ()


def test_corrupted_website_json_is_safe(tmp_path) -> None:
    store = ProtectionStore(tmp_path)
    store.website_path.write_text("{ this is not json", encoding="utf-8")

    assert store.load_websites() == []
    assert any("website rules" in error for error in store.errors())


def test_corrupted_settings_json_is_safe(tmp_path) -> None:
    store = ProtectionStore(tmp_path)
    store.settings_path.write_text("[1, 2, 3]", encoding="utf-8")

    assert store.load_settings() == ProtectionSettings()
    assert store.errors()


def test_invalid_website_entries_are_skipped(tmp_path) -> None:
    store = ProtectionStore(tmp_path)
    payload = [
        {"domain": "good.example", "list_type": "block", "added": "2026-01-01T00:00:00"},
        {"domain": "bad domain", "list_type": "block"},
        {"domain": "other.example", "list_type": "sideways"},
        "not-an-object",
    ]
    store.website_path.write_text(json.dumps(payload), encoding="utf-8")

    loaded = store.load_websites()

    assert [entry.domain for entry in loaded] == ["good.example"]
    assert len(store.errors()) == 3


def test_invalid_application_entries_are_skipped(tmp_path) -> None:
    store = ProtectionStore(tmp_path)
    payload = [
        {"name": "Good", "path": "", "policy": "allow"},
        {"name": "", "path": "", "policy": "block"},
        {"name": "Bad", "path": "", "policy": "maybe"},
    ]
    store.application_path.write_text(json.dumps(payload), encoding="utf-8")

    loaded = store.load_applications()

    assert [entry.name for entry in loaded] == ["Good"]
    assert len(store.errors()) == 2


def test_duplicate_persisted_rules_are_collapsed(tmp_path) -> None:
    store = ProtectionStore(tmp_path)
    payload = [
        {"domain": "dupe.example", "list_type": "block"},
        {"domain": "dupe.example", "list_type": "block"},
    ]
    store.website_path.write_text(json.dumps(payload), encoding="utf-8")

    assert len(store.load_websites()) == 1


def test_atomic_write_leaves_no_temporary_file(tmp_path) -> None:
    store = ProtectionStore(tmp_path)
    store.save_websites([website("example.com")])

    assert not list(tmp_path.glob("*.tmp"))
    assert store.website_path.exists()


def test_invalid_settings_fields_fall_back(tmp_path) -> None:
    store = ProtectionStore(tmp_path)
    payload = {
        "max_file_size_mb": "enormous",
        "subdomain_matching": "sometimes",
        "unknown_file_action": "guess",
        "blocked_extensions": [".exe", "not valid!"],
    }
    store.settings_path.write_text(json.dumps(payload), encoding="utf-8")

    loaded = store.load_settings()

    assert loaded == ProtectionSettings()
    assert len(store.errors()) >= 4


def test_store_errors_do_not_raise(tmp_path) -> None:
    store = ProtectionStore(tmp_path)
    store.application_path.write_text("null", encoding="utf-8")
    assert store.load_applications() == []
