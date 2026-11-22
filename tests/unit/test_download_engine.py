"""Tests for the download protection engine."""

from __future__ import annotations

import hashlib

import pytest

from ssg8.security.decisions import ProtectionAction
from ssg8.security.modules import download_engine
from ssg8.security.modules.download_engine import DownloadEngine
from ssg8.security.policies import ProtectionSettings


def engine(**overrides) -> DownloadEngine:
    settings = ProtectionSettings(**overrides)
    return DownloadEngine(lambda: settings)


def test_ordinary_file_is_allowed(tmp_path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("hello world", encoding="utf-8")

    decision = engine().evaluate(str(path))

    assert decision.action is ProtectionAction.ALLOW
    assert decision.metadata["extension"] == ".txt"
    assert len(decision.metadata["sha256"]) == 64
    assert decision.metadata["size_bytes"] == "11"


def test_sha256_matches_hashlib(tmp_path) -> None:
    path = tmp_path / "data.csv"
    path.write_bytes(b"a,b\n1,2\n")

    decision = engine().evaluate(str(path))

    assert decision.metadata["sha256"] == hashlib.sha256(b"a,b\n1,2\n").hexdigest()


def test_hash_is_consistent_between_inspections(tmp_path) -> None:
    path = tmp_path / "file.txt"
    path.write_text("same content", encoding="utf-8")
    downloader = engine()

    first = downloader.evaluate(str(path))
    second = downloader.evaluate(str(path))

    assert first.metadata["sha256"] == second.metadata["sha256"]


def test_inspection_does_not_modify_the_file(tmp_path) -> None:
    path = tmp_path / "untouched.txt"
    path.write_text("content", encoding="utf-8")
    before = (path.read_bytes(), path.stat().st_mtime_ns)

    engine().evaluate(str(path))

    after = (path.read_bytes(), path.stat().st_mtime_ns)
    assert before == after


def test_prohibited_extension_is_blocked(tmp_path) -> None:
    path = tmp_path / "installer.exe"
    path.write_bytes(b"MZ")

    decision = engine().evaluate(str(path))

    assert decision.action is ProtectionAction.BLOCK
    assert decision.metadata["policy"] == "blocked-extension"
    assert decision.rule is not None


def test_unknown_extension_defaults_to_review(tmp_path) -> None:
    path = tmp_path / "payload.zzz"
    path.write_text("data", encoding="utf-8")

    decision = engine().evaluate(str(path))

    assert decision.action is ProtectionAction.REVIEW
    assert "unknown" in decision.reason.lower()


def test_unknown_extension_can_be_allowed(tmp_path) -> None:
    path = tmp_path / "payload.zzz"
    path.write_text("data", encoding="utf-8")

    decision = engine(unknown_file_action="allow").evaluate(str(path))

    assert decision.action is ProtectionAction.ALLOW


def test_unknown_extension_can_be_blocked(tmp_path) -> None:
    path = tmp_path / "payload.zzz"
    path.write_text("data", encoding="utf-8")

    decision = engine(unknown_file_action="block").evaluate(str(path))

    assert decision.action is ProtectionAction.BLOCK


def test_oversized_file_requires_review(tmp_path) -> None:
    path = tmp_path / "large.bin"
    path.write_bytes(b"x" * (1024 * 1024 + 10))

    decision = engine(max_file_size_mb=1).evaluate(str(path))

    assert decision.action is ProtectionAction.REVIEW
    assert decision.metadata["policy"] == "oversized"
    assert decision.metadata["sha256"] == "not computed (over the size limit)"


def test_missing_file_requires_review(tmp_path) -> None:
    decision = engine().evaluate(str(tmp_path / "missing.txt"))

    assert decision.action is ProtectionAction.REVIEW
    assert decision.metadata["policy"] == "invalid-target"


def test_directory_is_rejected(tmp_path) -> None:
    decision = engine().evaluate(str(tmp_path))

    assert decision.action is ProtectionAction.REVIEW
    assert "folder" in decision.reason


def test_blank_path_is_rejected() -> None:
    decision = engine().evaluate("   ")

    assert decision.action is ProtectionAction.REVIEW
    assert decision.metadata["policy"] == "invalid-input"


def test_permission_error_is_reviewed(tmp_path, monkeypatch) -> None:
    path = tmp_path / "locked.txt"
    path.write_text("data", encoding="utf-8")

    def deny(_path):
        raise PermissionError("access denied")

    monkeypatch.setattr(download_engine, "_sha256", deny)

    decision = engine().evaluate(str(path))

    assert decision.action is ProtectionAction.REVIEW
    assert "could not be read" in decision.reason
    assert decision.metadata["policy"] == "filesystem-error"


@pytest.mark.parametrize("extension", [".BAT", ".Ps1", ".scr"])
def test_prohibited_extension_is_case_insensitive(tmp_path, extension: str) -> None:
    path = tmp_path / f"danger{extension}"
    path.write_text("data", encoding="utf-8")

    decision = engine().evaluate(str(path))

    assert decision.action is ProtectionAction.BLOCK
