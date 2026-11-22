"""Tests for the website protection engine."""

from __future__ import annotations

import pytest

from ssg8.security.decisions import ProtectionAction
from ssg8.security.modules.website_engine import WebsiteEngine, domain_matches
from ssg8.security.policies import (
    SUBDOMAIN_EXACT,
    SUBDOMAIN_INCLUDE,
    ProtectionSettings,
)


def engine(mode: str = SUBDOMAIN_INCLUDE) -> WebsiteEngine:
    return WebsiteEngine(lambda: ProtectionSettings(subdomain_matching=mode))


def test_exact_domain_block(website_rule) -> None:
    decision = engine().evaluate(
        "https://example.com/login", [website_rule("example.com")], []
    )
    assert decision.action is ProtectionAction.BLOCK
    assert "matches an active block rule" in decision.reason
    assert decision.metadata["host"] == "example.com"


def test_subdomain_matches_when_enabled(website_rule) -> None:
    decision = engine(SUBDOMAIN_INCLUDE).evaluate(
        "https://login.example.com/", [website_rule("example.com")], []
    )
    assert decision.action is ProtectionAction.BLOCK


def test_subdomain_does_not_match_exact_policy(website_rule) -> None:
    decision = engine(SUBDOMAIN_EXACT).evaluate(
        "https://login.example.com/", [website_rule("example.com")], []
    )
    assert decision.action is ProtectionAction.ALLOW


@pytest.mark.parametrize(
    "host",
    ["notexample.com", "example.com.evil.test", "example.org", "example.co"],
)
def test_similar_domains_do_not_match(host: str, website_rule) -> None:
    decision = engine().evaluate(
        f"https://{host}/", [website_rule("example.com")], []
    )
    assert decision.action is ProtectionAction.ALLOW


@pytest.mark.parametrize("host", ["example.com", "sub.example.com"])
def test_domain_matches_helper(host: str) -> None:
    assert domain_matches(host, "example.com", True)


@pytest.mark.parametrize(
    "host", ["notexample.com", "example.com.evil.test", "example.com.au"]
)
def test_domain_matches_helper_rejects_suffix_tricks(host: str) -> None:
    assert not domain_matches(host, "example.com", True)


def test_allow_rule(website_rule) -> None:
    decision = engine().evaluate(
        "https://trusted.example.org/", [], [website_rule("trusted.example.org", "allow")]
    )
    assert decision.action is ProtectionAction.ALLOW
    assert "matches an active allow rule" in decision.reason


def test_block_wins_over_allow(website_rule) -> None:
    decision = engine().evaluate(
        "https://example.com/",
        [website_rule("example.com")],
        [website_rule("example.com", "allow")],
    )
    assert decision.action is ProtectionAction.BLOCK
    assert "block rules take priority" in decision.reason


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "not a url",
        "ftp://example.com/file",
        "https://exa mple.com/",
    ],
)
def test_invalid_urls_are_reviewed(url: str, website_rule) -> None:
    decision = engine().evaluate(url, [website_rule("example.com")], [])
    assert decision.action is ProtectionAction.REVIEW
    assert decision.metadata["policy"] == "invalid-input"


def test_url_is_normalised_for_matching(website_rule) -> None:
    decision = engine().evaluate(
        "HTTPS://EXAMPLE.COM./Login", [website_rule("example.com")], []
    )
    assert decision.action is ProtectionAction.BLOCK
    assert decision.metadata["host"] == "example.com"


def test_bare_host_is_accepted(website_rule) -> None:
    decision = engine().evaluate(
        "example.com/login", [website_rule("example.com")], []
    )
    assert decision.action is ProtectionAction.BLOCK


def test_internationalised_domain(website_rule) -> None:
    decision = engine().evaluate(
        "https://xn--mnich-kva.example/", [website_rule("xn--mnich-kva.example")], []
    )
    assert decision.action is ProtectionAction.BLOCK


def test_unlisted_domain_is_allowed_by_default() -> None:
    decision = engine().evaluate("https://unknown.test/", [], [])
    assert decision.action is ProtectionAction.ALLOW
    assert decision.metadata["policy"] == "default"
