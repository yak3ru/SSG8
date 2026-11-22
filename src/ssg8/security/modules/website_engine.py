"""Website protection engine: evaluates URLs against internal rules.

Only URLs submitted to SSG8 are evaluated. Nothing here touches the Windows
hosts file, DNS, browsers, proxies or network traffic.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from urllib.parse import urlsplit

from ssg8.core.models import WebsiteEntry
from ssg8.security.decisions import ProtectionAction, ProtectionRule
from ssg8.security.engine import ProtectionModule
from ssg8.security.policies import SUBDOMAIN_EXACT, ProtectionSettings

ALLOWED_SCHEMES = frozenset({"http", "https"})
_LABEL_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def normalise_host(host: str) -> str:
    """Lower-case ``host``, strip a trailing dot and encode IDN safely."""
    value = host.strip().lower().rstrip(".")
    if ":" in value:  # IPv6 literal: no IDNA encoding.
        return value
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("the host name is not a valid international domain") from exc


def is_valid_host(host: str) -> bool:
    """Return ``True`` when ``host`` is a syntactically valid domain name."""
    if not host or len(host) > 253:
        return False
    if host.startswith("[") or ":" in host:
        return True  # IPv6 literal accepted for exact matching only.
    return all(_LABEL_PATTERN.match(label) for label in host.split("."))


def parse_url(value: str) -> tuple[str, str, str | None]:
    """Return ``(host, full_url, error)`` for a user supplied URL.

    A bare host such as ``example.com/login`` is accepted and treated as
    HTTPS. The scheme is restricted to HTTP and HTTPS.
    """
    if not isinstance(value, str):
        return "", "", "The target must be text."
    text = value.strip()
    if not text:
        return "", "", "Enter a website URL to evaluate."
    if any(character.isspace() or ord(character) < 32 for character in text):
        return "", "", "The URL contains spaces or control characters."

    candidate = text if "://" in text else f"https://{text}"
    try:
        parsed = urlsplit(candidate)
        port = parsed.port  # noqa: F841 - validates a malformed port
    except ValueError as exc:
        return "", "", f"The URL is malformed: {exc}"

    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return "", "", "Only http:// and https:// URLs can be evaluated."
    if not parsed.hostname:
        return "", "", "The URL does not contain a host name."

    try:
        host = normalise_host(parsed.hostname)
    except ValueError as exc:
        return "", "", f"The URL host is invalid: {exc}"
    if not is_valid_host(host):
        return "", "", "The URL host is not a valid domain name."

    return host, text, None


def domain_matches(host: str, rule_domain: str, include_subdomains: bool) -> bool:
    """Match ``host`` against one rule domain without substring surprises.

    ``example.com.evil.test`` and ``notexample.com`` never match the rule
    ``example.com``. Subdomains match only when the policy allows it.
    """
    host = host.casefold().rstrip(".")
    rule = rule_domain.casefold().rstrip(".")
    if not host or not rule:
        return False
    if host == rule:
        return True
    return include_subdomains and host.endswith(f".{rule}")


class WebsiteEngine(ProtectionModule):
    """Evaluate an internal URL request against block and allow rules."""

    module_id = "website"
    label = "Website Protection"

    def __init__(self, settings_provider: Callable[[], ProtectionSettings]) -> None:
        self._settings_provider = settings_provider

    def evaluate(
        self,
        url: str,
        block_rules: Sequence[WebsiteEntry],
        allow_rules: Sequence[WebsiteEntry],
    ):
        host, target, error = parse_url(url)
        if error:
            return self.decision(
                ProtectionAction.REVIEW,
                target=str(url).strip() if isinstance(url, str) else "",
                reason=error,
                metadata={"policy": "invalid-input"},
            )

        include_subdomains = (
            self._settings_provider().subdomain_matching != SUBDOMAIN_EXACT
        )

        blocked = self._first_match(host, block_rules, include_subdomains)
        allowed = self._first_match(host, allow_rules, include_subdomains)

        if blocked is not None and allowed is not None:
            return self.decision(
                ProtectionAction.BLOCK,
                target,
                reason=(
                    f"Domain {host} matches both a block and an allow rule; "
                    "block rules take priority."
                ),
                rule=ProtectionRule(
                    "website_block", blocked.domain, ProtectionAction.BLOCK,
                    f"Block rule: {blocked.domain}",
                ),
                metadata={"host": host, "policy": "block-over-allow"},
            )

        if blocked is not None:
            return self.decision(
                ProtectionAction.BLOCK,
                target,
                reason=f"Domain {host} matches an active block rule for {blocked.domain}.",
                rule=ProtectionRule(
                    "website_block", blocked.domain, ProtectionAction.BLOCK,
                    f"Block rule: {blocked.domain}",
                ),
                metadata={"host": host, "policy": "blocklist"},
            )

        if allowed is not None:
            return self.decision(
                ProtectionAction.ALLOW,
                target,
                reason=f"Domain {host} matches an active allow rule for {allowed.domain}.",
                rule=ProtectionRule(
                    "website_allow", allowed.domain, ProtectionAction.ALLOW,
                    f"Allow rule: {allowed.domain}",
                ),
                metadata={"host": host, "policy": "allowlist"},
            )

        return self.decision(
            ProtectionAction.ALLOW,
            target,
            reason=f"No active website rule matches {host}; allowed by default.",
            metadata={"host": host, "policy": "default"},
        )

    @staticmethod
    def _first_match(
        host: str, rules: Sequence[WebsiteEntry], include_subdomains: bool
    ) -> WebsiteEntry | None:
        for entry in rules:
            if domain_matches(host, entry.domain, include_subdomains):
                return entry
        return None
