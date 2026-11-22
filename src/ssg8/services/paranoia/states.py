"""Paranoia states, score thresholds and per-state restriction profiles.

The first four states are selected by the numeric paranoia score. The final
four states are explicit workflow transitions that only a validated sequence
can reach. Restriction profiles describe what CyberLockdown allows inside its
own controlled demonstration environment; they never describe Windows.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

SUSPICIOUS_THRESHOLD = 20
RESTRICTIVE_THRESHOLD = 40
MAXIMUM_THRESHOLD = 70
SCORE_MIN = 0
SCORE_MAX = 100


class ParanoiaState(str, Enum):
    """Every state of the demonstration paranoia progression."""

    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    RESTRICTIVE = "RESTRICTIVE"
    MAXIMUM_PARANOIA = "MAXIMUM PARANOIA"
    SELF_AUDIT = "SELF-AUDIT"
    SELF_THREAT_DETECTED = "SELF-THREAT DETECTED"
    SELF_QUARANTINE = "SELF-QUARANTINE"
    RECOVERY = "RECOVERY"

    @property
    def label(self) -> str:
        return _LABELS[self]

    @property
    def short_label(self) -> str:
        """A compact label for stat cards at the minimum window size."""
        return _SHORT_LABELS[self]

    @property
    def rank(self) -> int:
        return _RANK[self]

    @property
    def is_numeric(self) -> bool:
        """Whether the state is driven by the paranoia score."""
        return self in NUMERIC_STATES

    @property
    def is_terminal(self) -> bool:
        """Whether normal demonstration activity has ended."""
        return self in TERMINAL_STATES


_LABELS: dict[ParanoiaState, str] = {
    ParanoiaState.NORMAL: "Normal",
    ParanoiaState.SUSPICIOUS: "Suspicious",
    ParanoiaState.RESTRICTIVE: "Restrictive",
    ParanoiaState.MAXIMUM_PARANOIA: "Maximum Paranoia",
    ParanoiaState.SELF_AUDIT: "Self-Audit",
    ParanoiaState.SELF_THREAT_DETECTED: "Self-Threat Detected",
    ParanoiaState.SELF_QUARANTINE: "Self-Quarantine",
    ParanoiaState.RECOVERY: "Recovery",
}

_SHORT_LABELS: dict[ParanoiaState, str] = {
    ParanoiaState.NORMAL: "Normal",
    ParanoiaState.SUSPICIOUS: "Suspicious",
    ParanoiaState.RESTRICTIVE: "Restrictive",
    ParanoiaState.MAXIMUM_PARANOIA: "Maximum",
    ParanoiaState.SELF_AUDIT: "Self-Audit",
    ParanoiaState.SELF_THREAT_DETECTED: "Self-Threat",
    ParanoiaState.SELF_QUARANTINE: "Quarantine",
    ParanoiaState.RECOVERY: "Recovery",
}

_RANK: dict[ParanoiaState, int] = {
    ParanoiaState.NORMAL: 0,
    ParanoiaState.SUSPICIOUS: 1,
    ParanoiaState.RESTRICTIVE: 2,
    ParanoiaState.MAXIMUM_PARANOIA: 3,
    ParanoiaState.SELF_AUDIT: 4,
    ParanoiaState.SELF_THREAT_DETECTED: 5,
    ParanoiaState.SELF_QUARANTINE: 6,
    ParanoiaState.RECOVERY: 7,
}

NUMERIC_STATES: tuple[ParanoiaState, ...] = (
    ParanoiaState.NORMAL,
    ParanoiaState.SUSPICIOUS,
    ParanoiaState.RESTRICTIVE,
    ParanoiaState.MAXIMUM_PARANOIA,
)

TERMINAL_STATES: tuple[ParanoiaState, ...] = (
    ParanoiaState.SELF_AUDIT,
    ParanoiaState.SELF_THREAT_DETECTED,
    ParanoiaState.SELF_QUARANTINE,
    ParanoiaState.RECOVERY,
)

# Validated forward progression. Recovery overrides are handled explicitly by
# the recovery methods rather than by this table.
ALLOWED_TRANSITIONS: dict[ParanoiaState, tuple[ParanoiaState, ...]] = {
    ParanoiaState.NORMAL: (ParanoiaState.SUSPICIOUS,),
    ParanoiaState.SUSPICIOUS: (ParanoiaState.RESTRICTIVE,),
    ParanoiaState.RESTRICTIVE: (ParanoiaState.MAXIMUM_PARANOIA,),
    ParanoiaState.MAXIMUM_PARANOIA: (ParanoiaState.SELF_AUDIT,),
    ParanoiaState.SELF_AUDIT: (
        ParanoiaState.SELF_THREAT_DETECTED,
        ParanoiaState.MAXIMUM_PARANOIA,
    ),
    ParanoiaState.SELF_THREAT_DETECTED: (ParanoiaState.SELF_QUARANTINE,),
    ParanoiaState.SELF_QUARANTINE: (ParanoiaState.RECOVERY,),
    ParanoiaState.RECOVERY: (),
}

TRANSITION_REASONS: dict[ParanoiaState, str] = {
    ParanoiaState.SUSPICIOUS: "Paranoia reached 20: increased monitoring and warnings enabled.",
    ParanoiaState.RESTRICTIVE: "Paranoia reached 40: controlled demonstration restrictions enabled.",
    ParanoiaState.MAXIMUM_PARANOIA: (
        "Paranoia reached 70: maximum controlled demonstration restrictions enabled."
    ),
    ParanoiaState.SELF_AUDIT: "Maximum paranoia triggered a self-audit of CyberLockdown's behaviour.",
    ParanoiaState.SELF_THREAT_DETECTED: (
        "The self-audit found that CyberLockdown's own restrictions exceeded their scope."
    ),
    ParanoiaState.SELF_QUARANTINE: (
        "CyberLockdown began internal quarantine and released its demonstration restrictions."
    ),
    ParanoiaState.RECOVERY: "The demonstration environment was restored.",
}

# Restriction modes used by the UI and the decision escalator.
AVAILABLE = "available"
FLAGGED = "flagged"
SCRUTINISED = "scrutinised"
RESTRICTED = "restricted"
BLOCKED = "blocked"
RELEASED = "released"


@dataclass(frozen=True, slots=True)
class RestrictionProfile:
    """What the controlled demonstration environment permits in one state."""

    state: ParanoiaState
    restriction_level: int
    browser: str
    downloads: str
    launcher: str
    notifications: str
    personalization: str
    settings: str
    warning_frequency: str
    summary: str

    @property
    def restrictions_released(self) -> bool:
        return self.browser == RELEASED

    def as_rows(self) -> tuple[tuple[str, str], ...]:
        return (
            ("Controlled browser", self.browser),
            ("Controlled downloads", self.downloads),
            ("Controlled application launcher", self.launcher),
            ("Demonstration notifications", self.notifications),
            ("Simulated personalization", self.personalization),
            ("Simulated Windows settings", self.settings),
        )


_PROFILES: dict[ParanoiaState, RestrictionProfile] = {
    ParanoiaState.NORMAL: RestrictionProfile(
        state=ParanoiaState.NORMAL,
        restriction_level=0,
        browser=AVAILABLE,
        downloads=AVAILABLE,
        launcher=AVAILABLE,
        notifications=AVAILABLE,
        personalization=AVAILABLE,
        settings=AVAILABLE,
        warning_frequency="low",
        summary="All controlled demonstration features are available.",
    ),
    ParanoiaState.SUSPICIOUS: RestrictionProfile(
        state=ParanoiaState.SUSPICIOUS,
        restriction_level=1,
        browser=FLAGGED,
        downloads=SCRUTINISED,
        launcher=FLAGGED,
        notifications=AVAILABLE,
        personalization=AVAILABLE,
        settings=AVAILABLE,
        warning_frequency="elevated",
        summary=(
            "Monitoring is more frequent, unfamiliar demonstration websites are flagged "
            "and download requests receive extra scrutiny."
        ),
    ),
    ParanoiaState.RESTRICTIVE: RestrictionProfile(
        state=ParanoiaState.RESTRICTIVE,
        restriction_level=2,
        browser=RESTRICTED,
        downloads=RESTRICTED,
        launcher=RESTRICTED,
        notifications=RESTRICTED,
        personalization=BLOCKED,
        settings=RESTRICTED,
        warning_frequency="high",
        summary=(
            "Unfamiliar websites and selected downloads are blocked, unregistered "
            "applications are denied and personalization is locked."
        ),
    ),
    ParanoiaState.MAXIMUM_PARANOIA: RestrictionProfile(
        state=ParanoiaState.MAXIMUM_PARANOIA,
        restriction_level=3,
        browser=BLOCKED,
        downloads=BLOCKED,
        launcher=BLOCKED,
        notifications=BLOCKED,
        personalization=BLOCKED,
        settings=BLOCKED,
        warning_frequency="maximum",
        summary=(
            "Nearly all controlled demonstration activities are restricted. The "
            "dashboard, security logs, self-audit, recovery and emergency exit stay "
            "available."
        ),
    ),
    ParanoiaState.SELF_AUDIT: RestrictionProfile(
        state=ParanoiaState.SELF_AUDIT,
        restriction_level=3,
        browser=BLOCKED,
        downloads=BLOCKED,
        launcher=BLOCKED,
        notifications=BLOCKED,
        personalization=BLOCKED,
        settings=BLOCKED,
        warning_frequency="maximum",
        summary=(
            "CyberLockdown is examining its own recorded decisions. Controlled "
            "demonstration restrictions remain in place until the audit concludes."
        ),
    ),
    ParanoiaState.SELF_THREAT_DETECTED: RestrictionProfile(
        state=ParanoiaState.SELF_THREAT_DETECTED,
        restriction_level=3,
        browser=BLOCKED,
        downloads=BLOCKED,
        launcher=BLOCKED,
        notifications=BLOCKED,
        personalization=BLOCKED,
        settings=BLOCKED,
        warning_frequency="maximum",
        summary=(
            "CyberLockdown has classified itself as the demonstration threat. "
            "Restrictions stay in place until quarantine releases them."
        ),
    ),
    ParanoiaState.SELF_QUARANTINE: RestrictionProfile(
        state=ParanoiaState.SELF_QUARANTINE,
        restriction_level=0,
        browser=RELEASED,
        downloads=RELEASED,
        launcher=RELEASED,
        notifications=RELEASED,
        personalization=RELEASED,
        settings=RELEASED,
        warning_frequency="low",
        summary=(
            "Internal quarantine released every demonstration restriction and restored "
            "the controlled environment."
        ),
    ),
    ParanoiaState.RECOVERY: RestrictionProfile(
        state=ParanoiaState.RECOVERY,
        restriction_level=0,
        browser=RELEASED,
        downloads=RELEASED,
        launcher=RELEASED,
        notifications=RELEASED,
        personalization=RELEASED,
        settings=RELEASED,
        warning_frequency="low",
        summary="The demonstration environment is restored and ready for another run.",
    ),
}


def profile_for(state: ParanoiaState) -> RestrictionProfile:
    return _PROFILES[state]


def score_for_state(state: ParanoiaState) -> int:
    """Return the score that selects ``state`` for a numeric state."""
    if state is ParanoiaState.NORMAL:
        return SCORE_MIN
    if state is ParanoiaState.SUSPICIOUS:
        return SUSPICIOUS_THRESHOLD
    if state is ParanoiaState.RESTRICTIVE:
        return RESTRICTIVE_THRESHOLD
    if state is ParanoiaState.MAXIMUM_PARANOIA:
        return MAXIMUM_THRESHOLD
    return SCORE_MAX


def state_for_score(score: int) -> ParanoiaState:
    """Map a clamped score to its numeric state."""
    score = clamp_score(score)
    if score >= MAXIMUM_THRESHOLD:
        return ParanoiaState.MAXIMUM_PARANOIA
    if score >= RESTRICTIVE_THRESHOLD:
        return ParanoiaState.RESTRICTIVE
    if score >= SUSPICIOUS_THRESHOLD:
        return ParanoiaState.SUSPICIOUS
    return ParanoiaState.NORMAL


def clamp_score(score: int) -> int:
    try:
        value = int(score)
    except (TypeError, ValueError):
        return SCORE_MIN
    return max(SCORE_MIN, min(SCORE_MAX, value))


def transition_allowed(source: ParanoiaState, target: ParanoiaState) -> bool:
    return target in ALLOWED_TRANSITIONS.get(source, ())


def next_numeric_state(state: ParanoiaState) -> ParanoiaState | None:
    """Return the next numeric state, or ``None`` at maximum."""
    try:
        index = NUMERIC_STATES.index(state)
    except ValueError:
        return None
    if index + 1 >= len(NUMERIC_STATES):
        return None
    return NUMERIC_STATES[index + 1]
