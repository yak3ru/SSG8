"""Configuration and vocabulary for the internal threat analyzer.

The analyzer is deterministic: the same decisions, window and thresholds
always produce the same pattern candidates. No external intelligence, machine
learning model or random value is involved.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

# Pattern identifiers written to findings.
PATTERN_REPEATED_BLOCK = "repeated_block"
PATTERN_DOWNLOAD_VOLUME = "download_volume"
PATTERN_REVIEW_CONCENTRATION = "review_concentration"
PATTERN_MULTI_MODULE = "multi_module"

PATTERN_LABELS: dict[str, str] = {
    PATTERN_REPEATED_BLOCK: "Repeated block events",
    PATTERN_DOWNLOAD_VOLUME: "Repeated download violations",
    PATTERN_REVIEW_CONCENTRATION: "Review concentration",
    PATTERN_MULTI_MODULE: "Cross-module violations",
}

MODULE_SUBJECTS: dict[str, str] = {
    "website": "website",
    "download": "download",
    "application": "application",
    "notification": "notification",
}

DEFAULT_WINDOW_MINUTES = 15
DEFAULT_REPEAT_THRESHOLD = 3
DEFAULT_MULTI_MODULE_THRESHOLD = 2
DEFAULT_ALERT_MIN_SCORE = 25
DEFAULT_DEDUPE_MINUTES = 30

MIN_WINDOW_MINUTES = 1
MAX_WINDOW_MINUTES = 1440
MIN_REPEAT_THRESHOLD = 2
MAX_REPEAT_THRESHOLD = 50
MIN_MULTI_MODULE_THRESHOLD = 2
MAX_MULTI_MODULE_THRESHOLD = 4


@dataclass(frozen=True, slots=True)
class AnalysisSettings:
    """User-configurable thresholds for deterministic analysis."""

    window_minutes: int = DEFAULT_WINDOW_MINUTES
    repeat_threshold: int = DEFAULT_REPEAT_THRESHOLD
    multi_module_threshold: int = DEFAULT_MULTI_MODULE_THRESHOLD
    alert_min_score: int = DEFAULT_ALERT_MIN_SCORE
    dedupe_minutes: int = DEFAULT_DEDUPE_MINUTES


def validate_settings(settings: AnalysisSettings) -> str | None:
    """Return a readable validation error, or ``None``."""
    if not isinstance(settings.window_minutes, int):
        return "The analysis window must be a whole number of minutes."
    if not MIN_WINDOW_MINUTES <= settings.window_minutes <= MAX_WINDOW_MINUTES:
        return (
            f"The analysis window must be between {MIN_WINDOW_MINUTES} and "
            f"{MAX_WINDOW_MINUTES} minutes."
        )
    if not isinstance(settings.repeat_threshold, int):
        return "The repeated-event threshold must be a whole number."
    if not MIN_REPEAT_THRESHOLD <= settings.repeat_threshold <= MAX_REPEAT_THRESHOLD:
        return (
            f"The repeated-event threshold must be between {MIN_REPEAT_THRESHOLD} "
            f"and {MAX_REPEAT_THRESHOLD}."
        )
    if not isinstance(settings.multi_module_threshold, int):
        return "The multi-module threshold must be a whole number."
    if not (
        MIN_MULTI_MODULE_THRESHOLD
        <= settings.multi_module_threshold
        <= MAX_MULTI_MODULE_THRESHOLD
    ):
        return (
            f"The multi-module threshold must be between "
            f"{MIN_MULTI_MODULE_THRESHOLD} and {MAX_MULTI_MODULE_THRESHOLD}."
        )
    if not isinstance(settings.alert_min_score, int):
        return "The minimum alert score must be a whole number."
    if not 0 <= settings.alert_min_score <= 100:
        return "The minimum alert score must be between 0 and 100."
    if not isinstance(settings.dedupe_minutes, int):
        return "The duplicate suppression window must be a whole number."
    if not MIN_WINDOW_MINUTES <= settings.dedupe_minutes <= MAX_WINDOW_MINUTES:
        return (
            f"The duplicate suppression window must be between "
            f"{MIN_WINDOW_MINUTES} and {MAX_WINDOW_MINUTES} minutes."
        )
    return None


def with_updates(settings: AnalysisSettings, **changes: Any) -> AnalysisSettings:
    """Return a copy with ``changes`` applied."""
    return replace(settings, **changes)


def settings_to_dict(settings: AnalysisSettings) -> dict[str, int]:
    return {
        "window_minutes": settings.window_minutes,
        "repeat_threshold": settings.repeat_threshold,
        "multi_module_threshold": settings.multi_module_threshold,
        "alert_min_score": settings.alert_min_score,
        "dedupe_minutes": settings.dedupe_minutes,
    }


def settings_from_dict(raw: Any) -> tuple[AnalysisSettings, list[str]]:
    """Build settings from persisted JSON, falling back per invalid field."""
    defaults = AnalysisSettings()
    errors: list[str] = []
    if not isinstance(raw, dict):
        return defaults, ["Analysis settings are not a JSON object; defaults used."]

    values: dict[str, int] = {}
    fields = {
        "window_minutes": (MIN_WINDOW_MINUTES, MAX_WINDOW_MINUTES),
        "repeat_threshold": (MIN_REPEAT_THRESHOLD, MAX_REPEAT_THRESHOLD),
        "multi_module_threshold": (
            MIN_MULTI_MODULE_THRESHOLD,
            MAX_MULTI_MODULE_THRESHOLD,
        ),
        "alert_min_score": (0, 100),
        "dedupe_minutes": (MIN_WINDOW_MINUTES, MAX_WINDOW_MINUTES),
    }
    for key, (minimum, maximum) in fields.items():
        value = raw.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            if minimum <= value <= maximum:
                values[key] = value
                continue
        if value is not None:
            errors.append(f"Stored analysis setting '{key}' is invalid; default used.")

    settings = AnalysisSettings(**values)
    return settings, errors
