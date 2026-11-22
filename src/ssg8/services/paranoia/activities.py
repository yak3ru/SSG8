"""Demonstration activities and their deterministic paranoia weights.

Only actions performed inside CyberLockdown's controlled demonstration
environment are listed here. Unrelated Windows activity never appears in this
catalogue and never increases paranoia.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DemoActivity:
    """One harmless demonstration action that can raise suspicion."""

    key: str
    label: str
    points: int
    description: str
    warning: str = ""


ACTIVITIES: dict[str, DemoActivity] = {
    activity.key: activity
    for activity in (
        DemoActivity(
            "browser_open",
            "Open controlled browser",
            3,
            "A controlled browser session was opened inside CyberLockdown.",
            "Controlled browser session opened. Browsing behaviour is now under observation.",
        ),
        DemoActivity(
            "unfamiliar_website",
            "Visit unfamiliar demonstration website",
            5,
            "An unfamiliar host was requested in the controlled browser.",
            "Unfamiliar website detected. Its intentions remain questionable.",
        ),
        DemoActivity(
            "download_request",
            "Request a demonstration download",
            5,
            "A file was requested in the controlled download workflow.",
            "Download rejected. The file has not earned our trust.",
        ),
        DemoActivity(
            "launch_calculator",
            "Launch Calculator in controlled launcher",
            4,
            "A Calculator launch was requested in the controlled launcher.",
            "Unauthorized mathematical activity detected. Calculator access has been restricted.",
        ),
        DemoActivity(
            "launch_notepad",
            "Launch Notepad in controlled launcher",
            4,
            "A Notepad launch was requested in the controlled launcher.",
            "Notepad launch denied. Unauthorized text creation detected.",
        ),
        DemoActivity(
            "launch_paint",
            "Launch Paint in controlled launcher",
            4,
            "A Paint launch was requested in the controlled launcher.",
            "Paint launch blocked. Unauthorized image creation detected.",
        ),
        DemoActivity(
            "wallpaper_change",
            "Change simulated wallpaper",
            3,
            "A simulated wallpaper change was requested.",
            "Wallpaper modification blocked. Visual instability is a potential threat.",
        ),
        DemoActivity(
            "settings_open",
            "Open simulated Windows settings",
            4,
            "The simulated Windows settings panel was opened.",
            "System settings locked. User preferences are temporarily considered suspicious.",
        ),
        DemoActivity(
            "personalization_change",
            "Modify simulated personalization settings",
            5,
            "A simulated personalization preference was changed.",
            "Personalization changes rejected. Visual preferences are considered a threat surface.",
        ),
        DemoActivity(
            "restricted_attempt",
            "Attempt a restricted demonstration action",
            3,
            "A restricted demonstration action was attempted again.",
            "Repeated restricted action detected. CyberLockdown is becoming more suspicious.",
        ),
    )
}

DEFAULT_POINTS = 3

# Demonstration applications offered by the controlled launcher.
LAUNCHER_APPS: tuple[tuple[str, str, str], ...] = (
    ("calculator", "Calculator", "launch_calculator"),
    ("notepad", "Notepad", "launch_notepad"),
    ("paint", "Paint", "launch_paint"),
)

# Sample files offered by the controlled download workflow. They are created
# inside the demonstration's own temporary folder and are never opened.
DEMO_DOWNLOADS: tuple[tuple[str, str], ...] = (
    ("quarterly-report.pdf", "A trusted document type."),
    ("team-photo.jpg", "A trusted image type."),
    ("backup-archive.zip", "A trusted archive type."),
    ("installer.exe", "A prohibited executable type under the default policy."),
    ("mystery-file.xyz", "An unknown file type that requires review."),
)

DEMO_WALLPAPERS: tuple[tuple[str, str, str], ...] = (
    ("graphite", "Graphite Grid", "#17171C"),
    ("ember", "Ember Red", "#2A1417"),
    ("ocean", "Ocean Slate", "#141B26"),
    ("forest", "Forest Signal", "#12241A"),
)

DEMO_SETTINGS: tuple[tuple[str, str], ...] = (
    ("theme", "Demonstration theme"),
    ("notifications", "Demonstration notification preferences"),
    ("browser", "Controlled browser preferences"),
    ("security", "Demonstration security preferences"),
)


def activity_for(key: str) -> DemoActivity:
    """Return the catalogue entry for ``key`` or raise ``KeyError``."""
    return ACTIVITIES[key]


def points_for(key: str) -> int:
    activity = ACTIVITIES.get(key)
    return activity.points if activity is not None else DEFAULT_POINTS
