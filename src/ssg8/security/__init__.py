"""Internal protection layer for SSG8.

The engines evaluate requests submitted to the application and return a
structured decision. They never modify Windows settings, network traffic,
processes, files or notifications outside SSG8.
"""

from __future__ import annotations

from ssg8.security.decisions import (
    ProtectionAction,
    ProtectionDecision,
    ProtectionRule,
)
from ssg8.security.protection_manager import (
    MODULE_DEFINITIONS,
    MODULE_IDS,
    MODULE_LABELS,
    ProtectionManager,
)

__all__ = [
    "MODULE_DEFINITIONS",
    "MODULE_IDS",
    "MODULE_LABELS",
    "ProtectionAction",
    "ProtectionDecision",
    "ProtectionManager",
    "ProtectionRule",
]
