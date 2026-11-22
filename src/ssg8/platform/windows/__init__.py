"""Windows specific integration helpers for SSG8.

Only cosmetic desktop integration lives here in this phase. No system
settings, permissions, registry keys or services are modified.
"""

from __future__ import annotations

from ssg8.platform.windows.titlebar import apply_dark_title_bar

__all__ = ["apply_dark_title_bar"]
