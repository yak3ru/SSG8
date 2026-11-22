"""Notification control engine: evaluates notifications raised inside SSG8.

This module never touches Windows notifications, Focus Assist or another
application's own notification settings. Only notifications sent through the
SSG8 internal notification service are evaluated.
"""

from __future__ import annotations

from collections.abc import Mapping

from ssg8.core.app_state import NOTIFICATION_CATEGORIES
from ssg8.security.decisions import ProtectionAction, ProtectionRule
from ssg8.security.engine import ProtectionModule

CATEGORY_LABELS: dict[str, str] = {
    key: label for key, label in NOTIFICATION_CATEGORIES
}


class NotificationEngine(ProtectionModule):
    """Evaluate one internal notification against master and category state."""

    module_id = "notification"
    label = "Notification Control"

    def evaluate(
        self,
        category: str,
        message: str,
        *,
        master_enabled: bool,
        enabled_categories: Mapping[str, bool],
    ):
        target = category if isinstance(category, str) else ""
        preview = (message if isinstance(message, str) else "").strip()
        if len(preview) > 120:
            preview = preview[:117] + "..."

        if category not in CATEGORY_LABELS:
            return self.decision(
                ProtectionAction.REVIEW,
                target=target,
                reason=f"Unknown notification category: {target or '(none)'}.",
                metadata={"policy": "invalid-category", "preview": preview},
            )

        label = CATEGORY_LABELS[category]
        metadata = {"category": category, "label": label, "preview": preview}

        if not master_enabled:
            metadata["policy"] = "master-disabled"
            return self.decision(
                ProtectionAction.BLOCK,
                target=label,
                reason="Notification protection is disabled.",
                metadata=metadata,
            )

        if not enabled_categories.get(category, False):
            metadata["policy"] = "category-disabled"
            return self.decision(
                ProtectionAction.BLOCK,
                target=label,
                reason=f"Notification category '{label}' is disabled.",
                rule=ProtectionRule(
                    "notification_category",
                    category,
                    ProtectionAction.BLOCK,
                    f"Disabled category: {label}",
                ),
                metadata=metadata,
            )

        metadata["policy"] = "category-enabled"
        return self.decision(
            ProtectionAction.ALLOW,
            target=label,
            reason=f"Notification category '{label}' is enabled.",
            metadata=metadata,
        )
