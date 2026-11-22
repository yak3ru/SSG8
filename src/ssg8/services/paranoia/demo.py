"""Controlled demonstration environment for Phase 6.

Every request here is submitted to one of the existing Phase 2-5 protection
engines. The paranoia manager may escalate the engine's decision, and harmless
demonstration actions raise the paranoia score. Nothing here touches Windows,
the real filesystem outside the demonstration folder, real browsers, real
downloads or other applications.
"""

from __future__ import annotations

import shutil
import tempfile
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, Signal

from ssg8.core.models import EventCategory, Severity
from ssg8.security.decisions import ProtectionAction, ProtectionDecision
from ssg8.services.event_log import EventLog
from ssg8.services.paranoia.activities import (
    DEMO_DOWNLOADS,
    DEMO_SETTINGS,
    DEMO_WALLPAPERS,
    LAUNCHER_APPS,
)
from ssg8.services.paranoia.manager import ParanoiaManager
from ssg8.services.paranoia.states import BLOCKED, RESTRICTED, ParanoiaState

RESULT_LIMIT = 100


@dataclass(frozen=True, slots=True)
class DemoResult:
    """The visible outcome of one controlled demonstration request."""

    action: str
    message: str
    title: str = ""
    warning: str = ""
    decision: ProtectionDecision | None = None
    simulated: bool = False
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def allowed(self) -> bool:
        return self.action == "allow"

    @property
    def blocked(self) -> bool:
        return self.action == "block"

    @property
    def needs_confirmation(self) -> bool:
        return self.action == "review"


class ControlledEnvironment(QObject):
    """Run the controlled browser, download, launcher and settings demos."""

    changed = Signal()
    result_recorded = Signal(object)

    def __init__(
        self,
        protection: Any,
        paranoia: ParanoiaManager,
        events: EventLog | None = None,
        *,
        demo_root: Path | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._protection = protection
        self._paranoia = paranoia
        self._events = events
        self._files_dir: Path | None = None
        self._owns_files_dir = False
        self._demo_root = Path(demo_root) if demo_root is not None else None
        self._results: deque[DemoResult] = deque(maxlen=RESULT_LIMIT)
        self.wallpaper_key = "graphite"
        self.setting_values: dict[str, str] = {key: "Default" for key, _ in DEMO_SETTINGS}

    # --- controlled browser ------------------------------------------------

    def open_website(self, url: str) -> DemoResult:
        self._paranoia.record_activity("browser_open", target=url)
        decision = self._protection.evaluate_website(url)
        policy = str(decision.metadata.get("policy", ""))
        unfamiliar = policy == "default"
        warning = ""
        if unfamiliar:
            self._paranoia.record_activity("unfamiliar_website", target=decision.target)
            warning = self._paranoia.warning_for("unfamiliar_website")
        if decision.action is ProtectionAction.BLOCK:
            key = "unfamiliar_website" if unfamiliar else "restricted_attempt"
            finding = self._paranoia.register_blocked_attempt(
                key, decision.target, module_id="website"
            )
            if finding is not None:
                warning = f"High-risk demonstration finding {finding.id}: {finding.title}"
            elif unfamiliar:
                warning = self._paranoia.warning_for("unfamiliar_website")
        return self._finish(
            DemoResult(
                action=decision.action.value,
                message=decision.reason,
                title="Controlled browser",
                warning=warning,
                decision=decision,
            )
        )

    # --- controlled downloads ---------------------------------------------

    def request_download(self, filename: str) -> DemoResult:
        safe_name = Path(filename).name
        if not safe_name or safe_name != filename:
            result = DemoResult(
                action="block",
                message="The demonstration download name is invalid.",
                title="Controlled download",
            )
            return self._finish(result)

        self._paranoia.record_activity("download_request", target=safe_name)
        path = self._demo_file(safe_name)
        decision = self._protection.evaluate_download(str(path))
        warning = ""
        if decision.action is ProtectionAction.BLOCK:
            finding = self._paranoia.register_blocked_attempt(
                "download_request", safe_name, module_id="download"
            )
            warning = self._paranoia.warning_for("download_request")
            if finding is not None:
                warning = f"High-risk demonstration finding {finding.id}: {finding.title}"
        elif decision.action is ProtectionAction.REVIEW:
            warning = "The demonstration download requires confirmation under the current policy."
        return self._finish(
            DemoResult(
                action=decision.action.value,
                message=decision.reason,
                title="Controlled download",
                warning=warning,
                decision=decision,
            )
        )

    # --- controlled application launcher ---------------------------------

    def launch_application(self, app_key: str) -> DemoResult:
        entry = next((item for item in LAUNCHER_APPS if item[0] == app_key), None)
        if entry is None:
            return self._finish(
                DemoResult(
                    action="block",
                    message=f"Unknown controlled application: {app_key}",
                    title="Controlled launcher",
                )
            )
        _key, label, activity_key = entry
        self._paranoia.record_activity(activity_key, target=label)
        decision = self._protection.evaluate_application(label, None)
        action = decision.action
        message = decision.reason
        warning = ""

        if (
            action is ProtectionAction.REVIEW
            and decision.metadata.get("policy") == "unmatched"
            and self._paranoia.state() is ParanoiaState.NORMAL
        ):
            # The controlled launcher is available at NORMAL. The existing
            # application engine reports unmatched requests as REVIEW; the
            # demonstration launcher permits its own harmless built-in apps.
            action = ProtectionAction.ALLOW
            message = (
                "No application rule matches this demo app. The controlled launcher "
                "permits it while paranoia is Normal."
            )

        if action is ProtectionAction.BLOCK:
            finding = self._paranoia.register_blocked_attempt(
                activity_key, label, module_id="application"
            )
            warning = self._paranoia.warning_for(activity_key)
            if finding is not None:
                warning = f"High-risk demonstration finding {finding.id}: {finding.title}"
        elif action is ProtectionAction.REVIEW:
            warning = (
                "This harmless launch requires review under the current paranoia profile. "
                "Confirm it to continue the demonstration."
            )
        return self._finish(
            DemoResult(
                action=action.value,
                message=message,
                title="Controlled launcher",
                warning=warning,
                decision=decision,
                simulated=action is ProtectionAction.ALLOW,
            )
        )

    # --- simulated personalization and settings ---------------------------

    def change_wallpaper(self, wallpaper_key: str) -> DemoResult:
        entry = next((item for item in DEMO_WALLPAPERS if item[0] == wallpaper_key), None)
        if entry is None:
            return self._finish(
                DemoResult(
                    action="block",
                    message=f"Unknown simulated wallpaper: {wallpaper_key}",
                    title="Simulated personalization",
                )
            )
        self._paranoia.record_activity("wallpaper_change", target=entry[1])
        profile = self._paranoia.profile
        if profile.personalization in (BLOCKED, RESTRICTED):
            return self._local_block(
                "personalization",
                entry[1],
                "Wallpaper modification blocked by the current paranoia profile. "
                "The actual Windows wallpaper was never touched.",
                "wallpaper_change",
                "Simulated personalization",
            )
        self.wallpaper_key = wallpaper_key
        return self._finish(
            DemoResult(
                action="allow",
                message=(
                    f"Simulated wallpaper changed to {entry[1]} inside CyberLockdown. "
                    "The real Windows wallpaper is unchanged."
                ),
                title="Simulated personalization",
            )
        )

    def open_settings(self) -> DemoResult:
        self._paranoia.record_activity("settings_open")
        if self._paranoia.profile.settings in (BLOCKED, RESTRICTED):
            return self._local_block(
                "settings",
                "Simulated Windows settings",
                "System settings are locked under the current paranoia profile. "
                "Actual Windows settings are untouched.",
                "settings_open",
                "Simulated Windows settings",
            )
        return self._finish(
            DemoResult(
                action="allow",
                message=(
                    "Simulated Windows settings opened. These controls exist only inside "
                    "CyberLockdown."
                ),
                title="Simulated Windows settings",
            )
        )

    def apply_setting(self, key: str, value: str) -> DemoResult:
        label = dict(DEMO_SETTINGS).get(key, key)
        self._paranoia.record_activity("personalization_change", target=f"{label}: {value}")
        if self._paranoia.profile.settings in (BLOCKED, RESTRICTED):
            return self._local_block(
                "settings",
                label,
                "Simulated settings changes are restricted under the current paranoia profile.",
                "personalization_change",
                "Simulated Windows settings",
            )
        self.setting_values[key] = value
        return self._finish(
            DemoResult(
                action="allow",
                message=f"Simulated setting '{label}' set to '{value}'. Windows is unchanged.",
                title="Simulated Windows settings",
            )
        )

    # --- demonstration notifications -------------------------------------

    def send_notification(self, category: str, message: str) -> DemoResult:
        decision = self._protection.evaluate_notification(category, message)
        if decision.action is ProtectionAction.BLOCK:
            finding = self._paranoia.register_blocked_attempt(
                "restricted_attempt", category, module_id="notification"
            )
            warning = "Demonstration notification suppressed by the current paranoia profile."
            if finding is not None:
                warning = f"High-risk demonstration finding {finding.id}: {finding.title}"
            return self._finish(
                DemoResult(
                    action="block",
                    message=decision.reason,
                    title="Demonstration notification",
                    warning=warning,
                    decision=decision,
                )
            )
        return self._finish(
            DemoResult(
                action=decision.action.value,
                message=decision.reason,
                title="Demonstration notification",
                decision=decision,
                simulated=True,
            )
        )

    def record_restricted_attempt(self, target: str = "restricted demo action") -> None:
        self._paranoia.record_activity("restricted_attempt", target=target)

    # --- help and cleanup --------------------------------------------------

    def recent_results(self, limit: int | None = None) -> tuple[DemoResult, ...]:
        items = tuple(reversed(self._results))
        return items if limit is None else items[:limit]

    def cleanup(self) -> None:
        """Remove only the demonstration's own temporary download folder."""
        if self._files_dir is not None and self._owns_files_dir:
            shutil.rmtree(self._files_dir, ignore_errors=True)
        self._files_dir = None
        self._owns_files_dir = False

    # --- internals ---------------------------------------------------------

    def _finish(self, result: DemoResult) -> DemoResult:
        self._results.append(result)
        self.result_recorded.emit(result)
        if result.blocked:
            self._events_record(
                EventCategory.DEMO,
                Severity.HIGH,
                f"{result.title}: BLOCK - {result.message}",
                reason=result.warning or "Controlled demonstration request blocked.",
            )
        self.changed.emit()
        return result

    def _local_block(
        self,
        module: str,
        target: str,
        reason: str,
        activity_key: str,
        title: str,
    ) -> DemoResult:
        register = getattr(self._paranoia, "register_restriction", None)
        if callable(register):
            register(
                module,
                target,
                ProtectionAction.ALLOW,
                ProtectionAction.BLOCK,
                reason,
                activity_key,
            )
        finding = self._paranoia.register_blocked_attempt(
            activity_key, target, module_id=module
        )
        warning = self._paranoia.warning_for(activity_key) or reason
        if finding is not None:
            warning = f"High-risk demonstration finding {finding.id}: {finding.title}"
        return self._finish(
            DemoResult(
                action="block",
                message=reason,
                title=title,
                warning=warning,
            )
        )

    def _demo_file(self, filename: str) -> Path:
        if self._files_dir is None:
            base = self._demo_root
            if base is None:
                base = Path(tempfile.mkdtemp(prefix="ssg8-demo-"))
                self._owns_files_dir = True
                self._files_dir = base
            else:
                self._files_dir = base / "controlled-downloads"
                self._owns_files_dir = True
                self._files_dir.mkdir(parents=True, exist_ok=True)
        path = self._files_dir / Path(filename).name
        if not path.exists():
            path.write_text(
                "CyberLockdown controlled demonstration download.\n"
                f"Requested at {datetime.now().isoformat(timespec='seconds')}.\n",
                encoding="utf-8",
            )
        return path

    def _events_record(
        self,
        category: EventCategory,
        severity: Severity,
        message: str,
        *,
        reason: str = "",
    ) -> None:
        if self._events is None:
            return
        self._events.record(
            category,
            severity,
            message,
            source="Controlled demonstration",
            reason=reason,
            action="demo",
        )


def demo_file_names() -> tuple[str, ...]:
    return tuple(name for name, _description in DEMO_DOWNLOADS)
