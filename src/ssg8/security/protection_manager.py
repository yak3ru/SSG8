"""Unified protection manager for the four internal engines.

Every evaluation is routed to one engine, turned into the shared decision
model, recorded in the single application :class:`EventLog` and kept in a
bounded session history for the interface. Engine failures are caught per
module so one broken module never disables the others.

All of this happens inside SSG8. No rule changes Windows, a browser or another
application.
"""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Callable, Iterable

from PySide6.QtCore import QObject, Signal

from ssg8.core.app_state import (
    APPLICATION_POLICIES,
    WEBSITE_LIST_TYPES,
    AppState,
)
from ssg8.core.models import ApplicationEntry, EventCategory, Severity, WebsiteEntry
from ssg8.security.decisions import ProtectionAction, ProtectionDecision
from ssg8.security.engine import ProtectionModule
from ssg8.security.modules import (
    ApplicationEngine,
    DownloadEngine,
    NotificationEngine,
    WebsiteEngine,
)
from ssg8.security.policies import (
    ProtectionSettings,
    extension_errors,
    normalise_extensions,
    validate_settings,
    with_updates,
)
from ssg8.services.event_log import EventLog
from ssg8.storage.protection_store import ProtectionStore
from ssg8.utils.validation import (
    normalise_domain,
    validate_application_name,
    validate_application_path,
    validate_domain,
)

MODULE_DEFINITIONS: tuple[tuple[str, str], ...] = (
    ("website", "Website Protection"),
    ("download", "Download Protection"),
    ("application", "Application Control"),
    ("notification", "Notification Control"),
)
MODULE_LABELS: dict[str, str] = dict(MODULE_DEFINITIONS)
MODULE_IDS: tuple[str, ...] = tuple(module_id for module_id, _label in MODULE_DEFINITIONS)
MODULE_IDS_BY_LABEL: dict[str, str] = {
    label: module_id for module_id, label in MODULE_DEFINITIONS
}

DECISION_LIMIT = 300

_ACTION_SEVERITY: dict[ProtectionAction, Severity] = {
    ProtectionAction.ALLOW: Severity.INFO,
    ProtectionAction.BLOCK: Severity.HIGH,
    ProtectionAction.REVIEW: Severity.MEDIUM,
}


class ProtectionManager(QObject):
    """Coordinate the protection engines and their shared configuration."""

    changed = Signal()
    modules_changed = Signal()
    settings_changed = Signal()
    decision_recorded = Signal(object)

    def __init__(
        self,
        state: AppState,
        events: EventLog,
        store: ProtectionStore | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._state = state
        self._events = events
        self._store = store or ProtectionStore()
        self._settings = self._store.load_settings()
        self._enabled: dict[str, bool] = {module_id: True for module_id in MODULE_IDS}
        self._autonomous_mode = False
        self._decisions: deque[ProtectionDecision] = deque(maxlen=DECISION_LIMIT)
        self._stats: Counter[str] = Counter()
        self._seen_hashes: set[str] = set()
        self._lockdown_snapshot: dict[str, bool] | None = None
        self._decision_escalator: (
            Callable[[ProtectionDecision], ProtectionDecision] | None
        ) = None

        self._engines: dict[str, ProtectionModule] = {
            "website": WebsiteEngine(lambda: self._settings),
            "download": DownloadEngine(lambda: self._settings),
            "application": ApplicationEngine(),
            "notification": NotificationEngine(),
        }

        self._restore_rules()

        self._state.websites_changed.connect(self._persist_websites)
        self._state.applications_changed.connect(self._persist_applications)
        self._state.lockdown_changed.connect(self.handle_lockdown)

    # --- configuration -----------------------------------------------------

    @property
    def store(self) -> ProtectionStore:
        return self._store

    def settings(self) -> ProtectionSettings:
        return self._settings

    def update_settings(self, **changes) -> tuple[bool, str]:
        """Validate, persist and apply protection policy changes."""
        candidate = with_updates(self._settings, **changes)
        error = validate_settings(candidate)
        if error:
            return False, error

        self._settings = candidate
        saved = self._store.save_settings(candidate)
        self.settings_changed.emit()
        self._events.record(
            EventCategory.PREFERENCE,
            Severity.INFO,
            (
                "Protection policy updated: "
                f"max file size {candidate.max_file_size_mb} MB, "
                f"subdomains {candidate.subdomain_matching}, "
                f"unknown files {candidate.unknown_file_action}, "
                f"{len(candidate.blocked_extensions)} prohibited extensions"
            ),
        )
        if not saved:
            self._events.record(
                EventCategory.PROTECTION,
                Severity.MEDIUM,
                "Protection policy could not be written to disk.",
            )
        return True, "Protection policy saved."

    def update_prohibited_extensions(self, value: str) -> tuple[bool, str]:
        """Apply a comma separated extension list from the settings page."""
        error = extension_errors(value)
        if error:
            return False, error
        extensions = normalise_extensions(value)
        if not extensions:
            return False, "Configure at least one prohibited extension."
        return self.update_settings(blocked_extensions=extensions)

    def extension_error(self, value: str) -> str | None:
        return extension_errors(value)

    def set_decision_escalator(
        self,
        escalator: Callable[[ProtectionDecision], ProtectionDecision] | None,
    ) -> None:
        """Install an optional decision post-processor (Phase 6 paranoia).

        The escalator only ever sees a decision produced by an existing engine and
        returns the decision to record. It cannot bypass module evaluation and a
        failure falls back to the original decision.
        """
        self._decision_escalator = escalator

    def set_autonomous_mode(self, enabled: bool) -> None:
        """Enable the interactive presentation policy (never Windows-wide enforcement)."""
        self._autonomous_mode = bool(enabled)

    def autonomous_mode(self) -> bool:
        return self._autonomous_mode

    # --- module enablement -------------------------------------------------

    def module_ids(self) -> tuple[str, ...]:
        return MODULE_IDS

    def module_label(self, module_id: str) -> str:
        return MODULE_LABELS.get(module_id, module_id)

    def module_states(self) -> dict[str, bool]:
        return dict(self._enabled)

    def is_module_enabled(self, module_id: str) -> bool:
        return bool(self._enabled.get(module_id, False))

    def enabled_module_count(self) -> int:
        return sum(1 for enabled in self._enabled.values() if enabled)

    def set_module_enabled(
        self, module_id: str, enabled: bool, *, record: bool = True
    ) -> bool:
        if module_id not in self._enabled:
            return False
        if self._enabled[module_id] == enabled:
            return True
        self._enabled[module_id] = enabled
        if record:
            self._events.record(
                EventCategory.PROTECTION,
                Severity.INFO,
                f"Protection module '{self.module_label(module_id)}' "
                f"{'enabled' if enabled else 'disabled'}",
            )
        self.modules_changed.emit()
        return True

    # --- website rules -----------------------------------------------------

    def add_website_rule(self, domain: str, list_type: str) -> tuple[bool, str]:
        if list_type not in WEBSITE_LIST_TYPES:
            return False, "Choose whether the rule blocks or allows the domain."
        error = validate_domain(domain)
        if error:
            return False, error

        normalised = normalise_domain(domain)
        if self._state.has_website(normalised, list_type):
            list_name = "blocklist" if list_type == "block" else "allowlist"
            return False, f"{normalised} is already in the {list_name}."

        entry = self._state.add_website(normalised, list_type)
        if entry is None:
            return False, "The rule could not be added."
        self._events.record(
            EventCategory.CONFIGURATION,
            Severity.INFO,
            f"Website {list_type} rule added: {entry.domain}",
        )
        article = "an" if list_type == "allow" else "a"
        return True, f"Added {article} {list_type} rule for {entry.domain}."

    def remove_website_rule(self, entry: WebsiteEntry) -> bool:
        removed = self._state.remove_website(entry.domain, entry.list_type)
        if removed:
            self._events.record(
                EventCategory.CONFIGURATION,
                Severity.INFO,
                f"Website {entry.list_type} rule removed: {entry.domain}",
            )
        return removed

    # --- application rules -------------------------------------------------

    def add_application_rule(
        self, name: str, executable_path: str, policy: str
    ) -> tuple[bool, str]:
        if policy not in APPLICATION_POLICIES:
            return False, "Choose whether the rule allows or blocks the application."
        error = validate_application_name(name)
        if error:
            return False, error
        path = executable_path.strip()
        if path:
            error = validate_application_path(path)
            if error:
                return False, error

        clean_name = name.strip()
        for existing in self._state.applications(policy):
            if path:
                if existing.path and existing.path.casefold() == path.casefold():
                    return False, "That executable path already has the same policy."
            elif not existing.path and existing.name.casefold() == clean_name.casefold():
                return False, "That application name already has the same policy."

        entry = self._state.add_application(clean_name, path, policy)
        self._events.record(
            EventCategory.CONFIGURATION,
            Severity.INFO,
            f"Application {policy} rule added: {entry.name}",
        )
        article = "an" if policy == "allow" else "a"
        return True, f"Added {article} {policy} rule for {entry.name}."

    def remove_application_rule(self, entry: ApplicationEntry) -> bool:
        removed = self._state.remove_application(
            entry.path, entry.policy, entry.name
        )
        if removed:
            self._events.record(
                EventCategory.CONFIGURATION,
                Severity.INFO,
                f"Application {entry.policy} rule removed: {entry.name}",
            )
        return removed

    # --- notification categories ------------------------------------------

    def set_notification_category(self, key: str, enabled: bool) -> bool:
        if key not in self._state.notification_categories():
            return False
        self._state.set_notification_category_enabled(key, enabled)
        self._events.record(
            EventCategory.PREFERENCE,
            Severity.INFO,
            f"Notification category '{key}' {'enabled' if enabled else 'disabled'}",
        )
        return True

    # --- evaluation --------------------------------------------------------

    def evaluate_website(self, url: str) -> ProtectionDecision:
        engine = self._engines["website"]
        if not self._enabled["website"]:
            return self._finish(self._disabled_decision(engine, url))
        try:
            decision = engine.evaluate(
                url,
                self._state.websites("block"),
                self._state.websites("allow"),
            )
        except Exception as exc:  # noqa: BLE001 - one module must not break others
            return self._module_error(engine, url, exc)
        return self._finish(decision)

    def evaluate_download(self, file_path: str) -> ProtectionDecision:
        engine = self._engines["download"]
        if not self._enabled["download"]:
            return self._finish(self._disabled_decision(engine, file_path))
        try:
            decision = engine.evaluate(file_path, frozenset(self._seen_hashes))
        except Exception as exc:  # noqa: BLE001
            return self._module_error(engine, file_path, exc)

        digest = decision.metadata.get("sha256", "")
        if len(digest) == 64:
            self._seen_hashes.add(digest)
        return self._finish(decision)

    def evaluate_application(
        self, name: str, executable_path: str | None = None
    ) -> ProtectionDecision:
        engine = self._engines["application"]
        target = name if isinstance(name, str) else ""
        if not self._enabled["application"]:
            return self._finish(self._disabled_decision(engine, target))
        try:
            decision = engine.evaluate(
                name, executable_path, self._state.applications()
            )
        except Exception as exc:  # noqa: BLE001
            return self._module_error(engine, target, exc)
        return self._finish(decision)

    def evaluate_notification(self, category: str, message: str) -> ProtectionDecision:
        engine = self._engines["notification"]
        target = category if isinstance(category, str) else ""
        if not self._enabled["notification"]:
            return self._finish(self._disabled_decision(engine, target))
        try:
            decision = engine.evaluate(
                category,
                message,
                master_enabled=self._state.notification_control_enabled(),
                enabled_categories=self._state.notification_categories(),
            )
        except Exception as exc:  # noqa: BLE001
            return self._module_error(engine, target, exc)
        return self._finish(decision)

    # --- history and statistics -------------------------------------------

    def decisions(
        self,
        module_id: str | None = None,
        actions: Iterable[ProtectionAction] | None = None,
        limit: int | None = None,
    ) -> tuple[ProtectionDecision, ...]:
        wanted = set(actions) if actions is not None else None
        label = MODULE_LABELS.get(module_id) if module_id else None
        results: list[ProtectionDecision] = []
        for decision in reversed(self._decisions):
            if label is not None and decision.module != label:
                continue
            if wanted is not None and decision.action not in wanted:
                continue
            results.append(decision)
            if limit is not None and len(results) >= limit:
                break
        return tuple(results)

    def stats(self) -> dict[str, int]:
        return {
            "evaluations": self._stats.get("evaluations", 0),
            "allowed": self._stats.get(ProtectionAction.ALLOW.value, 0),
            "blocked": self._stats.get(ProtectionAction.BLOCK.value, 0),
            "review": self._stats.get(ProtectionAction.REVIEW.value, 0),
        }

    def last_decision(self) -> ProtectionDecision | None:
        return self._decisions[-1] if self._decisions else None

    def reset_session_history(self) -> None:
        """Clear in-session decisions and statistics (rules are kept)."""
        self._decisions.clear()
        self._stats.clear()
        self._seen_hashes.clear()
        self.changed.emit()

    # --- simulated lockdown ------------------------------------------------

    def handle_lockdown(self, active: bool) -> None:
        """Enable every module during lockdown and restore prior states after."""
        if active:
            if self._lockdown_snapshot is None:
                self._lockdown_snapshot = dict(self._enabled)
            for module_id in MODULE_IDS:
                self._enabled[module_id] = True
            self.modules_changed.emit()
            self._events.record(
                EventCategory.LOCKDOWN,
                Severity.HIGH,
                "Simulated lockdown enabled all internal protection modules",
            )
            return

        snapshot = self._lockdown_snapshot
        self._lockdown_snapshot = None
        if snapshot is None:
            return
        self._enabled = {
            module_id: snapshot.get(module_id, True) for module_id in MODULE_IDS
        }
        self.modules_changed.emit()
        disabled = [
            MODULE_LABELS[module_id]
            for module_id in MODULE_IDS
            if not self._enabled[module_id]
        ]
        detail = f" ({', '.join(disabled)} remain disabled)" if disabled else ""
        self._events.record(
            EventCategory.LOCKDOWN,
            Severity.INFO,
            "Protection modules restored to their pre-lockdown state" + detail,
        )

    @property
    def lockdown_snapshot_active(self) -> bool:
        return self._lockdown_snapshot is not None

    # --- internals ---------------------------------------------------------

    def _restore_rules(self) -> None:
        websites = self._store.load_websites()
        if websites:
            self._state.restore_websites(websites)
        applications = self._store.load_applications()
        if applications:
            self._state.restore_applications(applications)

    def _persist_websites(self) -> None:
        if not self._store.save_websites(list(self._state.websites())):
            self._events.record(
                EventCategory.PROTECTION,
                Severity.MEDIUM,
                "Website rules could not be written to disk.",
            )

    def _persist_applications(self) -> None:
        if not self._store.save_applications(list(self._state.applications())):
            self._events.record(
                EventCategory.PROTECTION,
                Severity.MEDIUM,
                "Application rules could not be written to disk.",
            )

    def _disabled_decision(
        self, engine: ProtectionModule, target: str
    ) -> ProtectionDecision:
        if self._autonomous_mode:
            return engine.decision(
                ProtectionAction.ALLOW,
                target=target if isinstance(target, str) else "",
                reason=f"{engine.label} is currently inactive; no managed restriction applies.",
                metadata={"policy": "module-disabled"},
            )
        return engine.decision(
            ProtectionAction.BLOCK,
            target=target if isinstance(target, str) else "",
            reason=f"The {engine.label} module is disabled.",
            metadata={"policy": "module-disabled"},
        )

    def _module_error(
        self, engine: ProtectionModule, target: str, error: Exception
    ) -> ProtectionDecision:
        decision = engine.decision(
            ProtectionAction.REVIEW,
            target=target if isinstance(target, str) else "",
            reason=f"The {engine.label} module could not evaluate this request: {error}",
            metadata={"policy": "module-error", "error": type(error).__name__},
        )
        return self._finish(decision, severity=Severity.HIGH)

    def _finish(
        self,
        decision: ProtectionDecision,
        *,
        severity: Severity | None = None,
    ) -> ProtectionDecision:
        if self._decision_escalator is not None:
            try:
                escalated = self._decision_escalator(decision)
                if isinstance(escalated, ProtectionDecision):
                    decision = escalated
            except Exception as exc:  # noqa: BLE001 - protection must keep working
                self._events.record(
                    EventCategory.PARANOIA,
                    Severity.MEDIUM,
                    "Paranoia restriction evaluation failed safely; the original "
                    "protection decision was kept.",
                    reason=f"{type(exc).__name__}: {exc}",
                    action="paranoia-error",
                )
        self._decisions.append(decision)
        self._stats["evaluations"] += 1
        self._stats[decision.action.value] += 1

        message = (
            f"{decision.module} {decision.action_label.upper()}: "
            f"{decision.target} \u2014 {decision.reason}"
        )
        if decision.rule is not None:
            message += f" [{decision.rule.describe()}]"

        self._events.record(
            EventCategory.PROTECTION,
            severity or _ACTION_SEVERITY[decision.action],
            message,
            module_id=MODULE_IDS_BY_LABEL.get(decision.module, ""),
            action=decision.action.value,
            target=decision.target,
        )
        self.changed.emit()
        self.decision_recorded.emit(decision)
        return decision
