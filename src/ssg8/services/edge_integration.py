"""Qt adapter for Edge's localhost-only navigation notifications."""
from __future__ import annotations

from PySide6.QtCore import QObject, QTimer

from ssg8.services.edge_bridge import EdgeBridge


class EdgeIntegration(QObject):
    """Move queued browser attempts onto the Qt UI thread safely."""

    def __init__(self, protection, events, parent: QObject | None = None):
        super().__init__(parent)
        self.protection = protection
        self.events = events
        self.bridge = EdgeBridge()
        self.started = False
        self._timer = QTimer(self)
        self._timer.setInterval(150)
        self._timer.timeout.connect(self._drain)
        self.protection.modules_changed.connect(self._sync_status)

        try:
            self.bridge.start()
            self.started = True
            self._sync_status()
            self._timer.start()
        except OSError:
            # The app must still open if another process owns the bridge port.
            # An extension cannot enforce remote rules without a running bridge.
            from ssg8.core.models import EventCategory, Severity
            self.events.record(
                EventCategory.PROTECTION,
                Severity.MEDIUM,
                "Edge integration unavailable; local connection port is occupied.",
                source="Edge integration",
            )

    def _sync_status(self) -> None:
        self.bridge.set_website_enabled(
            self.protection.is_module_enabled("website")
        )

    def _drain(self) -> None:
        # Prevent a browser flood from freezing the desktop UI.
        for _ in range(20):
            url = self.bridge.pop_attempt()
            if url is None:
                break
            # This flows through the existing decision_recorded signal,
            # so AutonomousController receives and scores the event.
            self.protection.evaluate_website(url)

    def stop(self) -> None:
        self._timer.stop()
        self.bridge.set_website_enabled(False)
        self.bridge.stop()
        self.started = False
