"""Application Protection: a single switch and a harmless built-in test window.

No manual application approvals or security-assessment controls.
"""
from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QDialog, QLabel, QVBoxLayout

from ssg8.ui.pages.base_page import BasePage
from ssg8.ui.components.panel import ContentPanel
from ssg8.ui.components.section_heading import PageIntro
from ssg8.ui.components.protection import ProtectionModuleRow
from ssg8.ui.components.action_button import ActionButton


class ApplicationsPage(BasePage):
    page_id = "applications"

    def build(self) -> None:
        self._sample_windows: list[QDialog] = []
        self.body.addWidget(PageIntro(
            "Application Protection",
            "Automatically requests that ordinary app windows close when protection is enabled.",
        ))

        protection = ContentPanel(
            "Protection Status",
            "Use the switch to start or stop automatic window closing.",
        )
        protection.body.addWidget(ProtectionModuleRow(
            self.context.protection, "application", protection,
            description=(
                "Requests normal window closure for ordinary applications, including "
                "File Explorer folder windows and Settings. VS Code, SSG8, and Windows "
                "recovery/administration controls stay accessible."
            ),
        ))
        self.body.addWidget(protection)

        actions = ContentPanel(
            "Window Closing Test",
            "Open a harmless test window to verify the protection switch.",
        )
        self.test_button = ActionButton(
            "Open Sample Window", "secondary", "apps", actions
        )
        self.test_button.clicked.connect(self.open_test_window)
        actions.body.addWidget(self.test_button)
        self.feedback = QLabel("", actions)
        self.feedback.setWordWrap(True)
        self.feedback.setObjectName("MutedText")
        actions.body.addWidget(self.feedback)
        self.body.addWidget(actions)

        # Quick link into the same page as the new sidebar entry.
        scan_panel = ContentPanel(
            "Malware Scanner",
            "Run SSG8's satirical, read-only application inventory.",
        )
        self.malware_scan_button = ActionButton(
            "Scan for Malware", "secondary", "search", scan_panel
        )
        self.malware_scan_button.clicked.connect(
            lambda: self.navigate_to("malware-scan")
        )
        scan_panel.body.addWidget(self.malware_scan_button)
        self.body.addWidget(scan_panel)

        self.context.protection.modules_changed.connect(self._on_protection_changed)
        self.refresh()

    def _enabled(self) -> bool:
        return self.context.protection.is_module_enabled("application")

    def _on_protection_changed(self) -> None:
        if self._enabled():
            for window in tuple(self._sample_windows):
                if window.isVisible():
                    window.close()
        self.refresh()

    def open_test_window(self) -> None:
        sample = QDialog(self)
        sample.setWindowTitle("SSG8 Sample Application")
        sample.setMinimumWidth(370)
        layout = QVBoxLayout(sample)
        layout.addWidget(QLabel("This is a harmless SSG8-owned sample window.", sample))
        self._sample_windows.append(sample)
        self._sample_window = sample
        sample.finished.connect(lambda _code, w=sample: self._remove_sample(w))
        sample.show()
        if self._enabled():
            QTimer.singleShot(200, sample.close)

    def _remove_sample(self, window: QDialog) -> None:
        if window in self._sample_windows:
            self._sample_windows.remove(window)
        window.deleteLater()

    def refresh(self) -> None:
        self.feedback.setText(
            "Protection ON. Ordinary application windows will receive a normal close "
            "request. Save prompts may still appear. Turn protection OFF to stop."
            if self._enabled()
            else "Protection OFF. Applications will not receive close requests from SSG8."
        )

    def on_shown(self) -> None:
        self.refresh()
