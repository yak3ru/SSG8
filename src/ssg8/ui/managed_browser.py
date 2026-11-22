"""Optional embedded browser with real in-app navigation and download decisions.

Only this Qt WebEngine session is controlled. No system proxy, firewall,
OS notifications, process termination or browser extension is involved.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from PySide6.QtCore import QUrl, QTimer
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox

from ssg8.security.decisions import ProtectionAction


def open_managed_browser(protection, parent=None):
    """Return a managed browser dialog or raise ImportError if WebEngine is unavailable."""
    # Lazy imports keep the rest of SSG8 usable without the optional QtWebEngine binaries.
    from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile
    from PySide6.QtWebEngineWidgets import QWebEngineView

    class PolicyPage(QWebEnginePage):
        def __init__(self, profile, owner):
            super().__init__(profile, owner)
            self.owner = owner

        def acceptNavigationRequest(self, url, navigation_type, is_main_frame):  # noqa: N802
            # Do not handle non-web protocols, and keep internal blank pages functional.
            if url.scheme().lower() == "about":
                return True
            if url.scheme().lower() not in ("https", "http"):
                self.owner.report("Unsupported external navigation was refused.")
                return False
            if not is_main_frame:
                return True
            verdict = protection.evaluate_website(url.toString())
            self.owner.last_decision = verdict
            if verdict.action is not ProtectionAction.ALLOW:
                self.owner.report(f"{verdict.action_label}: {verdict.reason}")
                return False
            self.owner.report("Navigation authorized.")
            return True

        def createWindow(self, _type):  # noqa: N802
            self.owner.report("Pop-up windows are disabled in this browser.")
            return None

    class Browser(QDialog):
        def __init__(self):
            super().__init__(parent)
            self.setWindowTitle("SSG8 — Managed Browser")
            self.resize(980, 700)
            self.last_decision = None
            self._downloads = tempfile.TemporaryDirectory(prefix="ssg8-managed-")
            self._profile = QWebEngineProfile(self)  # off-the-record, no persistent cookies
            self._profile.downloadRequested.connect(self._download_requested)
            self._page = PolicyPage(self._profile, self)
            self._view = QWebEngineView(self)
            self._view.setPage(self._page)
            self._address = QLineEdit(self)
            self._address.setPlaceholderText("https://example.com")
            self._address.returnPressed.connect(self.navigate)
            open_button = QPushButton("Open", self)
            open_button.clicked.connect(self.navigate)
            row = QHBoxLayout()
            row.addWidget(self._address, 1)
            row.addWidget(open_button)
            self._status = QLabel("Enter an address to request navigation.", self)
            self._status.setWordWrap(True)
            col = QVBoxLayout(self)
            col.addLayout(row)
            col.addWidget(self._view, 1)
            col.addWidget(self._status)
            self._view.setUrl(QUrl("about:blank"))

        def report(self, message: str):
            self._status.setText(message)
            if any(s in message for s in ("Blocked", "BLOCK", "REVIEW", "denied", "refused")):
                # Defer dialogs until after Qt finishes the navigation callback.
                QTimer.singleShot(0, lambda: QMessageBox.warning(self, "SSG8 Security Notice", message)
                                  if self.isVisible() else None)

        def navigate(self):
            text = self._address.text().strip()
            if not text:
                return
            if "://" not in text:
                text = "https://" + text
            self._view.setUrl(QUrl(text))

        def _download_requested(self, download):
            filename = Path(download.downloadFileName()).name or "download.bin"
            target = Path(self._downloads.name) / filename
            # This inspection is pre-download: no file bytes exist yet. An
            # unmatched policy can correctly require REVIEW, which is denied here.
            verdict = protection.evaluate_download(str(target))
            if verdict.action is not ProtectionAction.ALLOW:
                download.cancel()
                self.report(f"DOWNLOAD REJECTED: {verdict.reason}")
                return
            download.setDownloadDirectory(str(target.parent))
            download.setDownloadFileName(filename)
            download.accept()
            self.report("Managed download authorized into temporary application storage.")

        def closeEvent(self, event):  # noqa: N802
            # Qt owns the WebEngine profile/page. Do not tear those objects
            # down inside an in-flight navigation callback.
            try:
                self._view.stop()
                self._downloads.cleanup()
            except OSError:
                # Windows may temporarily hold a permitted download open.
                # Temporary OS storage is cleaned when its handles are closed.
                pass
            super().closeEvent(event)

    return Browser()
