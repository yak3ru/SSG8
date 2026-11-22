"""Page registry.

Each page lives in its own module and is looked up here by its page id. Pages
never import the main window, which keeps the import graph acyclic.
"""

from __future__ import annotations

from PySide6.QtWidgets import QWidget

from ssg8.core.context import AppContext
from ssg8.ui.pages.about_page import AboutPage
from ssg8.ui.pages.applications_page import ApplicationsPage
from ssg8.ui.pages.base_page import BasePage
from ssg8.ui.pages.dashboard_page import DashboardPage
from ssg8.ui.pages.demo_page import DemoPage
from ssg8.ui.pages.downloads_page import DownloadsPage
from ssg8.ui.pages.incidents_page import IncidentsPage
from ssg8.ui.pages.lockdown_page import LockdownPage
from ssg8.ui.pages.logs_page import LogsPage
from ssg8.ui.pages.malware_scan_page import MalwareScanPage
from ssg8.ui.pages.notifications_page import NotificationsPage
from ssg8.ui.pages.paranoia_page import ParanoiaPage
from ssg8.ui.pages.recovery_page import RecoveryPage
from ssg8.ui.pages.settings_page import SettingsPage
from ssg8.ui.pages.threat_monitor_page import ThreatMonitorPage
from ssg8.ui.pages.websites_page import WebsitesPage

PAGE_CLASSES: dict[str, type[BasePage]] = {
    DashboardPage.page_id: DashboardPage,
    ApplicationsPage.page_id: ApplicationsPage,
    MalwareScanPage.page_id: MalwareScanPage,
    ThreatMonitorPage.page_id: ThreatMonitorPage,
    IncidentsPage.page_id: IncidentsPage,
    LogsPage.page_id: LogsPage,
    RecoveryPage.page_id: RecoveryPage,
    AboutPage.page_id: AboutPage,
}


def create_page(page_id: str, context: AppContext, parent: QWidget | None = None) -> BasePage:
    """Instantiate the page registered under ``page_id``."""
    page_class = PAGE_CLASSES.get(page_id)
    if page_class is None:
        raise KeyError(f"Unknown page id: {page_id}")
    return page_class(context, parent)


__all__ = ["BasePage", "PAGE_CLASSES", "create_page"]
