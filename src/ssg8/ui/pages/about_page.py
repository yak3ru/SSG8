"""About SSG8: project information without invented credentials."""

from __future__ import annotations

import sys

import PySide6
from PySide6 import QtCore
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from ssg8 import __version__
from ssg8.ui import theme
from ssg8.ui.components.chip import Chip
from ssg8.ui.components.info_list import InfoList
from ssg8.ui.components.notice_banner import NoticeBanner
from ssg8.ui.components.panel import ContentPanel
from ssg8.ui.components.section_heading import PageIntro
from ssg8.ui.pages.base_page import BasePage

DESCRIPTION = (
    "SSG8 is a Windows application security monitor with local policy evaluation, "
    "incident analysis and an application-only protection workflow."
)
DESCRIPTION_SECOND = (
    "When enabled, SSG8 reads names of newly opened Windows application windows "
    "and flags them for review. Only its own sample window is closed automatically. "
    "It does not close unrelated Windows windows, modify system settings, or require administrator privileges."
)


class AboutPage(BasePage):
    """Branding, build details and an honest development status."""

    page_id = "about"

    def build(self) -> None:
        self.body.addWidget(
            PageIntro(
                "About SSG8",
                "Project information for this development build.",
            )
        )

        self.body.addWidget(self._build_brand_panel())
        self.body.addWidget(self._build_description_panel())
        self.body.addWidget(self._build_details_panel())

        self.body.addWidget(
            NoticeBanner(
                "No company certification, security certification or external partnership "
                "is claimed for this project.",
                "neutral",
                "info",
                self,
            )
        )

    # --- construction ------------------------------------------------------

    def _build_brand_panel(self) -> ContentPanel:
        panel = ContentPanel()
        panel.setMinimumHeight(104)

        row = QHBoxLayout()
        row.setContentsMargins(0, 4, 0, 4)
        row.setSpacing(16)

        mark = QWidget(panel)
        mark.setFixedSize(48, 48)
        mark.setStyleSheet(f"background-color: {theme.ACCENT}; border-radius: 11px;")
        mark_layout = QVBoxLayout(mark)
        mark_layout.setContentsMargins(0, 0, 0, 0)
        initial = QLabel("S", mark)
        initial.setAlignment(Qt.AlignmentFlag.AlignCenter)
        initial.setStyleSheet("color: #FFFFFF; font-size: 20pt; font-weight: 700;")
        mark_layout.addWidget(initial)
        row.addWidget(mark, 0, Qt.AlignmentFlag.AlignVCenter)

        text_column = QVBoxLayout()
        text_column.setContentsMargins(0, 0, 0, 0)
        text_column.setSpacing(3)

        title = QLabel("SSG8", panel)
        title.setStyleSheet("font-size: 19pt; font-weight: 700;")
        text_column.addWidget(title)

        subtitle = QLabel("Security Control Center", panel)
        subtitle.setObjectName("MutedText")
        text_column.addWidget(subtitle)

        row.addLayout(text_column)
        row.addStretch(1)

        row.addWidget(Chip(f"v{__version__}", "accent", panel), 0, Qt.AlignmentFlag.AlignVCenter)
        row.addWidget(Chip("Dev build", "neutral", panel), 0, Qt.AlignmentFlag.AlignVCenter)

        panel.body.addLayout(row)
        return panel

    def _build_description_panel(self) -> ContentPanel:
        panel = ContentPanel("What SSG8 is")

        first = QLabel(DESCRIPTION, panel)
        first.setObjectName("ValueText")
        first.setWordWrap(True)
        panel.body.addWidget(first)

        second = QLabel(DESCRIPTION_SECOND, panel)
        second.setObjectName("MutedText")
        second.setWordWrap(True)
        panel.body.addWidget(second)
        return panel

    def _build_details_panel(self) -> ContentPanel:
        panel = ContentPanel("Project details")

        info = InfoList(panel)
        info.add_row("Project", "SSG8 \u2014 Security Control Center")
        info.add_row("Version", __version__)
        info.add_row("Build type", "Development build (not packaged)")
        info.add_row(
            "Technology",
            f"Python {sys.version.split()[0]} \u00b7 PySide6 {PySide6.__version__} "
            f"\u00b7 Qt {QtCore.qVersion()}",
        )
        info.add_row("Interface", "PySide6 desktop widgets")
        info.add_row("Target platform", "Windows 10 / 11")
        info.add_row(
            "Development status",
            "Phase 6 \u2014 paranoia progression, maximum paranoia, self-audit, "
            "self-quarantine and recovery. Everything applies only inside SSG8; Windows "
            "is never modified.",
        )
        info.add_row(
            "Demonstration identity",
            "CyberLockdown \u2014 Maximum Security. Minimum Freedom.",
        )
        info.add_row(
            "Project repository",
            "github.com/lockdown3000/demo-repository",
            mono=True,
        )
        panel.body.addWidget(info)
        return panel
