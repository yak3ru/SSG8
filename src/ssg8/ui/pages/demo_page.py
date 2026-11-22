"""Controlled Demonstration Environment: browser, downloads, launcher, settings."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QWidget,
)

from ssg8.core.app_state import NOTIFICATION_CATEGORIES
from ssg8.services.paranoia.activities import (
    DEMO_DOWNLOADS,
    DEMO_SETTINGS,
    DEMO_WALLPAPERS,
    LAUNCHER_APPS,
)
from ssg8.services.paranoia.demo import DemoResult
from ssg8.ui import theme
from ssg8.ui.components.action_button import ActionButton
from ssg8.ui.components.chip import Chip, ChipCell
from ssg8.ui.components.data_table import DataTable
from ssg8.ui.components.dialog import confirm
from ssg8.ui.components.empty_state import EmptyState
from ssg8.ui.components.panel import ContentPanel
from ssg8.ui.components.search_input import SelectBox
from ssg8.ui.components.section_heading import PageIntro, muted_label
from ssg8.ui.pages.base_page import BasePage
from ssg8.utils.formatting import format_timestamp


def _outcome_tone(result: DemoResult) -> str:
    if result.blocked:
        return "danger"
    if result.needs_confirmation:
        return "warning"
    return "success"


class DemoPage(BasePage):
    """A safe sandbox where every action is evaluated inside CyberLockdown."""

    page_id = "demo"

    def build(self) -> None:
        self.body.addWidget(
            PageIntro(
                "Controlled Demo",
                "Exercise the existing protection engines inside a safe sandbox. Every "
                "action here is harmless and confined to CyberLockdown.",
            )
        )
        self.add_demo_notice(
            "Nothing on this page opens a real website, downloads a real file, launches a "
            "real application or changes the Windows wallpaper or settings. Simulated "
            "files live only in the demonstration's own temporary folder.",
            "warning",
            "alert",
        )

        self.body.addWidget(self._build_browser_panel())
        self.body.addWidget(self._build_download_panel())
        self.body.addWidget(self._build_launcher_panel())
        self.body.addWidget(self._build_personalization_panel())
        self.body.addWidget(self._build_settings_panel())
        self.body.addWidget(self._build_notification_panel())
        self.body.addWidget(self._build_monitor_panel())
        self.body.addWidget(self._build_result_panel())

        self.context.demo.changed.connect(self._refresh_results)
        self.context.monitor.changed.connect(self._refresh_monitor)
        self._refresh_monitor()
        self._refresh_results()

    # --- construction ------------------------------------------------------

    def _build_browser_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Controlled browser",
            "URLs are evaluated by the existing website engine. No network request is made.",
        )
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        self._url_input = QLineEdit(panel)
        self._url_input.setPlaceholderText("https://example.com/login")
        self._url_input.setMinimumHeight(34)
        self._url_input.returnPressed.connect(self._open_website)
        row.addWidget(self._url_input, 1)
        open_button = ActionButton("Open in controlled browser", "primary", "globe", panel)
        open_button.clicked.connect(self._open_website)
        row.addWidget(open_button)
        panel.body.addLayout(row)
        self._browser_result = self._result_label(panel)
        panel.body.addWidget(self._browser_result)
        return panel

    def _build_download_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Controlled downloads",
            "Requests are evaluated by the existing download engine against real policy "
            "rules and harmless demonstration files.",
        )
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        self._download_select = SelectBox(panel)
        self._download_select.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self._download_select.setMinimumContentsLength(10)
        self._download_select.add_options([(name, name) for name, _ in DEMO_DOWNLOADS])
        self._download_select.setToolTip(
            "Demonstration files: " + ", ".join(name for name, _ in DEMO_DOWNLOADS)
        )
        row.addWidget(self._download_select, 1)
        request_button = ActionButton("Request download", "primary", "download", panel)
        request_button.clicked.connect(self._request_download)
        row.addWidget(request_button)
        panel.body.addLayout(row)
        self._download_result = self._result_label(panel)
        panel.body.addWidget(self._download_result)
        return panel

    def _build_launcher_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Controlled application launcher",
            "Calculator, Notepad and Paint are harmless demonstration entries. Launches "
            "are simulated; no real process is started.",
        )
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        for app_key, label, _activity in LAUNCHER_APPS:
            button = ActionButton(label, "secondary", "apps", panel)
            button.clicked.connect(lambda _checked=False, key=app_key: self._launch(key))
            row.addWidget(button)
        row.addStretch(1)
        panel.body.addLayout(row)
        self._launcher_result = self._result_label(panel)
        panel.body.addWidget(self._launcher_result)
        return panel

    def _build_personalization_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Simulated personalization",
            "Choose a sample wallpaper inside CyberLockdown. The real Windows wallpaper "
            "is never read or changed.",
        )
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        self._wallpaper_select = SelectBox(panel)
        self._wallpaper_select.add_options(
            [(label, key) for key, label, _colour in DEMO_WALLPAPERS]
        )
        row.addWidget(self._wallpaper_select, 1)
        apply_button = ActionButton("Apply simulated wallpaper", "secondary", "refresh", panel)
        apply_button.clicked.connect(self._apply_wallpaper)
        row.addWidget(apply_button)
        panel.body.addLayout(row)

        self._wallpaper_preview = QFrame(panel)
        self._wallpaper_preview.setFixedHeight(54)
        self._set_preview_colour(DEMO_WALLPAPERS[0][2])
        panel.body.addWidget(self._wallpaper_preview)

        self._personalization_result = self._result_label(panel)
        panel.body.addWidget(self._personalization_result)
        return panel

    def _build_settings_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Simulated Windows settings",
            "These controls change demonstration preferences only. Windows settings are "
            "never read or changed.",
        )
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        open_button = ActionButton("Open simulated settings", "secondary", "sliders", panel)
        open_button.clicked.connect(self._open_settings)
        row.addWidget(open_button)

        self._setting_select = SelectBox(panel)
        self._setting_select.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self._setting_select.setMinimumContentsLength(8)
        self._setting_select.add_options([(label, key) for key, label in DEMO_SETTINGS])
        row.addWidget(self._setting_select, 1)
        panel.body.addLayout(row)

        value_row = QHBoxLayout()
        value_row.setContentsMargins(0, 0, 0, 0)
        value_row.setSpacing(10)
        value_row.addWidget(QLabel("Simulated theme", panel))
        self._setting_value = SelectBox(panel)
        self._setting_value.add_options([("Default", "Default"), ("Compact", "Compact"), ("Enhanced", "Enhanced")])
        value_row.addWidget(self._setting_value, 1)

        apply_button = ActionButton("Apply setting", "secondary", "check", panel)
        apply_button.clicked.connect(self._apply_setting)
        value_row.addWidget(apply_button)
        panel.body.addLayout(value_row)

        self._settings_result = self._result_label(panel)
        panel.body.addWidget(self._settings_result)
        return panel

    def _build_notification_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Demonstration notifications",
            "Only notifications generated inside this demonstration are evaluated.",
        )
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        self._notification_category = SelectBox(panel)
        self._notification_category.add_options(
            [(label, key) for key, label in NOTIFICATION_CATEGORIES]
        )
        row.addWidget(self._notification_category)
        self._notification_text = QLineEdit(panel)
        self._notification_text.setPlaceholderText("Demonstration notification text")
        self._notification_text.setMinimumHeight(34)
        row.addWidget(self._notification_text, 1)
        send_button = ActionButton("Simulate notification", "secondary", "bell", panel)
        send_button.clicked.connect(self._send_notification)
        row.addWidget(send_button)
        panel.body.addLayout(row)
        self._notification_result = self._result_label(panel)
        panel.body.addWidget(self._notification_result)
        return panel

    def _build_monitor_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Optional Windows activity awareness",
            "Read-only and disabled by default. Start it only if you want to demonstrate "
            "observation of selected real Windows activity.",
        )
        self._monitor_notice = muted_label(
            "Collected while enabled: process identifiers and executable names only. "
            "Not collected: command lines, file contents, keystrokes, screenshots, "
            "browser history, credentials, network traffic or private user data. "
            "CyberLockdown never terminates a process or changes process permissions."
        )
        panel.body.addWidget(self._monitor_notice)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        self._monitor_chip = Chip("DISABLED", "neutral", panel)
        row.addWidget(self._monitor_chip, 0, Qt.AlignmentFlag.AlignVCenter)
        self._monitor_status = QLabel("", panel)
        self._monitor_status.setObjectName("MutedText")
        self._monitor_status.setWordWrap(True)
        row.addWidget(self._monitor_status, 1)
        panel.body.addLayout(row)

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.setSpacing(8)
        buttons.addStretch(1)
        self._monitor_start = ActionButton("Start", "secondary", "activity", panel)
        self._monitor_start.clicked.connect(self._start_monitoring)
        buttons.addWidget(self._monitor_start)
        self._monitor_stop = ActionButton("Stop", "danger", "close", panel)
        self._monitor_stop.clicked.connect(self._stop_monitoring)
        buttons.addWidget(self._monitor_stop)
        self._monitor_refresh = ActionButton("Snapshot", "ghost", "refresh", panel)
        self._monitor_refresh.clicked.connect(self._refresh_snapshot)
        buttons.addWidget(self._monitor_refresh)
        panel.body.addLayout(buttons)

        self._monitor_snapshot = muted_label("")
        panel.body.addWidget(self._monitor_snapshot)
        return panel

    def _build_result_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Recent controlled activities",
            "Every evaluation is also recorded in Security Logs.",
        )
        self._result_table = DataTable(
            ["Time", "Area", "Outcome", "Detail"], panel, row_height=34
        )
        self._result_table.configure_columns({0: 140, 1: 170, 2: 100}, stretch=3)
        self._result_table.setMinimumHeight(140)
        self._result_empty = EmptyState(
            "apps",
            "No controlled activities yet",
            "Open a controlled website, request a demonstration download or launch a demo app.",
            minimum_height=130,
        )
        panel.body.addWidget(self._result_table)
        panel.body.addWidget(self._result_empty)
        self.register_empty_pair(self._result_table, self._result_empty)
        return panel

    # --- helpers -----------------------------------------------------------

    def _result_label(self, parent: QWidget) -> QLabel:
        label = QLabel("", parent)
        label.setObjectName("MutedText")
        label.setWordWrap(True)
        label.setMinimumHeight(32)
        return label

    def _show_result(self, result: DemoResult, label: QLabel) -> None:
        tone = theme.tone(_outcome_tone(result))
        text = result.message
        if result.warning:
            text = f"{text}\nWARNING: {result.warning}"
        label.setStyleSheet(f"color: {tone.text}; font-size: 8.5pt;")
        label.setText(text)
        self._refresh_results()

    def _set_preview_colour(self, colour: str) -> None:
        self._wallpaper_preview.setStyleSheet(
            f"background-color: {colour}; border: 1px solid {theme.BORDER_STRONG};"
            " border-radius: 5px;"
        )

    # --- browser -----------------------------------------------------------

    def _open_website(self) -> None:
        url = self._url_input.text().strip()
        if not url:
            self._browser_result.setText("Enter a demonstration URL first.")
            return
        result = self.context.demo.open_website(url)
        self._show_result(result, self._browser_result)

    # --- downloads ---------------------------------------------------------

    def _request_download(self) -> None:
        filename = self._download_select.current_value()
        if not filename:
            return
        result = self.context.demo.request_download(str(filename))
        if result.needs_confirmation:
            accepted = confirm(
                self,
                "Download requires review",
                "The current paranoia profile requires confirmation for this harmless "
                "demonstration download.\n\nAllow it once?",
                confirm_label="Allow once",
            )
            if accepted:
                self._download_result.setStyleSheet("")
                self._download_result.setText(
                    "Demonstration download permitted once after review. No real "
                    "download occurred."
                )
                self._refresh_results()
                return
            self._download_result.setText(
                "Demonstration download cancelled by the user after the REVIEW decision."
            )
            return
        self._show_result(result, self._download_result)

    # --- launcher ----------------------------------------------------------

    def _launch(self, app_key: str) -> None:
        preview = self.context.demo.launch_application(app_key)
        if preview.needs_confirmation:
            accepted = confirm(
                self,
                "Launch requires review",
                "The current paranoia profile requires review before this harmless "
                "demonstration launch.\n\nAllow this simulated launch once?",
                confirm_label="Allow once",
            )
            if not accepted:
                self._launcher_result.setText(
                    "Launch cancelled by the user after the REVIEW decision."
                )
                return
        self._launcher_result.setStyleSheet("")
        self._show_result(preview, self._launcher_result)

    # --- personalization and settings -------------------------------------

    def _apply_wallpaper(self) -> None:
        key = self._wallpaper_select.current_value()
        if not key:
            return
        result = self.context.demo.change_wallpaper(str(key))
        if result.allowed:
            colour = next(
                (colour for item_key, _label, colour in DEMO_WALLPAPERS if item_key == key),
                theme.SURFACE_RAISED,
            )
            self._set_preview_colour(colour)
        self._show_result(result, self._personalization_result)

    def _open_settings(self) -> None:
        result = self.context.demo.open_settings()
        self._show_result(result, self._settings_result)

    def _apply_setting(self) -> None:
        key = self._setting_select.current_value()
        value = self._setting_value.current_value()
        if not key or not value:
            return
        result = self.context.demo.apply_setting(str(key), str(value))
        self._show_result(result, self._settings_result)

    # --- notifications -----------------------------------------------------

    def _send_notification(self) -> None:
        category = self._notification_category.current_value()
        if not category:
            return
        message = self._notification_text.text().strip() or "Demonstration notification"
        result = self.context.demo.send_notification(str(category), message)
        self._show_result(result, self._notification_result)

    # --- monitoring --------------------------------------------------------

    def _start_monitoring(self) -> None:
        self.context.monitor.start()
        self._refresh_monitor()

    def _stop_monitoring(self) -> None:
        self.context.monitor.stop()
        self._refresh_monitor()

    def _refresh_snapshot(self) -> None:
        self.context.monitor.observe()
        self._refresh_monitor(show_snapshot=True)

    def _refresh_monitor(self, show_snapshot: bool = False) -> None:
        monitor = self.context.monitor
        enabled = monitor.enabled()
        self._monitor_chip.setText("ENABLED" if enabled else "DISABLED")
        self._monitor_chip.set_tone("success" if enabled else "neutral")
        self._monitor_status.setText(monitor.availability_note())
        if not monitor.available():
            self._monitor_status.setText(monitor.availability_note())
        self._monitor_start.setEnabled(monitor.available() and not enabled)
        self._monitor_stop.setEnabled(enabled)
        self._monitor_refresh.setEnabled(enabled)
        if show_snapshot and enabled:
            current = monitor.snapshot()
            names = ", ".join(process.name for process in current[:6])
            self._monitor_snapshot.setText(
                f"{len(current)} process name(s) observed. Showing up to six: {names}"
            )
        elif not enabled:
            self._monitor_snapshot.setText(
                "Monitoring is stopped. No real Windows activity is being observed."
            )

    # --- refresh -----------------------------------------------------------

    def _refresh_results(self) -> None:
        results = self.context.demo.recent_results(limit=10)
        self._result_table.clear_rows()
        for result in results:
            self._result_table.add_row(
                [
                    format_timestamp(result.timestamp),
                    result.title,
                    ChipCell(result.action.upper(), _outcome_tone(result)),
                    result.message,
                ],
                result,
            )
        if results:
            self._result_empty.set_content(
                "apps",
                "No controlled activities yet",
                "Open a controlled website, request a demonstration download or launch a demo app.",
            )
        self.sync_empty_states()

    # --- convenience for tests --------------------------------------------

    def open_website(self, url: str) -> DemoResult:
        self._url_input.setText(url)
        result = self.context.demo.open_website(url)
        self._show_result(result, self._browser_result)
        return result

    def request_download(self, filename: str) -> DemoResult:
        result = self.context.demo.request_download(filename)
        self._show_result(result, self._download_result)
        return result

    def launch_application(self, app_key: str) -> DemoResult:
        result = self.context.demo.launch_application(app_key)
        self._show_result(result, self._launcher_result)
        return result

    def apply_wallpaper(self, key: str) -> DemoResult:
        result = self.context.demo.change_wallpaper(key)
        self._show_result(result, self._personalization_result)
        return result

    def visible_results(self) -> int:
        return self._result_table.rowCount()

    def monitoring_enabled(self) -> bool:
        return self.context.monitor.enabled()
