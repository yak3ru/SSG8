"""Settings: interface preferences that stay inside SSG8."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QVBoxLayout, QWidget

from ssg8 import __version__
from ssg8.core.models import EventCategory, Severity
from ssg8.security.policies import (
    SUBDOMAIN_LABELS,
    SUBDOMAIN_MODES,
    UNKNOWN_FILE_ACTIONS,
    UNKNOWN_FILE_LABELS,
    ProtectionSettings,
    normalise_extensions,
)
from ssg8.storage.preferences import SETTING_LABELS
from ssg8.ui import theme
from ssg8.ui.components.action_button import ActionButton
from ssg8.ui.components.dialog import confirm
from ssg8.ui.components.info_list import ColourSwatch, InfoList
from ssg8.ui.components.panel import ContentPanel
from ssg8.ui.components.search_input import SelectBox
from ssg8.ui.components.section_heading import PageIntro, field_label, muted_label
from ssg8.ui.components.toggle_switch import ToggleSwitch
from ssg8.ui.pages.base_page import BasePage
from ssg8.utils.formatting import shorten_path

PREFERENCE_ORDER: tuple[str, ...] = (
    "confirm_before_delete",
    "record_navigation",
)

PREFERENCE_HELP: dict[str, str] = {
    "confirm_before_delete": "Ask before removing a configuration entry.",
    "record_navigation": "Add page navigation to the application event log.",
}


class SettingsPage(BasePage):
    """Appearance information and safe, local preferences."""

    page_id = "settings"

    def __init__(self, context, parent=None) -> None:
        super().__init__(context, parent)
        self._switches: dict[str, ToggleSwitch] = {}

    def build(self) -> None:
        self.body.addWidget(
            PageIntro(
                "Settings",
                "These preferences belong to the SSG8 interface. They are stored in a local "
                "configuration file and never change Windows behaviour.",
            )
        )


        self.body.addWidget(self._build_appearance_panel())
        self.body.addWidget(self._build_general_panel())
        self.body.addWidget(self._build_protection_panel())
        self.body.addWidget(self._build_startup_panel())
        self.body.addWidget(self._build_configuration_panel())

    # --- panels ------------------------------------------------------------

    def _build_appearance_panel(self) -> ContentPanel:
        panel = ContentPanel("Appearance", "The interface theme is fixed in this build.")

        preview = QWidget(panel)
        row = QHBoxLayout(preview)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        swatches = QHBoxLayout()
        swatches.setContentsMargins(0, 0, 0, 0)
        swatches.setSpacing(6)
        for colour, name in (
            (theme.BACKGROUND, "Background"),
            (theme.SURFACE, "Panel"),
            (theme.BORDER_STRONG, "Border"),
            (theme.ACCENT, "Accent"),
        ):
            swatches.addWidget(ColourSwatch(colour, preview))
            label = QLabel(name, preview)
            label.setObjectName("MutedText")
            swatches.addWidget(label)
            swatches.addSpacing(8)
        row.addLayout(swatches)
        row.addStretch(1)
        panel.body.addWidget(preview)

        info = InfoList(panel)
        info.add_row("Theme", "SSG8 Dark (fixed)")
        info.add_row("Accent colour", f"Deep security red ({theme.ACCENT})")
        info.add_row("Typography", "Segoe UI with monospaced values")
        info.add_row("Application version", __version__)
        panel.body.addWidget(info)
        return panel

    def _build_general_panel(self) -> ContentPanel:
        panel = ContentPanel("General preferences", "Stored locally for this user account.")

        for index, key in enumerate(PREFERENCE_ORDER):
            if index:
                panel.add_divider()
            panel.body.addWidget(self._preference_row(panel, key))
        return panel

    def _preference_row(self, parent: QWidget, key: str) -> QWidget:
        row_widget = QWidget(parent)
        row = QHBoxLayout(row_widget)
        row.setContentsMargins(0, 4, 0, 4)
        row.setSpacing(12)

        text_column = QVBoxLayout()
        text_column.setContentsMargins(0, 0, 0, 0)
        text_column.setSpacing(2)

        title = QLabel(SETTING_LABELS.get(key, key), row_widget)
        title.setObjectName("ValueText")
        title.setWordWrap(True)
        text_column.addWidget(title)

        description = QLabel(PREFERENCE_HELP.get(key, ""), row_widget)
        description.setObjectName("MutedText")
        description.setWordWrap(True)
        text_column.addWidget(description)

        row.addLayout(text_column, 1)

        switch = ToggleSwitch(
            row_widget,
            checked=self.context.preferences.get(key),
            tone="success",
        )
        switch.setAccessibleName(SETTING_LABELS.get(key, key))
        switch.toggled.connect(lambda checked, name=key: self._set_preference(name, checked))
        self._switches[key] = switch
        row.addWidget(switch, 0, Qt.AlignmentFlag.AlignVCenter)
        return row_widget

    # --- protection policy -------------------------------------------------

    def _build_protection_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Protection policy",
            "Applied by the internal engines only. Stored in protection_settings.json.",
        )

        info = InfoList(panel)
        settings_path = str(self.context.protection.store.settings_path)
        settings_value = info.add_row(
            "Settings file", shorten_path(settings_path, 30), mono=True
        )
        settings_value.setToolTip(settings_path)
        info.add_row("Engine scope", "Requests submitted to SSG8 only")
        panel.body.addWidget(info)
        panel.add_divider()

        panel.body.addWidget(field_label("Maximum inspected file size (MB)"))
        size_row = QHBoxLayout()
        size_row.setContentsMargins(0, 0, 0, 0)
        size_row.setSpacing(8)

        self._size_input = QLineEdit(panel)
        self._size_input.setFixedWidth(100)
        self._size_input.setMinimumHeight(34)
        size_row.addWidget(self._size_input)
        size_row.addWidget(muted_label("1 to 4096 MB", wrap=False))
        size_row.addStretch(1)
        panel.body.addLayout(size_row)

        panel.body.addWidget(field_label("Subdomain matching"))
        self._subdomain_select = SelectBox(panel)
        self._subdomain_select.add_options(
            [(SUBDOMAIN_LABELS[mode], mode) for mode in SUBDOMAIN_MODES]
        )
        panel.body.addWidget(self._subdomain_select)

        panel.body.addWidget(field_label("Unknown file types"))
        self._unknown_select = SelectBox(panel)
        self._unknown_select.add_options(
            [(UNKNOWN_FILE_LABELS[action], action) for action in UNKNOWN_FILE_ACTIONS]
        )
        panel.body.addWidget(self._unknown_select)

        panel.body.addWidget(field_label("Prohibited file extensions"))
        self._extensions_input = QLineEdit(panel)
        self._extensions_input.setPlaceholderText(".exe, .ps1, .scr")
        self._extensions_input.setMinimumHeight(34)
        panel.body.addWidget(self._extensions_input)
        panel.body.addWidget(
            muted_label(
                "Comma or space separated, for example .exe, .msi, .ps1. "
                "These extensions produce a BLOCK decision during inspection."
            )
        )

        self._policy_error = QLabel("", panel)
        self._policy_error.setStyleSheet(f"color: {theme.tone('danger').text};")
        self._policy_error.setWordWrap(True)
        self._policy_error.setVisible(False)
        panel.body.addWidget(self._policy_error)

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.setSpacing(8)
        buttons.addStretch(1)

        defaults = ActionButton("Restore defaults", "secondary", "refresh", panel)
        defaults.clicked.connect(self._restore_protection_defaults)
        buttons.addWidget(defaults)

        save = ActionButton("Save policy", "primary", "check", panel)
        save.clicked.connect(self._save_protection_policy)
        buttons.addWidget(save)

        panel.body.addLayout(buttons)
        self._refresh_protection_fields()
        return panel

    def _refresh_protection_fields(self) -> None:
        settings = self.context.protection.settings()
        self._size_input.setText(str(settings.max_file_size_mb))
        self._extensions_input.setText(", ".join(settings.blocked_extensions))
        self._subdomain_select.setCurrentIndex(
            max(0, self._subdomain_select.findData(settings.subdomain_matching))
        )
        self._unknown_select.setCurrentIndex(
            max(0, self._unknown_select.findData(settings.unknown_file_action))
        )

    def _show_policy_error(self, message: str | None) -> None:
        self._policy_error.setText(message or "")
        self._policy_error.setVisible(bool(message))

    def _save_protection_policy(self) -> None:
        size_text = self._size_input.text().strip()
        if not size_text.isdigit():
            self._show_policy_error("Enter the maximum file size as a whole number of MB.")
            return

        extension_text = self._extensions_input.text()
        error = self.context.protection.extension_error(extension_text)
        if error:
            self._show_policy_error(error)
            return

        ok, message = self.context.protection.update_settings(
            max_file_size_mb=int(size_text),
            subdomain_matching=self._subdomain_select.current_value(),
            unknown_file_action=self._unknown_select.current_value(),
            blocked_extensions=normalise_extensions(extension_text),
        )
        self._show_policy_error(None if ok else message)
        if ok:
            self._refresh_protection_fields()

    def _restore_protection_defaults(self) -> None:
        accepted = confirm(
            self,
            "Restore protection defaults",
            "Restore the default internal protection policy?",
            confirm_label="Restore defaults",
        )
        if not accepted:
            return

        defaults = ProtectionSettings()
        ok, message = self.context.protection.update_settings(
            max_file_size_mb=defaults.max_file_size_mb,
            subdomain_matching=defaults.subdomain_matching,
            unknown_file_action=defaults.unknown_file_action,
            blocked_extensions=defaults.blocked_extensions,
        )
        self._show_policy_error(None if ok else message)
        self._refresh_protection_fields()

    def _build_startup_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Startup behaviour",
            "Reported honestly for this build.",
        )
        info = InfoList(panel)
        info.add_row("Automatic startup", "Not implemented")
        info.add_row("Background processes", "None \u2014 SSG8 runs only while open")
        info.add_row("System service", "Not installed")
        info.add_row("Elevation", "Not requested")
        panel.body.addWidget(info)
        return panel

    def _build_configuration_panel(self) -> ContentPanel:
        panel = ContentPanel(
            "Configuration file",
            "Interface preferences only. No security policy is stored here.",
        )

        info = InfoList(panel, label_width=150)
        preferences_path = str(self.context.preferences.path)
        location = info.add_row(
            "Location", shorten_path(preferences_path, 34), mono=True
        )
        location.setToolTip(preferences_path)

        errors = self.context.preferences.load_errors()
        if errors:
            info.add_row("Last error", errors[-1])

        panel.body.addWidget(info)

        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.addStretch(1)

        reset = ActionButton("Restore defaults", "secondary", "refresh", panel)
        reset.clicked.connect(self._reset_preferences)
        buttons.addWidget(reset)

        panel.body.addLayout(buttons)
        return panel

    # --- actions -----------------------------------------------------------

    def _set_preference(self, key: str, checked: bool) -> None:
        self.context.preferences.set(key, checked)
        self.context.events.record(
            EventCategory.PREFERENCE,
            Severity.INFO,
            f"Preference '{key}' set to {checked}",
        )

    def _reset_preferences(self) -> None:
        accepted = confirm(
            self,
            "Restore defaults",
            "Restore the default SSG8 interface preferences?",
            confirm_label="Restore defaults",
        )
        if not accepted:
            return

        self.context.preferences.reset()
        for key, switch in self._switches.items():
            switch.set_state_silently(self.context.preferences.get(key))
        self.context.events.record(
            EventCategory.PREFERENCE,
            Severity.INFO,
            "Interface preferences restored to defaults",
        )

    def on_shown(self) -> None:
        for key, switch in self._switches.items():
            switch.set_state_silently(self.context.preferences.get(key))
        self._refresh_protection_fields()
