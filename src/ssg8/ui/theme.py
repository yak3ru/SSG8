"""Visual identity for the SSG8 desktop interface.

This module owns the palette, the typography helpers and the global Qt style
sheet. Every widget inherits from here so the interface stays consistent.
"""

from __future__ import annotations

from dataclasses import dataclass
from string import Template
from typing import Final

from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QApplication

from ssg8.core.models import Severity

# --- Palette -----------------------------------------------------------------

BACKGROUND: Final = "#0A0A0C"
SIDEBAR_BG: Final = "#0C0C0F"
SURFACE: Final = "#121216"
SURFACE_RAISED: Final = "#17171C"
SURFACE_HOVER: Final = "#1C1C22"
SURFACE_ACTIVE: Final = "#22222A"
TABLE_HEADER_BG: Final = "#101014"
INPUT_BG: Final = "#0F0F13"

BORDER: Final = "#232329"
BORDER_STRONG: Final = "#2E2E36"
BORDER_HOVER: Final = "#3E3E49"

TEXT_PRIMARY: Final = "#F0F0F3"
TEXT_SECONDARY: Final = "#A8A8B3"
TEXT_MUTED: Final = "#74747F"
TEXT_FAINT: Final = "#57575F"

ACCENT: Final = "#B0202B"
ACCENT_HOVER: Final = "#C42A36"
ACCENT_PRESSED: Final = "#8C1822"
ACCENT_TEXT: Final = "#F4C7CB"

SUCCESS: Final = "#3FB950"
WARNING: Final = "#D9A430"
DANGER: Final = "#E5484D"
INFO: Final = "#6E93C8"

RADIUS_PANEL: Final = 8
RADIUS_CONTROL: Final = 6

# --- Typography --------------------------------------------------------------

UI_FONT_FAMILY: Final = "Segoe UI"
MONO_FONT_FAMILIES: Final = ("Cascadia Mono", "Consolas", "Courier New")
BODY_POINT_SIZE: Final = 10


def with_letter_spacing(font: QFont, spacing: float) -> QFont:
    """Return ``font`` with absolute letter spacing applied."""
    font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, spacing)
    return font


def refresh_style(widget: object) -> None:
    """Re-apply the style sheet after a dynamic property changed."""
    style = widget.style()  # type: ignore[attr-defined]
    style.unpolish(widget)
    style.polish(widget)
    widget.update()  # type: ignore[attr-defined]


def mono_font(point_size: float = 9.0, bold: bool = False) -> QFont:
    """Return a monospaced font available on this machine."""
    available = set(QFontDatabase.families())
    family = next((f for f in MONO_FONT_FAMILIES if f in available), "Courier New")
    font = QFont(family)
    font.setPointSizeF(point_size)
    font.setBold(bold)
    return font


# --- Semantic tones ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Tone:
    """Foreground, background and border colours for a semantic state."""

    text: str
    background: str
    border: str


TONES: Final[dict[str, Tone]] = {
    "neutral": Tone(TEXT_SECONDARY, SURFACE_RAISED, BORDER_STRONG),
    "accent": Tone("#E9A0A6", "#2A1417", "#4A1E24"),
    "success": Tone("#7FD99A", "#12241A", "#24462E"),
    "warning": Tone("#E5C078", "#241D10", "#453617"),
    "danger": Tone("#EE9296", "#261416", "#4A2327"),
    "info": Tone("#9DBBE4", "#141B26", "#24344A"),
}

SEVERITY_TONES: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "danger",
    Severity.HIGH: "accent",
    Severity.MEDIUM: "warning",
    Severity.LOW: "info",
    Severity.INFO: "neutral",
}


def tone(name: str) -> Tone:
    """Return the tone named ``name``, falling back to neutral."""
    return TONES.get(name, TONES["neutral"])


def severity_tone(severity: Severity) -> str:
    """Return the tone name used for a severity level."""
    return SEVERITY_TONES.get(severity, "neutral")


def tone_style_sheet(name: str, *, radius: int = 4, padding: str = "3px 9px") -> str:
    """Return a small self-contained style sheet for a tinted label."""
    palette = tone(name)
    return (
        f"background-color: {palette.background};"
        f" border: 1px solid {palette.border};"
        f" border-radius: {radius}px;"
        f" color: {palette.text};"
        f" padding: {padding};"
    )


# --- Global style sheet ------------------------------------------------------

_STYLE_TEMPLATE = Template(
    """
/* ---------- base ---------- */
QMainWindow, QDialog, QMessageBox {
    background-color: $background;
}
QWidget {
    color: $text_primary;
}
QWidget#Root {
    background-color: $background;
}
QWidget#PageContent {
    background-color: transparent;
}
QLabel {
    background: transparent;
}

/* ---------- sidebar ---------- */
QFrame#Sidebar {
    background-color: $sidebar_bg;
    border-right: 1px solid $border;
}
QLabel#BrandTitle {
    font-size: 13pt;
    font-weight: 700;
    color: $text_primary;
}
QLabel#BrandSubtitle {
    font-size: 8.5pt;
    color: $text_muted;
}
QLabel#BrandInitial {
    color: #FFFFFF;
    font-size: 12pt;
    font-weight: 700;
}
QLabel#NavSectionLabel {
    font-size: 7.5pt;
    font-weight: 700;
    color: $text_faint;
    padding: 16px 16px 6px 18px;
}
QFrame#SidebarFooter {
    border-top: 1px solid $border;
}
QLabel#SidebarMeta {
    font-size: 8pt;
    color: $text_faint;
}

/* ---------- navigation ---------- */
QPushButton#NavItem {
    background-color: transparent;
    border: none;
    border-left: 2px solid transparent;
    border-radius: 0px;
    color: $text_secondary;
    font-size: 9.5pt;
    font-weight: 500;
    padding: 0px 12px 0px 14px;
    text-align: left;
}
QPushButton#NavItem:hover {
    background-color: #15151A;
    color: $text_primary;
}
QPushButton#NavItem:checked {
    background-color: #17171C;
    border-left: 2px solid $accent;
    color: $text_primary;
    font-weight: 600;
}

/* ---------- top header ---------- */
QFrame#TopHeader {
    background-color: $background;
    border-bottom: 1px solid $border;
}
QLabel#Breadcrumb {
    font-size: 7.5pt;
    font-weight: 700;
    color: $text_faint;
}
QLabel#PageTitle {
    font-size: 15pt;
    font-weight: 600;
    color: $text_primary;
}
QFrame#HeaderDivider {
    background-color: $border_strong;
}
QFrame#LockdownStrip {
    background-color: #1E1113;
    border-bottom: 1px solid #4A2327;
}
QLabel#LockdownStripText {
    color: #EE9296;
    font-size: 9pt;
    font-weight: 600;
}

/* ---------- footer ---------- */
QFrame#AppFooter {
    background-color: $sidebar_bg;
    border-top: 1px solid $border;
}
QLabel#FooterNote {
    font-size: 8pt;
    color: $text_faint;
}
QLabel#FooterBuild {
    font-size: 8pt;
    color: $text_muted;
}

/* ---------- panels ---------- */
QFrame#Panel {
    background-color: $surface;
    border: 1px solid $border;
    border-radius: ${radius_panel}px;
}
QLabel#PanelTitle {
    font-size: 10.5pt;
    font-weight: 600;
    color: $text_primary;
}
QLabel#PanelSubtitle {
    font-size: 8.5pt;
    color: $text_muted;
}
QLabel#SectionTitle {
    font-size: 9pt;
    font-weight: 700;
    color: $text_secondary;
}
QFrame#PanelDivider {
    background-color: $border;
}

/* ---------- page text ---------- */
QLabel#PageHeading {
    font-size: 19pt;
    font-weight: 700;
    color: $text_primary;
}
QLabel#PageLead {
    font-size: 9.5pt;
    color: $text_muted;
}
QLabel#FieldLabel {
    font-size: 8.5pt;
    font-weight: 600;
    color: $text_secondary;
}
QLabel#ValueText {
    font-size: 9.5pt;
    color: $text_primary;
}
QLabel#MutedText {
    font-size: 8.5pt;
    color: $text_muted;
}
QLabel#MonoText {
    font-size: 9pt;
    color: $text_secondary;
}

/* ---------- stat cards ---------- */
QFrame#StatCard {
    background-color: $surface;
    border: 1px solid $border;
    border-radius: ${radius_panel}px;
}
QLabel#StatLabel {
    font-size: 7.5pt;
    font-weight: 700;
    color: $text_faint;
}
QLabel#StatValue {
    font-size: 15pt;
    font-weight: 600;
    color: $text_primary;
}
QLabel#StatCaption {
    font-size: 8pt;
    color: $text_muted;
}

/* ---------- buttons ---------- */
QPushButton {
    background-color: $surface_raised;
    border: 1px solid $border_strong;
    border-radius: ${radius_control}px;
    color: $text_primary;
    font-size: 9pt;
    font-weight: 600;
    padding: 7px 14px;
}
QPushButton:hover {
    background-color: $surface_hover;
    border-color: $border_hover;
}
QPushButton:pressed {
    background-color: $surface_active;
}
QPushButton:disabled {
    background-color: #121215;
    border-color: $border;
    color: $text_faint;
}
QPushButton[buttonStyle="primary"] {
    background-color: $accent;
    border-color: $accent;
    color: #FFF3F4;
}
QPushButton[buttonStyle="primary"]:hover {
    background-color: $accent_hover;
    border-color: $accent_hover;
}
QPushButton[buttonStyle="primary"]:pressed {
    background-color: $accent_pressed;
}
QPushButton[buttonStyle="primary"]:disabled {
    background-color: #35161A;
    border-color: #35161A;
    color: #8A6669;
}
QPushButton[buttonStyle="danger"] {
    background-color: transparent;
    border-color: #5A262A;
    color: #EE9296;
}
QPushButton[buttonStyle="danger"]:hover {
    background-color: #221214;
    border-color: #7A3036;
}
QPushButton[buttonStyle="danger"]:disabled {
    background-color: transparent;
    border-color: $border;
    color: $text_faint;
}
QPushButton[buttonStyle="ghost"] {
    background-color: transparent;
    border-color: transparent;
    color: $text_secondary;
    font-weight: 500;
    padding: 5px 10px;
}
QPushButton[buttonStyle="ghost"]:hover {
    background-color: $surface_hover;
    color: $text_primary;
}
QPushButton[buttonStyle="icon"] {
    background-color: transparent;
    border-color: transparent;
    padding: 6px;
    border-radius: 6px;
}
QPushButton[buttonStyle="icon"]:hover {
    background-color: $surface_hover;
}
QPushButton[buttonStyle="icon"]:pressed {
    background-color: $surface_active;
}

/* ---------- inputs ---------- */
QLineEdit {
    background-color: $input_bg;
    border: 1px solid $border_strong;
    border-radius: ${radius_control}px;
    color: $text_primary;
    padding: 7px 10px;
    font-size: 9.5pt;
    selection-background-color: $accent;
    selection-color: #FFFFFF;
}
QLineEdit:hover {
    border-color: $border_hover;
}
QLineEdit:focus {
    border-color: #4E4E5B;
}
QLineEdit:disabled {
    color: $text_faint;
    background-color: #101013;
}
QLineEdit#SearchInput {
    padding-left: 6px;
}

QComboBox {
    background-color: $input_bg;
    border: 1px solid $border_strong;
    border-radius: ${radius_control}px;
    color: $text_primary;
    padding: 6px 28px 6px 10px;
    font-size: 9pt;
    min-height: 18px;
}
QComboBox:hover {
    border-color: $border_hover;
}
QComboBox:disabled {
    color: $text_faint;
}
QComboBox::drop-down {
    border: none;
    width: 26px;
}
QComboBox::down-arrow {
    image: none;
    width: 0px;
    height: 0px;
}
QComboBox QAbstractItemView {
    background-color: $surface_raised;
    border: 1px solid $border_strong;
    outline: 0;
    padding: 4px;
    selection-background-color: $surface_active;
    selection-color: $text_primary;
}
QComboBox QAbstractItemView::item {
    padding: 6px 10px;
    min-height: 20px;
}

/* ---------- tables ---------- */
QTableWidget#DataTable {
    background-color: transparent;
    alternate-background-color: transparent;
    border: none;
    color: $text_primary;
    font-size: 9pt;
    gridline-color: transparent;
    outline: 0;
    selection-background-color: #1E1E26;
    selection-color: $text_primary;
}
QTableWidget#DataTable::item {
    padding: 8px 10px;
    border-bottom: 1px solid #1A1A1F;
}
QTableWidget#DataTable::item:selected {
    background-color: #1E1E26;
}
QHeaderView {
    background-color: transparent;
}
QHeaderView::section {
    background-color: $table_header_bg;
    border: none;
    border-bottom: 1px solid $border;
    color: $text_muted;
    font-size: 8pt;
    font-weight: 700;
    padding: 8px 10px;
}
QHeaderView::section:first {
    border-top-left-radius: 6px;
}
QHeaderView::section:last {
    border-top-right-radius: 6px;
}
QTableCornerButton::section {
    background-color: $table_header_bg;
    border: none;
}

/* ---------- empty state ---------- */
QFrame#EmptyState {
    background-color: transparent;
    border: 1px dashed #26262E;
    border-radius: ${radius_panel}px;
}
QLabel#EmptyTitle {
    font-size: 10pt;
    font-weight: 600;
    color: $text_secondary;
}
QLabel#EmptyText {
    font-size: 8.5pt;
    color: $text_muted;
}

/* ---------- scroll bars ---------- */
QScrollArea {
    background: transparent;
    border: none;
}
QScrollArea > QWidget > QWidget {
    background: transparent;
}
QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 2px 2px 2px 0px;
}
QScrollBar::handle:vertical {
    background: #2A2A33;
    border-radius: 4px;
    min-height: 32px;
}
QScrollBar::handle:vertical:hover {
    background: #3A3A46;
}
QScrollBar:horizontal {
    background: transparent;
    height: 10px;
    margin: 0px 2px 2px 2px;
}
QScrollBar::handle:horizontal {
    background: #2A2A33;
    border-radius: 4px;
    min-width: 32px;
}
QScrollBar::add-line, QScrollBar::sub-line {
    width: 0px;
    height: 0px;
}
QScrollBar::add-page, QScrollBar::sub-page {
    background: transparent;
}

/* ---------- menus and tooltips ---------- */
QMenu {
    background-color: $surface_raised;
    border: 1px solid $border_strong;
    padding: 6px;
}
QMenu::item {
    background-color: transparent;
    color: $text_secondary;
    padding: 7px 20px 7px 14px;
    border-radius: 4px;
}
QMenu::item:selected {
    background-color: $surface_active;
    color: $text_primary;
}
QMenu::item:disabled {
    color: $text_faint;
}
QMenu::separator {
    height: 1px;
    background: $border;
    margin: 6px 8px;
}
QToolTip {
    background-color: $surface_raised;
    border: 1px solid $border_strong;
    color: $text_primary;
    padding: 5px 8px;
}
"""
)


def build_style_sheet() -> str:
    """Render the global style sheet from the current palette."""
    return _STYLE_TEMPLATE.substitute(
        background=BACKGROUND,
        sidebar_bg=SIDEBAR_BG,
        surface=SURFACE,
        surface_raised=SURFACE_RAISED,
        surface_hover=SURFACE_HOVER,
        surface_active=SURFACE_ACTIVE,
        table_header_bg=TABLE_HEADER_BG,
        input_bg=INPUT_BG,
        border=BORDER,
        border_strong=BORDER_STRONG,
        border_hover=BORDER_HOVER,
        text_primary=TEXT_PRIMARY,
        text_secondary=TEXT_SECONDARY,
        text_muted=TEXT_MUTED,
        text_faint=TEXT_FAINT,
        accent=ACCENT,
        accent_hover=ACCENT_HOVER,
        accent_pressed=ACCENT_PRESSED,
        radius_panel=RADIUS_PANEL,
        radius_control=RADIUS_CONTROL,
    )


STYLE_SHEET = build_style_sheet()


def apply_theme(app: QApplication) -> None:
    """Apply the SSG8 palette and typography to ``app``."""
    font = QFont(UI_FONT_FAMILY, BODY_POINT_SIZE)
    font.setStyleStrategy(QFont.StyleStrategy.PreferAntialias)
    app.setFont(font)
    app.setStyleSheet(build_style_sheet())
