"""Reusable widget library for the SSG8 interface."""

from __future__ import annotations

from ssg8.ui.components import icons
from ssg8.ui.components.action_button import ActionButton, IconButton
from ssg8.ui.components.chip import CellContainer, Chip, ChipCell
from ssg8.ui.components.data_table import DataTable
from ssg8.ui.components.dialog import FieldSpec, confirm, prompt_form, prompt_text
from ssg8.ui.components.empty_state import EmptyState
from ssg8.ui.components.info_list import ColourSwatch, InfoList
from ssg8.ui.components.navigation_item import NavigationItem
from ssg8.ui.components.notice_banner import NoticeBanner
from ssg8.ui.components.panel import ContentPanel, divider, vertical_divider
from ssg8.ui.components.risk_chart import RiskTrendChart
from ssg8.ui.components.protection import (
    DecisionSummary,
    ProtectionModuleRow,
    action_tone,
)
from ssg8.ui.components.search_input import SearchInput, SelectBox
from ssg8.ui.components.section_heading import (
    PageIntro,
    SectionHeading,
    field_label,
    mono_label,
    muted_label,
)
from ssg8.ui.components.sidebar import Sidebar
from ssg8.ui.components.stat_card import StatCard
from ssg8.ui.components.status_badge import StatusBadge
from ssg8.ui.components.toggle_switch import ToggleSwitch
from ssg8.ui.components.top_header import TopHeader

__all__ = [
    "ActionButton",
    "CellContainer",
    "Chip",
    "ChipCell",
    "ColourSwatch",
    "ContentPanel",
    "DataTable",
    "DecisionSummary",
    "EmptyState",
    "FieldSpec",
    "IconButton",
    "InfoList",
    "NavigationItem",
    "NoticeBanner",
    "PageIntro",
    "ProtectionModuleRow",
    "RiskTrendChart",
    "SearchInput",
    "SectionHeading",
    "SelectBox",
    "Sidebar",
    "StatCard",
    "StatusBadge",
    "ToggleSwitch",
    "TopHeader",
    "action_tone",
    "confirm",
    "divider",
    "field_label",
    "icons",
    "mono_label",
    "muted_label",
    "prompt_form",
    "prompt_text",
    "vertical_divider",
]
