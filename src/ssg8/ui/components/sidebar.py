"""Persistent application sidebar."""

from __future__ import annotations

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ssg8 import __version__
from ssg8.ui import theme
from ssg8.ui.components.chip import Chip
from ssg8.ui.components.navigation_item import NavigationItem
from ssg8.ui.navigation import NAVIGATION, NavigationSection

SIDEBAR_WIDTH = 264
BRAND_MARK_SIZE = 28


class Sidebar(QFrame):
    """Brand block, grouped navigation and a footer with the live mode."""

    navigate_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(SIDEBAR_WIDTH)

        self._items: dict[str, NavigationItem] = {}
        self._group = QButtonGroup(self)
        self._group.setExclusive(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._build_brand())
        layout.addWidget(self._build_navigation(), 1)
        layout.addWidget(self._build_footer())

        self.set_active("dashboard")

    # --- construction ------------------------------------------------------

    def _build_brand(self) -> QWidget:
        brand = QWidget(self)
        row = QHBoxLayout(brand)
        row.setContentsMargins(16, 18, 16, 18)
        row.setSpacing(10)

        mark = QFrame(brand)
        mark.setFixedSize(BRAND_MARK_SIZE, BRAND_MARK_SIZE)
        mark.setStyleSheet(
            f"background-color: {theme.ACCENT}; border-radius: 7px;"
        )
        mark_layout = QVBoxLayout(mark)
        mark_layout.setContentsMargins(0, 0, 0, 0)
        initial = QLabel("S", mark)
        initial.setObjectName("BrandInitial")
        initial.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark_layout.addWidget(initial)
        row.addWidget(mark, 0, Qt.AlignmentFlag.AlignVCenter)

        text_column = QVBoxLayout()
        text_column.setContentsMargins(0, 0, 0, 0)
        text_column.setSpacing(1)

        title = QLabel("SSG8", brand)
        title.setObjectName("BrandTitle")
        text_column.addWidget(title)

        subtitle = QLabel("Security Control Center", brand)
        subtitle.setObjectName("BrandSubtitle")
        text_column.addWidget(subtitle)

        row.addLayout(text_column)
        row.addStretch(1)
        return brand

    def _build_navigation(self) -> QScrollArea:
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        container = QWidget()
        container.setObjectName("SidebarNav")
        column = QVBoxLayout(container)
        column.setContentsMargins(0, 0, 0, 8)
        column.setSpacing(0)

        for section in NAVIGATION:
            column.addWidget(self._build_section_label(section))
            for entry in section.entries:
                item = NavigationItem(entry, container)
                item.clicked.connect(lambda _checked=False, page=entry.page_id: self._on_item_clicked(page))
                self._group.addButton(item)
                self._items[entry.page_id] = item
                column.addWidget(item)

        column.addStretch(1)
        scroll.setWidget(container)
        return scroll

    def _build_section_label(self, section: NavigationSection) -> QLabel:
        label = QLabel(section.title, self)
        label.setObjectName("NavSectionLabel")
        label.setFont(theme.with_letter_spacing(label.font(), 1.1))
        return label

    def _build_footer(self) -> QFrame:
        footer = QFrame(self)
        footer.setObjectName("SidebarFooter")

        column = QVBoxLayout(footer)
        column.setContentsMargins(16, 12, 16, 14)
        column.setSpacing(8)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        self._lockdown_chip = Chip("APPLICATION PROTECTION OFF", "neutral", footer)
        row.addWidget(self._lockdown_chip)
        row.addStretch(1)
        column.addLayout(row)

        meta = QLabel(f"v{__version__}  \u00b7  Development build", footer)
        meta.setObjectName("SidebarMeta")
        column.addWidget(meta)
        return footer

    # --- behaviour ---------------------------------------------------------

    def _on_item_clicked(self, page_id: str) -> None:
        self.navigate_requested.emit(page_id)

    def set_active(self, page_id: str) -> None:
        """Highlight ``page_id`` without emitting a navigation request."""
        item = self._items.get(page_id)
        if item is None:
            return
        if not item.isChecked():
            item.setChecked(True)
        for other_id, other in self._items.items():
            if other_id != page_id:
                other.setChecked(False)

    def active_page(self) -> str | None:
        for page_id, item in self._items.items():
            if item.isChecked():
                return page_id
        return None

    def set_lockdown_state(self, active: bool) -> None:
        if active:
            self._lockdown_chip.setText("APPLICATION PROTECTION ON")
            self._lockdown_chip.set_tone("danger")
        else:
            self._lockdown_chip.setText("APPLICATION PROTECTION OFF")
            self._lockdown_chip.set_tone("neutral")

    def item_for(self, page_id: str) -> NavigationItem | None:
        return self._items.get(page_id)

    def icon_size(self) -> QSize:  # pragma: no cover - convenience for tests
        return QSize(16, 16)
