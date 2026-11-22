"""Themed table widget used by every list view in SSG8."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

DEFAULT_ROW_HEIGHT = 40
HEADER_HEIGHT = 34


class DataTable(QTableWidget):
    """A read-only table with consistent styling and row payloads."""

    def __init__(
        self,
        headers: list[str],
        parent: QWidget | None = None,
        *,
        row_height: int = DEFAULT_ROW_HEIGHT,
        stretch_last: bool = True,
    ) -> None:
        super().__init__(0, len(headers), parent)
        self.setObjectName("DataTable")
        self._payloads: list[Any] = []

        self.setHorizontalHeaderLabels(headers)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(False)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setFrameShape(QTableWidget.Shape.NoFrame)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setSortingEnabled(False)

        vertical = self.verticalHeader()
        vertical.setVisible(False)
        vertical.setDefaultSectionSize(row_height)

        header = self.horizontalHeader()
        header.setHighlightSections(False)
        header.setFixedHeight(HEADER_HEIGHT)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setStretchLastSection(stretch_last)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        # Keep the table able to shrink with the window instead of forcing the
        # whole page wider than the minimum window size.
        header.setMinimumSectionSize(40)

        self.setMinimumHeight(row_height * 3 + HEADER_HEIGHT)

    # --- configuration -----------------------------------------------------

    def configure_columns(self, widths: dict[int, int] | None = None, stretch: int | None = None) -> None:
        """Set explicit column widths and optionally make one column stretch."""
        header = self.horizontalHeader()
        for index, width in (widths or {}).items():
            header.setSectionResizeMode(index, QHeaderView.ResizeMode.Interactive)
            self.setColumnWidth(index, width)
        if stretch is not None:
            header.setStretchLastSection(False)
            header.setSectionResizeMode(stretch, QHeaderView.ResizeMode.Stretch)

    # --- data --------------------------------------------------------------

    def clear_rows(self) -> None:
        self.setRowCount(0)
        self._payloads.clear()

    def add_row(self, cells: list[str | QWidget], payload: Any = None) -> int:
        """Append a row. ``str`` cells become text, ``QWidget`` cells are embedded."""
        row = self.rowCount()
        self.setRowCount(row + 1)
        for column, value in enumerate(cells):
            if isinstance(value, QWidget):
                value.setParent(self)
                self.setCellWidget(row, column, value)
            else:
                item = QTableWidgetItem(str(value))
                item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                self.setItem(row, column, item)
        self._payloads.append(payload)
        return row

    def row_payload(self, row: int) -> Any:
        if 0 <= row < len(self._payloads):
            return self._payloads[row]
        return None

    def selected_payload(self) -> Any:
        row = self.currentRow()
        if row < 0 or row >= len(self._payloads):
            return None
        return self._payloads[row]

    def has_selection(self) -> bool:
        return 0 <= self.currentRow() < len(self._payloads)

    def select_first_row(self) -> None:
        if self.rowCount():
            self.selectRow(0)

    def visible_row_count(self) -> int:
        return self.rowCount()
