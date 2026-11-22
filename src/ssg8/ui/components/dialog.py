"""Confirmation and form dialogs with consistent styling."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from ssg8.ui import theme
from ssg8.ui.components.action_button import ActionButton

Validator = Callable[[str], str | None]


def confirm(
    parent: QWidget | None,
    title: str,
    message: str,
    *,
    confirm_label: str = "Confirm",
    cancel_label: str = "Cancel",
    danger: bool = False,
) -> bool:
    """Ask the user to confirm an action. Returns ``True`` when accepted."""
    box = QMessageBox(parent)
    box.setWindowTitle(title)
    box.setText(message)
    box.setIcon(QMessageBox.Icon.NoIcon)

    accept = box.addButton(confirm_label, QMessageBox.ButtonRole.AcceptRole)
    accept.setProperty("buttonStyle", "danger" if danger else "primary")
    theme.refresh_style(accept)

    cancel = box.addButton(cancel_label, QMessageBox.ButtonRole.RejectRole)
    cancel.setProperty("buttonStyle", "secondary")
    theme.refresh_style(cancel)

    box.setDefaultButton(accept)
    box.setEscapeButton(cancel)
    box.exec()
    return box.clickedButton() is accept


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """One text field of a :class:`FormDialog`."""

    key: str
    label: str
    placeholder: str = ""
    initial: str = ""
    validator: Validator | None = field(default=None)


class FormDialog(QDialog):
    """A small modal form with inline, per-field validation."""

    def __init__(
        self,
        parent: QWidget | None,
        *,
        title: str,
        fields: list[FieldSpec],
        confirm_label: str = "Save",
        description: str = "",
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(470)
        self._fields = fields
        self._edits: dict[str, QLineEdit] = {}
        self._errors: dict[str, QLabel] = {}
        self._values: dict[str, str] = {spec.key: spec.initial for spec in fields}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 18)
        layout.setSpacing(9)

        heading = QLabel(title, self)
        heading.setObjectName("PanelTitle")
        layout.addWidget(heading)

        if description:
            note = QLabel(description, self)
            note.setObjectName("PanelSubtitle")
            note.setWordWrap(True)
            layout.addWidget(note)

        layout.addSpacing(2)
        for spec in fields:
            label = QLabel(spec.label, self)
            label.setObjectName("FieldLabel")
            layout.addWidget(label)

            edit = QLineEdit(self)
            edit.setPlaceholderText(spec.placeholder)
            edit.setText(spec.initial)
            edit.setMinimumHeight(36)
            edit.textEdited.connect(lambda _text, key=spec.key: self._clear_error(key))
            edit.returnPressed.connect(self._try_accept)
            layout.addWidget(edit)
            self._edits[spec.key] = edit

            error = QLabel("", self)
            error.setStyleSheet(f"color: {theme.tone('danger').text}; font-size: 8.5pt;")
            error.setWordWrap(True)
            error.setVisible(False)
            layout.addWidget(error)
            self._errors[spec.key] = error

        layout.addSpacing(4)
        buttons = QHBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.setSpacing(8)
        buttons.addStretch(1)

        cancel = ActionButton("Cancel", "secondary", parent=self)
        cancel.clicked.connect(self.reject)
        buttons.addWidget(cancel)

        accept = ActionButton(confirm_label, "primary", parent=self)
        accept.setDefault(True)
        accept.clicked.connect(self._try_accept)
        buttons.addWidget(accept)

        layout.addLayout(buttons)

        if fields:
            self._edits[fields[0].key].setFocus()

    # --- public API --------------------------------------------------------

    def values(self) -> dict[str, str]:
        return dict(self._values)

    # --- internals ---------------------------------------------------------

    def _clear_error(self, key: str) -> None:
        self._errors[key].setVisible(False)

    def _try_accept(self) -> None:
        accepted: dict[str, str] = {}
        first_invalid: QLineEdit | None = None

        for spec in self._fields:
            text = self._edits[spec.key].text().strip()
            error = spec.validator(text) if spec.validator is not None else None
            label = self._errors[spec.key]
            if error:
                label.setText(error)
                label.setVisible(True)
                if first_invalid is None:
                    first_invalid = self._edits[spec.key]
            else:
                label.setVisible(False)
                accepted[spec.key] = text

        if first_invalid is not None:
            first_invalid.setFocus()
            return

        self._values = accepted
        self.accept()


def prompt_text(
    parent: QWidget | None,
    *,
    title: str,
    label: str,
    placeholder: str = "",
    initial: str = "",
    confirm_label: str = "Save",
    validator: Validator | None = None,
    description: str = "",
) -> str | None:
    """Show a single field form and return the accepted text."""
    result = prompt_form(
        parent,
        title=title,
        fields=[FieldSpec("value", label, placeholder, initial, validator)],
        confirm_label=confirm_label,
        description=description,
    )
    return result["value"] if result else None


def prompt_form(
    parent: QWidget | None,
    *,
    title: str,
    fields: list[FieldSpec],
    confirm_label: str = "Save",
    description: str = "",
) -> dict[str, str] | None:
    """Show a multi field form and return the accepted values."""
    dialog = FormDialog(
        parent,
        title=title,
        fields=fields,
        confirm_label=confirm_label,
        description=description,
    )
    if dialog.exec() == QDialog.DialogCode.Accepted:
        return dialog.values()
    return None
