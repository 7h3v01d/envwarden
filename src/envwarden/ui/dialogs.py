# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Confirmation dialog. Destructive actions require typing the target's name."""

from __future__ import annotations

from PyQt6.QtWidgets import (QDialog, QDialogButtonBox, QLabel, QLineEdit, QPushButton,
                             QVBoxLayout, QWidget)


class ConfirmDialog(QDialog):
    def __init__(self, parent: QWidget | None, title: str, summary: str,
                 phrase: str = "", danger: bool = False) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(460)
        self._phrase = phrase
        lay = QVBoxLayout(self)
        head = QLabel(title.upper())
        head.setObjectName("Bad" if danger else "Section")
        lay.addWidget(head)
        body = QLabel(summary)
        body.setWordWrap(True)
        lay.addWidget(body)
        self.edit: QLineEdit | None = None
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.ok_btn = QPushButton("Proceed")
        self.ok_btn.setObjectName("Danger" if danger else "Primary")
        buttons.addButton(self.ok_btn, QDialogButtonBox.ButtonRole.AcceptRole)
        if phrase:
            hint = QLabel(f"Type  {phrase}  to confirm.")
            hint.setObjectName("Muted")
            lay.addWidget(hint)
            self.edit = QLineEdit()
            self.edit.setPlaceholderText(phrase)
            self.edit.textChanged.connect(self._sync)
            lay.addWidget(self.edit)
            self.ok_btn.setEnabled(False)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def _sync(self, text: str) -> None:
        self.ok_btn.setEnabled(text.strip() == self._phrase)

    def accept(self) -> None:  # guard against Enter-key bypass
        if self._phrase and (self.edit is None or self.edit.text().strip() != self._phrase):
            return
        super().accept()


def confirm(parent: QWidget | None, title: str, summary: str, phrase: str = "", danger: bool = False) -> bool:
    return ConfirmDialog(parent, title, summary, phrase, danger).exec() == QDialog.DialogCode.Accepted
