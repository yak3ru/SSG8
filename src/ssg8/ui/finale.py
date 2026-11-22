"""Accessible cinematic ending for the SSG8 security policy story."""
from __future__ import annotations

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QProgressBar, QPushButton, QVBoxLayout


class SelfQuarantineDialog(QDialog):
    finished_sequence = Signal()
    replay_requested = Signal()

    STEPS = (
        ("FINAL INTEGRITY SCAN", "Scanning the security policies responsible for recent access restrictions..."),
        ("CRITICAL THREAT DETECTED", "Application identified: SSG8.exe\nClassification: Excessive security interference."),
        ("SELF-QUARANTINE INITIATED", "SSG8 is disabling its own controls and restoring user access."),
        ("FINAL THREAT ELIMINATED: OURSELVES", "Your computer is now safe from our protection."),
    )

    def __init__(self, report, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SSG8 \u2014 Final Security Audit")
        self.resize(600, 320)
        self.setModal(False)
        self._index = 0
        self._report = report
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 26, 28, 24)
        root.setSpacing(14)
        self._title = QLabel(self)
        self._title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._title.setWordWrap(True)
        self._title.setStyleSheet("font-size: 18pt; font-weight: 700; color: #ff8794")
        root.addWidget(self._title)
        self._description = QLabel(self)
        self._description.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._description.setWordWrap(True)
        self._description.setStyleSheet("font-size: 11pt")
        root.addWidget(self._description)
        self._evidence = QLabel(self)
        self._evidence.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._evidence.setWordWrap(True)
        self._evidence.setText(f"Audit {report.id}: {report.legitimate_blocked} legitimate requests blocked; {report.restrictions_applied} restrictions recorded.")
        root.addWidget(self._evidence)
        self._bar = QProgressBar(self)
        self._bar.setRange(0, 100)
        self._bar.setTextVisible(False)
        root.addWidget(self._bar)
        buttons = QHBoxLayout()
        self._replay = QPushButton("Replay", self)
        self._replay.clicked.connect(self.replay_requested.emit)
        buttons.addWidget(self._replay)
        self._finish = QPushButton("Finish & Exit", self)
        self._finish.clicked.connect(self.finished_sequence.emit)
        buttons.addWidget(self._finish)
        root.addLayout(buttons)
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._advance)
        self._display_step()
        self._timer.start()

    def _display_step(self):
        title, detail = self.STEPS[self._index]
        self._title.setText(title)
        self._description.setText(detail)
        self._bar.setValue(round(100 * (self._index + 1) / len(self.STEPS)))

    def _advance(self):
        if self._index < len(self.STEPS) - 1:
            self._index += 1
            self._display_step()
        else:
            self._timer.stop()
            # Give the audience time to read the punchline, then exit normally.
            QTimer.singleShot(2400, self._auto_finish)

    def _auto_finish(self):
        if self.isVisible():
            self.finished_sequence.emit()

    def closeEvent(self, event):
        self._timer.stop()
        super().closeEvent(event)
