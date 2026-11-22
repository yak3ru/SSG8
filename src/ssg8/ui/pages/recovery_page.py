"""Accessible one-click recovery: no Windows settings modified."""
from __future__ import annotations
from PySide6.QtWidgets import QApplication, QLabel
from ssg8.ui.pages.base_page import BasePage
from ssg8.ui.components.panel import ContentPanel
from ssg8.ui.components.section_heading import PageIntro
from ssg8.ui.components.action_button import ActionButton
class RecoveryPage(BasePage):
    page_id='recovery'
    def build(self):
        self.body.addWidget(PageIntro('Recovery Center','Restore application state or exit safely at any time.'))
        panel=ContentPanel('Session Recovery','No Windows settings or unrelated applications are changed.')
        reset=ActionButton('Reset Application Protection','primary','refresh',panel)
        reset.clicked.connect(self.reset)
        panel.body.addWidget(reset)
        quit_btn=ActionButton('Exit SSG8','secondary',parent=panel)
        quit_btn.clicked.connect(QApplication.instance().quit)
        panel.body.addWidget(quit_btn)
        self.notice=QLabel('Recovery is always available.',panel)
        self.notice.setObjectName('MutedText')
        panel.body.addWidget(self.notice)
        self.body.addWidget(panel)
    def reset(self):
        owner=self.window()
        if hasattr(owner,'autonomy'):
            owner.autonomy.reset()
        else:
            self.context.paranoia.quick_reset('Recovery requested')
            for module in self.context.protection.module_ids():
                self.context.protection.set_module_enabled(module,False)
        self.context.protection.reset_session_history()
        self.notice.setText('Protection disabled. Session history cleared.')
