"""Application Protection dashboard. No score or escalation indicators."""
from __future__ import annotations
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QWidget
from ssg8.ui.pages.base_page import BasePage
from ssg8.ui.components.panel import ContentPanel
from ssg8.ui.components.section_heading import PageIntro
from ssg8.ui.components.stat_card import StatCard
from ssg8.ui.components.action_button import ActionButton
from ssg8.ui.components.protection import ProtectionModuleRow
from ssg8.ui.components.data_table import DataTable
from ssg8.ui.components.chip import ChipCell
from ssg8.ui.components.protection import action_tone
from ssg8.utils.formatting import format_timestamp

class DashboardPage(BasePage):
    page_id='dashboard'
    def build(self):
        self.body.addWidget(PageIntro('Security Overview',
            'Application security monitoring, assessments, and recent events.'))
        cards=QGridLayout()
        self.status=StatCard('Application Protection','Disabled','User-controlled protection','shield')
        self.evaluations=StatCard('Evaluations','0','Applications inspected','activity')
        self.blocked=StatCard('Restricted','0','Managed requests rejected','alert')
        for i,widget in enumerate((self.status,self.evaluations,self.blocked)):
            cards.addWidget(widget,0,i)
        frame=QWidget(self)
        frame.setLayout(cards)
        self.body.addWidget(frame)
        control=ContentPanel('Application Protection',
            'Enable for automatic observation of newly opened application windows on Windows.')
        control.body.addWidget(ProtectionModuleRow(
            self.context.protection,'application',control,
            description='Observes external windows and reports suspicious requests. External windows are not forcibly closed.'))
        self.open_button=ActionButton('Open Application Protection','primary','apps',control)
        self.open_button.clicked.connect(lambda:self.navigate_to('applications'))
        control.body.addWidget(self.open_button)
        self.body.addWidget(control)
        history=ContentPanel('Recent Events','Recent application assessments.')
        self.table=DataTable(['Time','Application','Decision','Reason'],history)
        self.table.configure_columns({0:160,1:190,2:100},stretch=3)
        history.body.addWidget(self.table)
        self.body.addWidget(history)
        self.context.protection.modules_changed.connect(self.refresh)
        self.context.protection.changed.connect(self.refresh)
        self.refresh()
    def refresh(self):
        active=self.context.protection.is_module_enabled('application')
        stats=self.context.protection.stats()
        self.status.set_value('Enabled' if active else 'Disabled')
        self.evaluations.set_value(str(len(self.context.protection.decisions('application'))))
        from ssg8.security.decisions import ProtectionAction
        self.blocked.set_value(str(len(self.context.protection.decisions('application',actions=(ProtectionAction.BLOCK,)))))
        self.table.clear_rows()
        for item in self.context.protection.decisions('application',limit=12):
            self.table.add_row([format_timestamp(item.timestamp),item.target,
                ChipCell(item.action_label,action_tone(item.action)),item.reason],item)
    def on_shown(self):
        self.refresh()
