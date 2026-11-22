"""PySide6 GUI acceptance checks for the application-only Windows build."""
from __future__ import annotations
import sys
import pytest
from PySide6.QtWidgets import QApplication
from ssg8.core.context import build_context
from ssg8.storage.preferences import Preferences
from ssg8.storage.protection_store import ProtectionStore
from ssg8.ui import theme
from ssg8.ui.main_window import MainWindow
from ssg8.security.decisions import ProtectionAction

@pytest.fixture(scope='module')
def qapp():
    app=QApplication.instance() or QApplication([])
    theme.apply_theme(app)
    return app

@pytest.fixture
def window(qapp,tmp_path):
    context=build_context(Preferences(tmp_path/'prefs.json'), ProtectionStore(tmp_path/'data'))
    ui=MainWindow(context)
    ui.show()
    qapp.processEvents()
    yield ui
    ui.close()
    qapp.processEvents()


def test_only_app_protection_is_present(window):
    assert set(window.pages()) == {'dashboard','applications','threat-monitor','incidents','logs','recovery','about'}
    assert all(not x for x in window.context.protection.module_states().values())
    assert window.page('applications') is not None
    assert window.page('websites') is None
    assert window.page('downloads') is None
    assert window.page('notifications') is None


def test_application_policy_is_immediately_restrictive(window):
    protection=window.context.protection
    protection.set_module_enabled('application',True)
    QApplication.processEvents()
    result=protection.evaluate_application('Notepad.exe')
    assert result.action is ProtectionAction.BLOCK
    assert not protection.is_module_enabled('website')
    assert window.page('dashboard').status.value()=='Enabled'
    assert window.page('dashboard').blocked.value()=='1'


def test_recovery_resets_to_disabled(window):
    protection=window.context.protection
    protection.set_module_enabled('application',True)
    protection.evaluate_application('Calculator')
    window.navigate('recovery')
    window.page('recovery').reset()
    assert not any(protection.module_states().values())
    assert window.context.paranoia.score()==0


@pytest.mark.parametrize('size',[(1000,650),(1600,900)])
def test_pages_fit_screen(window,size):
    window.resize(*size)
    QApplication.processEvents()
    for page_id in window.pages():
        window.navigate(page_id)
        QApplication.processEvents()
        page=window.page(page_id)
        assert page._scroll.widget().width() <= page._scroll.viewport().width()+1, page_id


def test_owned_sample_window_closes_normally(window, qapp):
    from PySide6.QtTest import QTest
    window.navigate('applications')
    page=window.page('applications')
    window.context.protection.set_module_enabled('application', True)
    # Prevent a modal warning box from blocking the automated UI test.
    notices=[]
    page.notify_decision=lambda decision: notices.append(decision)
    page.open_test_window()
    qapp.processEvents()
    assert page._sample_window.isVisible()
    QTest.qWait(500)
    qapp.processEvents()
    assert not page._sample_window.isVisible()
    assert notices and notices[-1].action is ProtectionAction.BLOCK
