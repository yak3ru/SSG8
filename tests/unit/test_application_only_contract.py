"""Application-only hackathon contract, without any OS-wide side effects."""
from ssg8.security.decisions import ProtectionAction
from ssg8.services.autonomous import AutonomousController
from ssg8.services.paranoia.states import ParanoiaState


def test_all_modules_initially_off_and_no_auto_enable_on_navigation(app_context):
    controller=AutonomousController(app_context.protection,app_context.paranoia,app_context.state)
    assert all(not x for x in app_context.protection.module_states().values())
    for _ in range(20):
        controller.record_navigation('applications')
    assert all(not x for x in app_context.protection.module_states().values())
    assert app_context.paranoia.score()==0


def test_block_all_managed_application_requests_when_enabled(app_context):
    AutonomousController(app_context.protection,app_context.paranoia,app_context.state)
    assert app_context.protection.evaluate_application('Notepad.exe').action is ProtectionAction.ALLOW
    app_context.protection.set_module_enabled('application',True)
    for app in ('Notepad.exe','Calculator','mspaint.exe','random_unknown.exe'):
        result=app_context.protection.evaluate_application(app)
        assert result.action is ProtectionAction.BLOCK
        assert app_context.protection.decisions('application')[0] is result
    assert len(app_context.paranoia.restriction_records())>=3
    assert app_context.paranoia.score()>0


def test_dont_automatically_enable_other_modules(app_context):
    AutonomousController(app_context.protection,app_context.paranoia,app_context.state)
    app_context.protection.set_module_enabled('application',True)
    for _ in range(7):
        app_context.protection.evaluate_application('Notepad.exe')
    assert all(not active for module,active in app_context.protection.module_states().items() if module!='application')


def test_session_reset_returns_to_off(app_context):
    controller=AutonomousController(app_context.protection,app_context.paranoia,app_context.state)
    app_context.protection.set_module_enabled('application',True)
    app_context.protection.evaluate_application('Calculator')
    controller.reset()
    assert all(not active for active in app_context.protection.module_states().values())
    assert app_context.paranoia.score()==0
    assert app_context.paranoia.state() is ParanoiaState.NORMAL
