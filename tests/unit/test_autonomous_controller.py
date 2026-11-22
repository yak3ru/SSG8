"""Regression checks for application-only controller."""
from ssg8.security.decisions import ProtectionAction
from ssg8.services.autonomous import AutonomousController, audit_eligible
from ssg8.services.paranoia.states import ParanoiaState


def test_controller_starts_disabled(app_context):
    ctl=AutonomousController(app_context.protection,app_context.paranoia,app_context.state)
    assert app_context.protection.enabled_module_count()==0
    assert app_context.paranoia.score()==0
    assert ctl is not None


def test_no_implicit_activation_from_page_visits(app_context):
    ctl=AutonomousController(app_context.protection,app_context.paranoia,app_context.state)
    for _ in range(15):
        ctl.record_navigation('applications')
    assert not app_context.protection.is_module_enabled('application')


def test_operator_enables_application_only(app_context):
    ctl=AutonomousController(app_context.protection,app_context.paranoia,app_context.state)
    app_context.protection.set_module_enabled('application',True)
    decision=app_context.protection.evaluate_application('Notepad')
    assert decision.action is ProtectionAction.BLOCK
    assert not app_context.protection.is_module_enabled('website')
    assert ctl is not None


def test_reset_preserves_existing_rules(app_context):
    ctl=AutonomousController(app_context.protection,app_context.paranoia,app_context.state)
    ok,_=app_context.protection.add_application_rule('TestApp','', 'block')
    assert ok
    app_context.protection.set_module_enabled('application',True)
    app_context.protection.evaluate_application('TestApp')
    ctl.reset()
    assert app_context.paranoia.state() is ParanoiaState.NORMAL
    assert app_context.protection.enabled_module_count()==0
    assert app_context.paranoia.score()==0
    assert app_context.state.applications('block')


def test_self_audit_requires_evidence():
    assert not audit_eligible(ParanoiaState.MAXIMUM_PARANOIA,())
    assert not audit_eligible(ParanoiaState.NORMAL,())
