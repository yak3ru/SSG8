"""Application-only service smoke test using lightweight Qt signal substitutes.

This does NOT verify PySide6 GUI behavior, Windows observation, or EXE packaging.
"""
from __future__ import annotations
import sys,types,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'src'))
class BoundSignal:
    def __init__(self): self.callbacks=[]
    def connect(self,callback): self.callbacks.append(callback)
    def emit(self,*args):
        for callback in tuple(self.callbacks):callback(*args)
class Signal:
    def __init__(self,*args): pass
    def __set_name__(self,owner,name): self.name=name
    def __get__(self,obj,owner=None):
        if obj is None:return self
        return obj.__dict__.setdefault('_signal_'+self.name,BoundSignal())
class QObject:
    def __init__(self,parent=None): pass
scheduled=[]
class QTimer:
    @staticmethod
    def singleShot(ms,cb): scheduled.append(cb)
qt=types.ModuleType('PySide6.QtCore')
qt.Signal=Signal;qt.QObject=QObject;qt.QTimer=QTimer
sys.modules['PySide6']=types.ModuleType('PySide6')
sys.modules['PySide6.QtCore']=qt
from ssg8.core.context import build_context
from ssg8.services.autonomous import AutonomousController
from ssg8.storage.protection_store import ProtectionStore
from ssg8.storage.paranoia_store import ParanoiaStore
from ssg8.storage.analysis_store import AnalysisStore
from ssg8.storage.preferences import Preferences
from ssg8.services.paranoia.states import ParanoiaState
from ssg8.security.decisions import ProtectionAction
with tempfile.TemporaryDirectory() as d:
    root=Path(d)
    ctx=build_context(Preferences(root/'preferences.json'),ProtectionStore(root/'data'),
        AnalysisStore(root/'analysis'),ParanoiaStore(root/'paranoia'),root/'sandbox')
    ctl=AutonomousController(ctx.protection,ctx.paranoia,ctx.state)
    assert ctx.protection.enabled_module_count()==0
    assert ctx.paranoia.score()==0
    assert ctx.protection.evaluate_application('Calculator').action is ProtectionAction.ALLOW
    assert ctx.paranoia.score()==0
    ctx.protection.set_module_enabled('application',True)
    reports=[]
    ctl.finale_requested.connect(reports.append)
    decisions=[]
    for i in range(60):
        d=ctx.protection.evaluate_application(f'TestTool{i}.exe')
        decisions.append(d)
        assert d.action is ProtectionAction.BLOCK
        while scheduled: scheduled.pop(0)()
        if reports: break
    assert reports, f'audit missing after {len(decisions)} decisions; score {ctx.paranoia.score()}'
    assert reports[0].has_violations
    assert ctx.protection.is_module_enabled('application')
    assert all(not active for name,active in ctx.protection.module_states().items() if name!='application')
    print('APPLICATION AUDIT PASSED:',len(decisions),'requests,',reports[0].legitimate_blocked,'evidence records')
    ctx.paranoia.begin_quarantine()
    ctx.paranoia.complete_recovery()
    ctl.reset()
    assert ctx.protection.enabled_module_count()==0
    assert ctx.paranoia.score()==0
    assert ctx.paranoia.state()==ParanoiaState.NORMAL
    print('RECOVERY PASSED: all modules off, baseline state restored')
