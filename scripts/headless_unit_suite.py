"""Run existing *logic* tests with lightweight Qt signal substitutes.

Not a replacement for running pytest against PySide6 in Windows.
"""
from __future__ import annotations
import sys,types

class BoundSignal:
    def __init__(self): self.callbacks=[]
    def connect(self,callback):self.callbacks.append(callback)
    def emit(self,*args):
        for cb in tuple(self.callbacks):cb(*args)
class Signal:
    def __init__(self,*kinds): pass
    def __set_name__(self,owner,name):self.name=name
    def __get__(self,obj,owner=None):
        if obj is None:return self
        return obj.__dict__.setdefault('_sig_'+self.name,BoundSignal())
class QObject:
    def __init__(self,parent=None):pass
class QTimer:
    @staticmethod
    def singleShot(ms,callback):callback()
qt=types.ModuleType('PySide6.QtCore')
qt.Signal=Signal;qt.QObject=QObject;qt.QTimer=QTimer
sys.modules['PySide6']=types.ModuleType('PySide6')
sys.modules['PySide6.QtCore']=qt
import pytest
raise SystemExit(pytest.main(['tests/unit','-q']))
