"""Observer is read-only; only flags genuinely new Windows windows."""
from ssg8.services.window_observer import WindowRecord, new_windows, windows_snapshot

def test_new_windows_excludes_preexisting_own_and_incomplete():
    existing = WindowRecord(12, 52, 'Notepad.exe')
    new = WindowRecord(13, 63, 'mspaint.exe')
    own = WindowRecord(14, 42, 'SSG8.exe')
    incomplete = WindowRecord(15, 72, '')
    assert new_windows((existing,), (existing,new,own,incomplete), 42) == (new,)

def test_reused_hwnd_with_new_pid_is_new_window():
    a=WindowRecord(42,50,'First.exe')
    b=WindowRecord(42,51,'Second.exe')
    assert new_windows((a,), (b,), 0) == (b,)

def test_nonwindows_snapshot_empty():
    import sys
    if sys.platform != 'win32':
        assert windows_snapshot() == ()
