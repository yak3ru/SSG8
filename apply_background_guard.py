"""Correct SSG8's restricted-background Calculator detection and tray status.

Run once from the SSG8 project root. This is NOT an unrestricted background
window closer: it preserves the narrow background-app allowlist and the tray's
Pause/Quit controls. Existing .bak files are not overwritten.
"""
from __future__ import annotations

from pathlib import Path

MAIN = Path('src/ssg8/ui/main_window.py')
TRAY = Path('src/ssg8/ui/tray_mode.py')


def modify_main(source: str) -> tuple[str, str]:
    old = 'approved = {"calc.exe", "calculatorapp.exe", "notepad.exe", "mspaint.exe"}'
    new = ('approved = {"calc.exe", "calculatorapp.exe", "notepad.exe", '
           '"mspaint.exe", "applicationframehost.exe"}')
    if new in source:
        return source, 'already patched'
    if old not in source or '# SSG8_BACKGROUND_APPROVED_WINDOWS_ONLY' not in source:
        raise RuntimeError('Expected restricted background guard not found; refusing to modify MainWindow.')
    # The existing approved_window_closer.py must still validate exact hosted
    # window titles. This change merely passes the owner name to that validator.
    return source.replace(old, new, 1), 'updated'


def modify_tray(source: str) -> tuple[str, str]:
    marker = '# SSG8_BACKGROUND_OBSERVER_STATUS_CHECK'
    if marker in source:
        return source, 'already patched'

    old = '''        if enabled and self.window.isHidden():
            status = "Application Protection: ON (background)"
        else:
            status = "Application Protection: ON" if enabled else "Application Protection: OFF"
'''
    new = '''        # SSG8_BACKGROUND_OBSERVER_STATUS_CHECK
        # The protection manager's Enabled flag is not the same as an active
        # Windows observer. Report the observer state instead of a misleading ON.
        observer = getattr(self.window, "window_observer", None)
        observing = bool(observer is not None and observer.enabled())
        if enabled and not observing:
            status = "Protection selected ON — observer inactive"
        elif enabled and self.window.isHidden():
            status = "Application Protection: ON (limited background)"
        else:
            status = "Application Protection: ON" if enabled else "Application Protection: OFF"
'''
    if old not in source:
        raise RuntimeError('Expected new tray status logic not found; refusing to modify TrayMode.')
    return source.replace(old, new, 1), 'updated'


def main() -> None:
    if not MAIN.is_file() or not TRAY.is_file():
        raise SystemExit('Run from the outer SSG8 project folder containing src/ssg8/.')

    main_src = MAIN.read_text(encoding='utf-8')
    tray_src = TRAY.read_text(encoding='utf-8')
    main_new, main_status = modify_main(main_src)
    tray_new, tray_status = modify_tray(tray_src)

    # Do not modify only one file if the other one fails validation.
    compile(main_new, str(MAIN), 'exec')
    compile(tray_new, str(TRAY), 'exec')
    for path, old, new in (
        (MAIN, main_src, main_new),
        (TRAY, tray_src, tray_new),
    ):
        if old != new:
            backup = path.with_suffix('.py.before_status_fix.bak')
            if not backup.exists():
                backup.write_text(old, encoding='utf-8')
            path.write_text(new, encoding='utf-8')
    print(f'main_window.py: {main_status}')
    print(f'tray_mode.py: {tray_status}')
    print('Done. Test with Notepad and Calculator in the system tray.')
    print('Other applications remain excluded from background automatic closing.')


if __name__ == '__main__':
    main()
