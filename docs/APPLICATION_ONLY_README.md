# SSG8 — Application Protection Only

This version exposes **Application Protection** as its sole protection module.
Website, Download and Notification Protection are removed from the UI.
Their legacy internal engines are retained for compatibility with old tests and local data.

## What is implemented

- The Application Protection switch starts OFF.
- When enabled on Windows, SSG8 observes **new visible application windows** through read-only Win32 window APIs, logging app executable basenames (no window titles, document names, keystrokes, or command-line arguments).
- Newly seen eligible application windows produce SSG8 security assessments and may display a warning.
- An SSG8-owned sample window **really closes** with a normal Qt window close when protection is enabled, followed by a security warning.
- A manually selected .exe can be assessed without opening, editing, or deleting the file.
- Existing incident reports, event logs, risk scoring and the theatrical self-quarantine finale remain.
- Recovery can disable protection, and closing SSG8 stops observation.

## What is not implemented

- **No automatic closing of external applications**, File Explorer, Task Manager, or all Windows windows. Observing a program does not grant safe authority to close it; general-purpose closing can interrupt work and disable access to recovery.
- No OS-wide application denial rules, no administrator requirement, and no process termination.
- No real executable self-deletion. The finale releases internal restrictions and exits safely.

## Run in the Windows VM

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe src\ssg8\main.py
```

1. Start SSG8. Check Dashboard shows Application Protection Disabled.
2. Open Application Protection and turn the switch ON.
3. Press **Open Protected Sample Window**. Its window should close automatically and show a warning. No external process is modified.
4. With SSG8 running, open a nonessential application window (e.g. Notepad). SSG8 should report an assessment, while leaving the external app open.
5. Turn protection OFF; no further new-window assessment should occur.
6. Use Recovery Center to clear state. Keep Task Manager and Explorer accessible.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/test_window_observer.py tests/unit/test_application_only_contract.py
```

To build on Windows:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_windows.ps1
```

The release has not been interactively verified on Windows in this build environment.
