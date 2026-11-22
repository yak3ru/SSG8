# SSG8 — Application Protection

SSG8 (v0.9.0) is a Windows desktop security control center built with Python and PySide6 (Qt 6).
This build has one protection module: **Application Protection**. It watches for new visible
application windows with read-only Win32 APIs, scores the risk of each one and raises security
alerts. It never terminates external processes and does not need administrator rights.

For what is and is not implemented, see [docs/APPLICATION_ONLY_README.md](docs/APPLICATION_ONLY_README.md).

## Requirements

- Windows 10 or 11 (best run in a VM for demos)
- Python 3.13 (the `py` launcher, or `python` on PATH)
- No administrator rights

## 1. Set up (first time only)

Open PowerShell in the project root:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

`requirements.txt` installs only `PySide6>=6.8,<7.0`.

## 2. Run the system

```powershell
.\.venv\Scripts\python.exe src\ssg8\main.py
```

The **SSG8 — Security Control Center** window opens and a system tray icon appears.
Run it from the project root. `main.py` sets up its own import path, so you don't need
`pip install -e .` or `PYTHONPATH`.

Closing SSG8 stops all observation.

## 3. Try it out

1. **Dashboard** should show Application Protection as *Disabled*. It always starts OFF.
2. Open **Application Protection** and turn the switch **ON**.
3. Click **Open Protected Sample Window**. That SSG8-owned window closes by itself and a security warning appears.
4. With SSG8 still running, open a harmless app such as Notepad. SSG8 logs an assessment and may warn you, but leaves Notepad open.
5. Check **Security Logs** and incidents for the recorded events and risk scores.
6. Turn protection **OFF**. New windows are no longer assessed.
7. Use the **Recovery Center** to clear state. Task Manager and Explorer stay usable the whole time.

You can also pick an `.exe` by hand to have it assessed. SSG8 never opens, changes or deletes the file.

## Data location

Settings, logs and analysis data go to `%LOCALAPPDATA%\SSG8\`
(or `~/.ssg8/SSG8` if `LOCALAPPDATA` is not set). To reset SSG8 completely, close it and delete that folder.

## Run the tests

```powershell
.\.venv\Scripts\python.exe -m pip install pytest
.\.venv\Scripts\python.exe -m pytest -q
```

The tests run Qt in `offscreen` mode (set in `tests/conftest.py`), so no window opens.
To run only the core Application Protection tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/unit/test_window_observer.py tests/unit/test_application_only_contract.py
```

## Project layout

```
src/ssg8/
  main.py        entry point (create_application, main)
  core/          app state, context wiring, shared models
  security/      protection manager, rules, analysis & risk scoring
  services/      window observer, event log, paranoia/self-audit, Edge bridge
  storage/       JSON stores for preferences, protection and analysis data
  ui/            main window, tray mode, theme, components
  platform/      Windows-specific helpers (dark title bar)
tests/           unit/ and integration/ pytest suites
docs/            design, acceptance and integration notes
```

## Troubleshooting

- **`No module named PySide6`**: you ran the system Python. Use `.\.venv\Scripts\python.exe`, or activate the venv with `.\.venv\Scripts\Activate.ps1`.
- **`Activate.ps1` is blocked**: run `Set-ExecutionPolicy -Scope Process Bypass` in that shell, or call `.venv\Scripts\python.exe` directly.
- **Nothing happens when you open other apps**: make sure the Application Protection switch is ON. External windows are only assessed, never closed.

## Further docs

- [docs/APPLICATION_ONLY_README.md](docs/APPLICATION_ONLY_README.md): scope of this build
- [docs/WINDOWS_ACCEPTANCE_v0.8.md](docs/WINDOWS_ACCEPTANCE_v0.8.md): Windows acceptance checklist
- [docs/EDGE_INTEGRATION.md](docs/EDGE_INTEGRATION.md): legacy Website Protection / Edge bridge notes (not shown in this build's UI)
