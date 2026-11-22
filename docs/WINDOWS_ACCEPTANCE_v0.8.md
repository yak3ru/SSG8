# SSG8 v0.8.0 — Windows / VirtualBox acceptance checklist

## Scope / build status

The four protection engines, automatic escalation, security logs, self-audit, recovery, and the app-controlled UI integration are in source. The browser uses a **Qt WebEngine** managed profile. This build has not been tested on a real Windows guest or packaged as an `.exe` in the Linux source-generation environment. Claims of system-wide blocking, forced closing of Task Manager or other applications, or destructive self-deletion are **not** part of the implementation.

## What to verify on the Windows guest

1. Take a clean VirtualBox snapshot and run SSG8 from source.
2. Confirm the Dashboard lists **0/4 enabled** protection modules and no visible paranoia/scoring meter.
3. Confirm ordinary navigation works; there is no sidebar **Controlled Demo**, **Malfunction Lab**, **Paranoia Center** or **Lockdown Center**.
4. In Website Protection, choose **Managed Browser**. Enter a benign HTTPS URL and verify that early-stage navigation works or reports any actual network error accurately. Later requests should be refused, with the attempt logged by SSG8.
5. Test a benign downloadable file inside the managed browser. Verify allowed transfers go into temporary SSG8 storage only; when restrictions are active, WebEngine cancels the download. No existing user file should be deleted.
6. Inspect a local file in Download Protection. Confirm metadata and SHA-256 display. The inspector does not itself delete, quarantine, or intercept system-wide downloads.
7. Evaluate Calculator or Notepad inside Application Control; add a harmless entry for analysis. Observe the policy becoming increasingly strict, with a native dialog for rejected requests. **The real Windows application must remain untouched.**
8. Submit several notifications using Notification Control. Verify SSG8-managed requests are logged and increasingly rejected; unrelated Windows notifications remain unaffected.
9. Confirm **Recent Events** and Security Logs show recorded requests and module activations without exposing a paranoia percentage in the main Dashboard.
10. Continue submitting requests until the final self-audit. Confirm the audit references actual recorded legitimate requests that were blocked; see SSG8 identify itself as the source of overrestriction.
11. Confirm the self-quarantine animation finishes, all application-owned restrictions are released, and SSG8 exits normally. **No executable or Windows system file is deleted.**
12. Relaunch and use Recovery Center to reset. Confirm protections begin OFF again and previously saved website/application rules remain.
13. Test the app when no internet is available and when Qt WebEngine is missing: the main dashboard and policy evaluator must still load, and the missing-browser error must be clear.
14. Run the full native PySide6 pytest suite in the Windows virtual environment. Verify the UI tests, original engine tests, and new autonomous controller tests.
15. Build with `scripts/build_windows.ps1`, launch `dist\SSG8\SSG8.exe`, and repeat the browser, download, audit, reset, and exit scenarios.

## Python-only checks performed during source development

- `python -m compileall -q src tests`: completed successfully.
- `python scripts/headless_unit_suite.py`: **200 unit tests passed** using lightweight stand-ins for Qt signals. This is **not equivalent** to a PySide6 GUI test.
- `python scripts/headless_integration_check.py`: the service-level story reached self-threat detection after **18 recorded requests**, then reset successfully.
- PySide6 installation from the package index failed in the development container (network/DNS failure). No Windows/Qt GUI verification or actual EXE build is claimed.

## Safety

Maintain a working user-exit path and a clean VM snapshot. No administrator elevation is needed for the SSG8-owned features. Never test destructive OS-wide changes; the whole joke is that the **app's own** policies become unreasonable.
