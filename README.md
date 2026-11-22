# SSG8 Application Protection — CyberLarps

**Maximum Security. Minimum Freedom.**

This is a focused Windows/PySide6 version of SSG8 with one active protection module: Application Protection.
The UI contains Dashboard, Application Protection, Threat Monitor, Incidents, Security Logs, Recovery Center and About.

The Application Protection switch is initially OFF. When ON, Windows window observations generate security assessments automatically. Externally opened Windows applications are observed, **not closed**; the built-in SSG8 sample window is closed immediately using a normal Qt close event to demonstrate the intended visual effect.

See [the Application Protection instructions](docs/APPLICATION_ONLY_README.md) for usage, limitations, and verification.
