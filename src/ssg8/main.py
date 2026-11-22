"""SSG8 application entry point.

Run from the project root with either::

    python src/ssg8/main.py
    .venv\\Scripts\\python.exe src\\ssg8\\main.py

Only the application shell is created here. Security features are added in
later phases.
"""

from __future__ import annotations

import sys
from pathlib import Path

APPLICATION_NAME = "SSG8"


def _bootstrap_import_path() -> None:
    """Make ``import ssg8`` work when this file is run as a script.

    Python puts the script's own directory on ``sys.path``. That directory
    contains a ``platform`` package which would shadow the standard library
    ``platform`` module, so it is removed and the ``src`` directory is added
    instead. This keeps both ``python src/ssg8/main.py`` and the package import
    path working without side effects.
    """
    script_dir = Path(__file__).resolve().parent
    src_dir = script_dir.parent

    def _is_script_dir(entry: str) -> bool:
        try:
            return Path(entry or Path.cwd()).resolve() == script_dir
        except OSError:
            return False

    sys.path[:] = [entry for entry in sys.path if not _is_script_dir(entry)]
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))


_bootstrap_import_path()

from PySide6.QtWidgets import QApplication  # noqa: E402 - must follow bootstrap

from ssg8 import __version__  # noqa: E402
from ssg8.ui.main_window import MainWindow  # noqa: E402
from ssg8.ui.tray_mode import TrayMode  # noqa: E402
from ssg8.ui.theme import apply_theme  # noqa: E402


def create_application(argv: list[str] | None = None) -> QApplication:
    """Create the ``QApplication`` and apply the SSG8 theme."""
    app = QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName(APPLICATION_NAME)
    # No applicationDisplayName on purpose: Qt appends it to native window
    # titles, which would break the exact "SSG8 — Security Control Center".
    app.setApplicationVersion(__version__)
    app.setOrganizationName(APPLICATION_NAME)
    apply_theme(app)
    return app


def main(argv: list[str] | None = None) -> int:
    """Start the SSG8 desktop application and return its exit code."""
    app = create_application(argv)
    window = MainWindow()
    app.ssg8_tray = TrayMode(app, window)  # Keep controller alive.
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
