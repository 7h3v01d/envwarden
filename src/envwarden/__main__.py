# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Entry point: ``python -m envwarden`` (GUI) or ``python -m envwarden <command>`` (CLI)."""

from __future__ import annotations

import logging
import sys


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv:
        from .cli import main as cli_main
        return cli_main(argv)

    from PyQt6.QtGui import QFont
    from PyQt6.QtWidgets import QApplication

    from . import APP_NAME, __version__
    from .core import EnvManager
    from .ui.main_window import MainWindow

    mgr = EnvManager()
    logging.basicConfig(filename=str(mgr.paths.runtime_log), level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("Leon Priest")
    app.setFont(QFont("JetBrains Mono", 9))
    window = MainWindow(mgr)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
