# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from envwarden.core import EnvManager  # noqa: E402
from envwarden.paths import AppPaths  # noqa: E402


@pytest.fixture
def mgr(tmp_path: Path) -> EnvManager:
    return EnvManager(AppPaths.create(tmp_path / "home"))


@pytest.fixture(scope="session")
def shared_mgr(tmp_path_factory: pytest.TempPathFactory) -> EnvManager:
    """One real environment ('base' with 'six') reused by the slower integration tests."""
    m = EnvManager(AppPaths.create(tmp_path_factory.mktemp("shared") / "home"))
    res = m.create("base", requirements=["six"])
    assert res.ok, res.message
    return m


@pytest.fixture(scope="session")
def qapp():
    from PyQt6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


def spin(app, ms: int) -> None:
    from PyQt6.QtCore import QEventLoop, QTimer
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def wait_idle(app, window, timeout_s: float = 120) -> None:
    import time
    deadline = time.monotonic() + timeout_s
    spin(app, 50)
    while window.runner.active and time.monotonic() < deadline:
        spin(app, 100)
    assert not window.runner.active, "background tasks did not finish"
