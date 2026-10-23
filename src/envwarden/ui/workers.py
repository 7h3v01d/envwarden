# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""QObject-on-QThread task runner.

* Workers are QObjects moved to a QThread (not QThread subclasses).
* Results are delivered through queued slots on the runner, which lives in
  the GUI thread, so callbacks always run on the GUI thread (verified by
  test_r2b — never connect these with DirectConnection).
* ``_worker_refs`` keeps every (thread, worker) pair alive until the thread
  has finished, preventing GC-while-running crashes.
* Mutating tasks are exclusive (deny-first): a second one is refused.
"""

from __future__ import annotations

import itertools
import logging
import traceback
from typing import Any, Callable

from PyQt6.QtCore import QObject, QThread, pyqtSignal, pyqtSlot

log = logging.getLogger("envwarden.ui")


class _Worker(QObject):
    finished = pyqtSignal(int, object)
    failed = pyqtSignal(int, str)

    def __init__(self, token: int, fn: Callable[..., Any], args: tuple, kwargs: dict) -> None:
        super().__init__()
        self._token, self._fn, self._args, self._kwargs = token, fn, args, kwargs

    @pyqtSlot()
    def run(self) -> None:
        try:
            result = self._fn(*self._args, **self._kwargs)
        except Exception as exc:  # surfaced to the UI, never swallowed
            log.error("task failed\n%s", traceback.format_exc())
            self.failed.emit(self._token, f"{type(exc).__name__}: {exc}")
        else:
            self.finished.emit(self._token, result)


class TaskRunner(QObject):
    busy_changed = pyqtSignal(bool, str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._worker_refs: dict[int, tuple[QThread, _Worker]] = {}
        self._callbacks: dict[int, tuple[Callable[[Any], None], Callable[[str], None] | None, bool, str]] = {}
        self._ids = itertools.count(1)
        self._mutating_token: int | None = None

    @property
    def mutating_busy(self) -> bool:
        return self._mutating_token is not None

    @property
    def active(self) -> int:
        return len(self._worker_refs)

    def submit(self, label: str, fn: Callable[..., Any], *args: Any,
               on_done: Callable[[Any], None], on_error: Callable[[str], None] | None = None,
               mutating: bool = False, **kwargs: Any) -> bool:
        if mutating and self._mutating_token is not None:
            return False
        token = next(self._ids)
        thread = QThread(self)
        worker = _Worker(token, fn, args, kwargs)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.finished.connect(self._on_finished)
        worker.failed.connect(self._on_failed)
        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)
        thread.setObjectName(f"envwarden-task-{token}")
        thread.finished.connect(self._on_thread_finished)  # queued to the GUI thread
        self._worker_refs[token] = (thread, worker)
        self._callbacks[token] = (on_done, on_error, mutating, label)
        if mutating:
            self._mutating_token = token
        self.busy_changed.emit(True, label)
        thread.start()
        return True

    @pyqtSlot(int, object)
    def _on_finished(self, token: int, result: object) -> None:
        cb = self._callbacks.pop(token, None)
        self._clear_mutating(token)
        if cb:
            cb[0](result)

    @pyqtSlot(int, str)
    def _on_failed(self, token: int, message: str) -> None:
        cb = self._callbacks.pop(token, None)
        self._clear_mutating(token)
        if cb and cb[1]:
            cb[1](message)

    def _clear_mutating(self, token: int) -> None:
        if self._mutating_token == token:
            self._mutating_token = None

    @pyqtSlot()
    def _on_thread_finished(self) -> None:
        thread = self.sender()
        for token, (t, _w) in list(self._worker_refs.items()):
            if t is thread:
                self._release(token)
                break

    def _release(self, token: int) -> None:
        pair = self._worker_refs.pop(token, None)
        if pair:
            thread, worker = pair
            worker.deleteLater()
            thread.deleteLater()
        self.busy_changed.emit(bool(self._worker_refs), "")

    def shutdown(self, timeout_ms: int = 5000) -> None:
        for thread, _w in list(self._worker_refs.values()):
            thread.quit()
            thread.wait(timeout_ms)
