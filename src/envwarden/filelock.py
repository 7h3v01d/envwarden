# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Inter-process exclusive file lock (stdlib only: fcntl on POSIX, msvcrt on Windows).

Each lock holds its own open file descriptor, so two lock objects for the same
path conflict even inside one process — two EnvManager instances, a GUI and a
CLI, or two GUIs all serialise against each other. The OS releases the lock
if the holding process dies, so there are no stale lock files to clean up.
"""

from __future__ import annotations

import json
import os
import socket
import time
from datetime import datetime
from pathlib import Path
from typing import Any

if os.name == "nt":  # pragma: no cover - exercised on Windows CI
    import msvcrt
else:
    import fcntl


class InterProcessLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.info_path = path.with_suffix(path.suffix + ".holder.json")
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def _try_lock(self, fd: int) -> bool:
        try:
            if os.name == "nt":  # pragma: no cover
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def acquire(self, timeout: float = 0.0, poll: float = 0.05) -> bool:
        if self._fd is not None:
            raise RuntimeError("InterProcessLock is not re-entrant; nest at a higher level")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if self._try_lock(fd):
                self._fd = fd
                return True
            if time.monotonic() >= deadline:
                os.close(fd)
                return False
            time.sleep(poll)

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if os.name == "nt":  # pragma: no cover
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def write_holder(self, operation: str) -> None:
        info = {"pid": os.getpid(), "host": socket.gethostname(), "operation": operation,
                "since": datetime.now().isoformat(timespec="seconds")}
        try:
            self.info_path.write_text(json.dumps(info), encoding="utf-8")
        except OSError:
            pass

    def holder(self) -> dict[str, Any]:
        try:
            return json.loads(self.info_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def __enter__(self) -> "InterProcessLock":
        if not self.acquire(timeout=30):
            raise TimeoutError(f"Timed out waiting for lock {self.path}")
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.release()
