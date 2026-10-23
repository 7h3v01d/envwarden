# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Subprocess helper. Always argv lists, never ``shell=True``."""

from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

log = logging.getLogger("envwarden.procs")

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


@dataclass(frozen=True)
class CmdResult:
    ok: bool
    code: int
    stdout: str
    stderr: str
    argv: tuple[str, ...]

    @property
    def output(self) -> str:
        text = "\n".join(p for p in (self.stdout.strip(), self.stderr.strip()) if p)
        return text or ("Command completed." if self.ok else f"Command failed with exit code {self.code}.")


def child_env() -> dict[str, str]:
    env = dict(os.environ)
    # An activated venv in the parent must never leak into the child.
    for key in ("VIRTUAL_ENV", "PYTHONHOME", "PYTHONPATH", "CONDA_PREFIX"):
        env.pop(key, None)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    env["PIP_NO_INPUT"] = "1"
    env["UV_NO_PROGRESS"] = "1"
    return env


def run(argv: Sequence[str | os.PathLike[str]], timeout: float = 900, cwd: Path | None = None,
        extra_env: dict[str, str] | None = None) -> CmdResult:
    args = tuple(str(a) for a in argv)
    log.info("run %s", " ".join(args))
    try:
        cp = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
            env={**child_env(), **(extra_env or {})},
            creationflags=_NO_WINDOW,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError as exc:
        return CmdResult(False, 127, "", f"Executable not found: {exc.filename or args[0]}", args)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout if isinstance(exc.stdout, str) else ""
        return CmdResult(False, 124, out, f"Timed out after {timeout:.0f}s", args)
    except OSError as exc:
        return CmdResult(False, 126, "", str(exc), args)
    return CmdResult(cp.returncode == 0, cp.returncode, cp.stdout or "", cp.stderr or "", args)
