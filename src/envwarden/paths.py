# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Application storage layout.

Windows : %LOCALAPPDATA%\\EnvWarden
Other   : $XDG_DATA_HOME/envwarden  (default ~/.local/share/envwarden)
Override: ENVWARDEN_HOME (used by the test-suite and portable installs)
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path


def default_home() -> Path:
    override = os.environ.get("ENVWARDEN_HOME")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "EnvWarden"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "envwarden"


@dataclass(frozen=True)
class AppPaths:
    home: Path

    @classmethod
    def create(cls, home: Path | None = None) -> "AppPaths":
        paths = cls((home or default_home()).resolve())
        paths.ensure()
        return paths

    @property
    def envs(self) -> Path:
        return self.home / "environments"

    @property
    def meta(self) -> Path:
        return self.home / "meta"

    @property
    def snapshots(self) -> Path:
        return self.home / "snapshots"

    @property
    def templates(self) -> Path:
        return self.home / "templates"

    @property
    def temp(self) -> Path:
        return self.home / "temp"

    @property
    def scans(self) -> Path:
        return self.home / "scans"

    @property
    def registry(self) -> Path:
        return self.home / "registry.json"

    @property
    def settings(self) -> Path:
        return self.home / "settings.json"

    @property
    def audit(self) -> Path:
        return self.home / "audit.jsonl"

    @property
    def runtime_log(self) -> Path:
        return self.home / "runtime.log"

    def ensure(self) -> None:
        for d in (self.home, self.envs, self.meta, self.snapshots, self.templates, self.temp, self.scans):
            d.mkdir(parents=True, exist_ok=True)


def venv_python(env_dir: Path) -> Path:
    if os.name == "nt":
        return env_dir / "Scripts" / "python.exe"
    return env_dir / "bin" / "python"


def venv_bin(env_dir: Path) -> Path:
    return env_dir / ("Scripts" if os.name == "nt" else "bin")


def is_venv(path: Path) -> bool:
    return (path / "pyvenv.cfg").is_file()


def is_within(child: Path, parent: Path) -> bool:
    """True when *child* resolves strictly inside *parent* (never equal)."""
    try:
        c = child.resolve()
        p = parent.resolve()
    except OSError:
        return False
    return c != p and c.is_relative_to(p)


def frozen() -> bool:
    return bool(getattr(sys, "frozen", False))
