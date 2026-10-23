# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Installer backends.

``uv`` is used when it is on PATH (fast, can fetch managed Pythons);
otherwise the stdlib ``venv`` + ``python -m pip`` path is used. Both are
driven through the *target environment's* interpreter, never a global pip.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .paths import frozen
from .procs import run

VERSION_SPEC = re.compile(r"^\d+(\.\d+){0,2}$")


@dataclass(frozen=True)
class PythonInfo:
    version: str
    path: str
    source: str


@dataclass(frozen=True)
class Backend:
    kind: str  # "uv" | "pip"
    uv_path: str | None = None
    uv_version: str = ""

    @property
    def label(self) -> str:
        return f"uv {self.uv_version}".strip() if self.kind == "uv" else "pip (stdlib venv)"

    # -- environment creation ------------------------------------------------
    def venv_argv(self, target: Path, python: str = "") -> list[str]:
        if self.kind == "uv":
            argv = [str(self.uv_path), "venv", "--seed", "--no-config"]
            if python:
                argv += ["--python", python]
            return argv + [str(target)]
        exe = resolve_python(python) if python else default_python()
        if not exe:
            raise LookupError(f"Python '{python}' was not found. Install it, or install uv to fetch it automatically.")
        return [exe, "-m", "venv", str(target)]

    # -- package operations --------------------------------------------------
    def pip_argv(self, env_python: Path, *args: str) -> list[str]:
        if self.kind == "uv":
            return [str(self.uv_path), "pip", *args, "--python", str(env_python)]
        return [str(env_python), "-m", "pip", *args]

    def install_argv(self, env_python: Path, specs: Sequence[str], upgrade: bool = False) -> list[str]:
        extra = ["--upgrade"] if upgrade else []
        return self.pip_argv(env_python, "install", *extra, *specs)

    def install_requirements_argv(self, env_python: Path, req_file: Path) -> list[str]:
        return self.pip_argv(env_python, "install", "-r", str(req_file))

    def uninstall_argv(self, env_python: Path, names: Sequence[str]) -> list[str]:
        if self.kind == "uv":
            return self.pip_argv(env_python, "uninstall", *names)
        return self.pip_argv(env_python, "uninstall", "-y", *names)

    def freeze_argv(self, env_python: Path) -> list[str]:
        return self.pip_argv(env_python, "freeze")

    def outdated_argv(self, env_python: Path) -> list[str]:
        return self.pip_argv(env_python, "list", "--outdated", "--format", "json")

    def check_argv(self, env_python: Path) -> list[str]:
        return self.pip_argv(env_python, "check")


def detect_backend(prefer: str = "auto") -> Backend:
    if prefer in ("auto", "uv"):
        uv = shutil.which("uv")
        if uv:
            res = run([uv, "--version"], timeout=20)
            version = res.stdout.split()[1] if res.ok and len(res.stdout.split()) > 1 else ""
            return Backend("uv", uv, version)
    return Backend("pip")


def default_python() -> str | None:
    if not frozen() and sys.executable:
        return sys.executable
    return shutil.which("python") or shutil.which("python3")


def resolve_python(spec: str) -> str | None:
    """Resolve '3.12', '3.12.4' or an interpreter path to an executable path."""
    spec = spec.strip()
    if not spec:
        return default_python()
    candidate = Path(spec).expanduser()
    if candidate.is_file():
        return str(candidate)
    if not VERSION_SPEC.match(spec):
        return None
    major_minor = ".".join(spec.split(".")[:2])
    if os.name == "nt" and shutil.which("py"):
        res = run(["py", f"-{major_minor}", "-c", "import sys;print(sys.executable)"], timeout=30)
        if res.ok and res.stdout.strip():
            return res.stdout.strip()
    found = shutil.which(f"python{major_minor}")
    return found


def discover_pythons(backend: Backend) -> list[PythonInfo]:
    found: dict[str, PythonInfo] = {}
    if backend.kind == "uv":
        res = run([str(backend.uv_path), "python", "list", "--only-installed", "--output-format", "json"], timeout=60)
        if res.ok:
            try:
                for item in json.loads(res.stdout):
                    path = item.get("path") or ""
                    ver = item.get("version") or ""
                    if path and ver and path not in found:
                        found[path] = PythonInfo(ver, path, "uv")
            except ValueError:
                pass
    if os.name == "nt" and shutil.which("py"):
        res = run(["py", "-0p"], timeout=30)
        for line in res.stdout.splitlines():
            m = re.match(r"^\s*-V:(\S+)\s+\*?\s*(.+?)\s*$", line) or re.match(r"^\s*-(\d+\.\d+)\S*\s+\*?\s*(.+?)\s*$", line)
            if m and m.group(2) not in found:
                found[m.group(2)] = PythonInfo(m.group(1), m.group(2), "py launcher")
    else:
        for minor in range(8, 16):
            exe = shutil.which(f"python3.{minor}")
            if exe and exe not in found:
                found[exe] = PythonInfo(f"3.{minor}", exe, "PATH")
    unique: dict[str, PythonInfo] = {}
    for info in found.values():
        try:
            real = os.path.normcase(os.path.realpath(info.path))
        except OSError:
            real = info.path
        unique.setdefault(real, info)

    def key(p: PythonInfo) -> tuple[int, ...]:
        return tuple(int(x) for x in re.findall(r"\d+", p.version)[:3])

    return sorted(unique.values(), key=key, reverse=True)
