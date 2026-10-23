# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Workspace discovery: find projects and the virtualenvs that live inside them.

A *workspace* is a folder such as ``C:\\dev`` that holds many projects. Walking it
(depth-limited, pruning heavy folders) yields:

* every virtualenv (a directory containing ``pyvenv.cfg``) — never descended into;
* every Python project (a folder with pyproject.toml / setup.py / setup.cfg /
  requirements*.txt / Pipfile, or with top-level .py files next to a venv);
* the link between them: a venv's *owner project* is its parent folder.

So a project with no venv is reported as such, instead of the tool assuming one
must be built — and a project that already has ``.venv`` is never given a second.
Nothing here writes to disk.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .paths import is_venv

PROJECT_MARKERS = ("pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "requirements.txt")
CONVENTIONAL_VENV_NAMES = (".venv", "venv", "env", ".env", "virtualenv", ".virtualenv")
PRUNE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", ".nox", "build", "dist", "site-packages", ".idea", ".vscode", ".gradle", "target",
    "$recycle.bin", "system volume information", "appdata", ".cache", ".cargo", ".rustup", ".npm",
}
DEFAULT_DEPTH = 4
MAX_DIRS = 50_000  # hard stop so a mis-chosen root (e.g. C:\) can't run forever


@dataclass
class FoundVenv:
    path: str
    project_dir: str  # owner project folder ("" when the venv is not inside a project)
    python_version: str  # from pyvenv.cfg, may be ""


@dataclass
class FoundProject:
    path: str
    name: str
    markers: list[str]
    venvs: list[str] = field(default_factory=list)  # venv paths owned by this project

    @property
    def status(self) -> str:
        if not self.venvs:
            return "no-venv"
        return "multiple" if len(self.venvs) > 1 else "has-venv"


@dataclass
class DiscoveryResult:
    roots: list[str]
    projects: list[FoundProject]
    venvs: list[FoundVenv]
    dirs_visited: int
    truncated: bool
    errors: list[str] = field(default_factory=list)


def project_markers(folder: Path) -> list[str]:
    found: list[str] = []
    try:
        names = {e.name for e in os.scandir(folder) if e.is_file()}
    except OSError:
        return found
    for m in PROJECT_MARKERS:
        if m in names:
            found.append(m)
    found += sorted(n for n in names if re.fullmatch(r"requirements[-_.].*\.txt", n))
    return found


def _has_python_files(folder: Path) -> bool:
    try:
        return any(e.name.endswith((".py", ".pyw")) and e.is_file() for e in os.scandir(folder))
    except OSError:
        return False


def venv_python_version(venv_dir: Path) -> str:
    try:
        for line in (venv_dir / "pyvenv.cfg").read_text(encoding="utf-8", errors="replace").splitlines():
            key, _, val = line.partition("=")
            if key.strip().lower() in ("version", "version_info"):
                return val.strip()
    except OSError:
        pass
    return ""


def venvs_in_project(project_dir: Path) -> list[Path]:
    """Virtualenvs directly inside *project_dir* (conventional names first)."""
    found: list[Path] = []
    try:
        entries = sorted(os.scandir(project_dir), key=lambda e: e.name.lower())
    except OSError:
        return found
    for e in entries:
        if e.is_dir(follow_symlinks=False) and ".envwarden-trash-" not in e.name and is_venv(Path(e.path)):
            found.append(Path(e.path))
    return sorted(found, key=lambda p: (p.name not in CONVENTIONAL_VENV_NAMES, p.name.lower()))


def discover(roots: list[str], max_depth: int = DEFAULT_DEPTH, exclude: set[str] | None = None) -> DiscoveryResult:
    prune = PRUNE_DIRS | {x.lower() for x in (exclude or set())}
    projects: dict[str, FoundProject] = {}
    venvs: dict[str, FoundVenv] = {}
    errors: list[str] = []
    visited = 0
    truncated = False

    for root in roots:
        base = Path(root).expanduser()
        if not base.is_dir():
            errors.append(f"Workspace not found: {base}")
            continue
        base = base.resolve()
        stack: list[tuple[Path, int]] = [(base, 0)]
        while stack:
            folder, depth = stack.pop()
            visited += 1
            if visited > MAX_DIRS:
                truncated = True
                break
            if is_venv(folder):
                key = os.path.normcase(str(folder))
                if key not in venvs:
                    venvs[key] = FoundVenv(str(folder), "", venv_python_version(folder))
                continue  # never walk inside a venv
            markers = project_markers(folder)
            child_venvs = venvs_in_project(folder)
            if markers or (child_venvs and _has_python_files(folder)):
                pkey = os.path.normcase(str(folder))
                projects.setdefault(pkey, FoundProject(str(folder), folder.name, markers))
            if depth >= max_depth:
                # still record venvs sitting directly here even at max depth
                for v in child_venvs:
                    stack.append((v, depth + 1))
                continue
            try:
                children = [e for e in os.scandir(folder) if e.is_dir(follow_symlinks=False)]
            except OSError as exc:
                errors.append(f"{folder}: {exc.strerror or exc}")
                continue
            for e in children:
                name = e.name.lower()
                if name in prune or ".envwarden-trash-" in name or (name.startswith(".") and name not in CONVENTIONAL_VENV_NAMES
                                     and not is_venv(Path(e.path))):
                    continue
                stack.append((Path(e.path), depth + 1))
        if truncated:
            break

    # link venvs to owning projects (owner = parent folder)
    for v in venvs.values():
        parent = os.path.normcase(str(Path(v.path).parent))
        proj = projects.get(parent)
        if proj:
            v.project_dir = proj.path
            proj.venvs.append(v.path)
    for p in projects.values():
        p.venvs.sort(key=lambda s: (Path(s).name not in CONVENTIONAL_VENV_NAMES, s.lower()))

    return DiscoveryResult(
        roots=[str(Path(r).expanduser()) for r in roots],
        projects=sorted(projects.values(), key=lambda p: p.path.lower()),
        venvs=sorted(venvs.values(), key=lambda v: v.path.lower()),
        dirs_visited=visited,
        truncated=truncated,
        errors=errors,
    )


_NAME_CLEAN = re.compile(r"[^A-Za-z0-9_.-]+")


def suggest_env_name(venv_path: Path, project_dir: str) -> str:
    """'myproj' for myproj/.venv; 'myproj-venv311' for a non-conventional folder name."""
    base = Path(project_dir).name if project_dir else venv_path.parent.name
    stem = _NAME_CLEAN.sub("-", base).strip("-.") or "env"
    if venv_path.name not in CONVENTIONAL_VENV_NAMES:
        stem = f"{stem}-{_NAME_CLEAN.sub('-', venv_path.name).strip('-.')}"
    if not stem[0].isalnum():
        stem = "p" + stem
    return stem[:60]
