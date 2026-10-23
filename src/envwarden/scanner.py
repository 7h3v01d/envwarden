# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Project import scanner.

Module -> distribution resolution uses the *target environment's*
``importlib.metadata.packages_distributions()`` (accurate for anything
installed), falling back to a small curated table for modules that are not
installed yet. Declared dependencies are read from ``pyproject.toml``
(PEP 621) and ``requirements*.txt`` so undeclared / unused ones are reported.

Per-project overrides live in ``envwarden.json`` at the project root::

    {"exclude": ["legacy"], "package_mappings": {"mylib": "my-dist"}}
"""

from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:  # pragma: no cover  (Python < 3.11)
    tomllib = None  # type: ignore[assignment]

from .versions import normalize

EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", ".nox", "node_modules", "build", "dist", "htmlcov", "site-packages",
    "venv", ".venv", "env", "virtualenv", ".idea", ".vscode", ".eggs",
}
MAX_FILE_BYTES = 2 * 1024 * 1024

# Only consulted for modules that are NOT installed in the target environment.
FALLBACK_MAPPINGS: dict[str, str] = {
    "bs4": "beautifulsoup4", "cv2": "opencv-python", "dotenv": "python-dotenv", "PIL": "pillow",
    "sklearn": "scikit-learn", "yaml": "pyyaml", "skimage": "scikit-image", "Crypto": "pycryptodome",
    "jose": "python-jose", "jwt": "pyjwt", "dateutil": "python-dateutil", "serial": "pyserial",
    "win32api": "pywin32", "win32con": "pywin32", "win32com": "pywin32", "pythoncom": "pywin32",
    "attr": "attrs", "nacl": "pynacl", "magic": "python-magic", "docx": "python-docx",
    "pptx": "python-pptx", "fitz": "pymupdf", "usb": "pyusb", "gi": "pygobject",
    "OpenGL": "pyopengl", "zmq": "pyzmq", "telegram": "python-telegram-bot", "slugify": "python-slugify",
    "multipart": "python-multipart", "google.protobuf": "protobuf", "websocket": "websocket-client",
    "mpl_toolkits": "matplotlib", "pkg_resources": "setuptools", "_pytest": "pytest",
}

PROJECT_MARKERS = ("pyproject.toml", "setup.py", "setup.cfg", ".git")


@dataclass
class ImportFinding:
    module: str
    distribution: str
    installed_version: str  # "" when missing
    files: list[str] = field(default_factory=list)

    @property
    def missing(self) -> bool:
        return not self.installed_version


@dataclass
class ScanReport:
    project_root: str
    files_scanned: int
    parse_errors: list[str]
    findings: list[ImportFinding]
    declared: list[str]
    undeclared: list[str]
    unused_declared: list[str]

    @property
    def missing(self) -> list[ImportFinding]:
        return [f for f in self.findings if f.missing]

    def requirements_lines(self) -> list[str]:
        lines = []
        for f in sorted(self.findings, key=lambda x: x.distribution.lower()):
            lines.append(f"{f.distribution}=={f.installed_version}" if f.installed_version else f.distribution)
        return sorted(set(lines), key=str.lower)

    def summary(self) -> str:
        return (
            f"Project root: {self.project_root}\n"
            f"Files scanned: {self.files_scanned} (parse errors: {len(self.parse_errors)})\n"
            f"Third-party imports: {len(self.findings)}  ·  missing from env: {len(self.missing)}\n"
            f"Undeclared: {len(self.undeclared)}  ·  declared but unused: {len(self.unused_declared)}"
        )


def find_project_root(start: Path, max_up: int = 4) -> Path:
    start = start.resolve()
    current = start
    for _ in range(max_up + 1):
        if any((current / m).exists() for m in PROJECT_MARKERS):
            return current
        if current.parent == current:
            break
        current = current.parent
    return start


def load_project_config(root: Path) -> dict[str, Any]:
    cfg_path = root / "envwarden.json"
    if not cfg_path.is_file():
        return {}
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def iter_python_files(root: Path, excluded: set[str]):
    for dirpath, dirnames, filenames in os.walk(root):
        d = Path(dirpath)
        # prune excluded dirs and anything that is itself a virtualenv
        dirnames[:] = [
            n for n in dirnames
            if n not in excluded and not n.startswith(".venv") and not (d / n / "pyvenv.cfg").exists()
        ]
        for name in filenames:
            if name.endswith((".py", ".pyw")):
                yield d / name


def extract_imports(path: Path) -> set[str]:
    """Absolute imports only, as top-level module names (plus dotted 'google.x' style)."""
    source = path.read_text(encoding="utf-8-sig", errors="replace")
    tree = ast.parse(source, filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def local_modules(root: Path) -> set[str]:
    local: set[str] = set()
    for base in (root, root / "src"):
        if not base.is_dir():
            continue
        try:
            for item in base.iterdir():
                if item.is_dir() and ((item / "__init__.py").exists() or any(item.glob("*.py"))):
                    local.add(item.name)
                elif item.suffix in (".py", ".pyw"):
                    local.add(item.stem)
        except OSError:
            continue
    return local


_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def declared_dependencies(root: Path) -> set[str]:
    names: set[str] = set()
    pyproject = root / "pyproject.toml"
    if pyproject.is_file() and tomllib is not None:
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            project = data.get("project", {})
            specs = list(project.get("dependencies", []))
            for group in project.get("optional-dependencies", {}).values():
                specs.extend(group)
            for group in data.get("dependency-groups", {}).values():  # PEP 735
                specs.extend(s for s in group if isinstance(s, str))
            for spec in specs:
                m = _REQ_LINE.match(spec)
                if m:
                    names.add(normalize(m.group(1)))
        except (OSError, ValueError):
            pass
    for req in root.glob("requirements*.txt"):
        try:
            for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith("-"):
                    continue
                m = _REQ_LINE.match(line)
                if m:
                    names.add(normalize(m.group(1)))
        except OSError:
            continue
    return names


def _resolve(module: str, ctx: dict[str, Any], mappings: dict[str, str]) -> tuple[str | None, str]:
    """Return (distribution, top-level) or (None, top) when stdlib/builtin."""
    top = module.split(".")[0]
    stdlib = set(ctx.get("stdlib", ())) | set(ctx.get("builtins", ()))
    if top in stdlib or top.startswith("_") and top.lstrip("_") in stdlib:
        return None, top
    # user overrides first, then dotted fallback ('google.protobuf'), then top-level
    for key in (module, top):
        if key in mappings:
            return mappings[key], top
    pd: dict[str, list[str]] = ctx.get("packages_distributions", {})
    if top in pd and pd[top]:
        dists = pd[top]
        return (dists[0] if len(dists) == 1 else sorted(dists, key=len)[0]), top
    for key in (".".join(module.split(".")[:2]), top):
        if key in FALLBACK_MAPPINGS:
            return FALLBACK_MAPPINGS[key], top
    return top, top


def scan_project(project_dir: Path, ctx: dict[str, Any]) -> ScanReport:
    root = find_project_root(project_dir)
    config = load_project_config(root)
    excluded = EXCLUDED_DIRS | set(config.get("exclude", []))
    mappings = {str(k): str(v) for k, v in config.get("package_mappings", {}).items()}
    local = local_modules(root)
    installed = {normalize(k): v for k, v in ctx.get("installed", {}).items()}

    by_dist: dict[str, ImportFinding] = {}
    parse_errors: list[str] = []
    files = 0
    for path in iter_python_files(root, excluded):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            modules = extract_imports(path)
        except (SyntaxError, ValueError, OSError) as exc:
            parse_errors.append(f"{path.relative_to(root)}: {type(exc).__name__}")
            continue
        files += 1
        rel = str(path.relative_to(root))
        for module in modules:
            dist, top = _resolve(module, ctx, mappings)
            if dist is None or top in local:
                continue
            key = normalize(dist)
            finding = by_dist.get(key)
            if finding is None:
                finding = by_dist[key] = ImportFinding(module=top, distribution=dist, installed_version=installed.get(key, ""))
            if rel not in finding.files and len(finding.files) < 25:
                finding.files.append(rel)

    declared = declared_dependencies(root)
    used = set(by_dist)
    return ScanReport(
        project_root=str(root),
        files_scanned=files,
        parse_errors=parse_errors,
        findings=sorted(by_dist.values(), key=lambda f: f.distribution.lower()),
        declared=sorted(declared),
        undeclared=sorted(used - declared) if declared else [],
        unused_declared=sorted(declared - used),
    )
