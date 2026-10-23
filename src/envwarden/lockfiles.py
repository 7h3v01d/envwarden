# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Declared / locked dependencies and drift against what is actually installed.

Source of truth, in precedence order:
  uv.lock  >  pylock.toml (PEP 751)  >  requirements.txt  >  pyproject.toml [project]
poetry.lock / Pipfile.lock are recognised but left to their own tools.

Markers (``sys_platform == 'win32'``, ``python_version < '3.12'`` …) are evaluated
against the TARGET environment's own marker values, so a Windows-only
dependency isn't reported missing on Linux and vice versa.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

from packaging.markers import InvalidMarker, Marker, UndefinedComparison, UndefinedEnvironmentName
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .versions import normalize

BASE_TOOLS = {"pip", "setuptools", "wheel", "uv"}


@dataclass(frozen=True)
class Source:
    kind: str  # uv.lock | pylock.toml | requirements.txt | pyproject.toml | poetry.lock | Pipfile.lock
    path: str

    @property
    def is_lock(self) -> bool:
        return self.kind in ("uv.lock", "pylock.toml")

    @property
    def foreign_tool(self) -> str:
        return {"poetry.lock": "Poetry (poetry install)", "Pipfile.lock": "Pipenv (pipenv sync)"}.get(self.kind, "")


@dataclass
class Expected:
    name: str  # normalized
    display: str
    exact: str = ""  # pinned version ("" = any / range)
    spec: str = ""  # PEP 440 specifier set for ranges
    editable_root: bool = False


@dataclass
class Drift:
    source: Source | None
    missing: list[str] = field(default_factory=list)
    mismatched: list[tuple[str, str, str]] = field(default_factory=list)  # name, installed, wanted
    extra: list[str] = field(default_factory=list)  # installed but not in the lock (exact sources only)
    stale: str = ""  # lock older than its pyproject
    notes: list[str] = field(default_factory=list)
    checked: int = 0

    @property
    def drifted(self) -> int:
        return len(self.missing) + len(self.mismatched)

    @property
    def status(self) -> str:
        if self.source is None:
            return "no deps declared"
        if self.source.foreign_tool:
            return f"managed by {self.source.foreign_tool.split(' ')[0]}"
        if self.stale:
            return "lock stale"
        if self.drifted:
            return f"{self.drifted} drifted"
        return "in sync" + (f" (+{len(self.extra)} extra)" if self.extra else "")

    def describe(self) -> str:
        if self.source is None:
            return "No requirements, lock file or pyproject dependencies found."
        lines = [f"Source: {self.source.kind}  ({self.source.path})", f"Status: {self.status}  · {self.checked} checked"]
        if self.stale:
            lines.append(f"! {self.stale}")
        if self.missing:
            lines.append(f"\nMISSING ({len(self.missing)})")
            lines += [f"  - {n}" for n in self.missing]
        if self.mismatched:
            lines.append(f"\nWRONG VERSION ({len(self.mismatched)})")
            lines += [f"  ~ {n}: installed {have}, wants {want}" for n, have, want in self.mismatched]
        if self.extra:
            lines.append(f"\nNOT IN LOCK ({len(self.extra)}) — an exact sync would remove these")
            lines += [f"  + {n}" for n in self.extra]
        if self.notes:
            lines.append("")
            lines += [f"note: {n}" for n in self.notes]
        return "\n".join(lines)


# ---------------------------------------------------------------- detection
def detect_sources(project: Path) -> list[Source]:
    order = ("uv.lock", "pylock.toml", "poetry.lock", "Pipfile.lock", "requirements.txt", "pyproject.toml")
    found = [Source(k, str(project / k)) for k in order if (project / k).is_file()
             and (k != "pyproject.toml" or _pyproject_has_project(project / k))]
    if not (project / "pylock.toml").is_file():
        for extra in sorted(project.glob("pylock.*.toml")):  # PEP 751 named locks
            found.insert(1, Source("pylock.toml", str(extra)))
            break
    return found


def primary_source(project: Path) -> Source | None:
    srcs = detect_sources(project)
    return srcs[0] if srcs else None


def _load_toml(path: Path) -> dict[str, Any]:
    if tomllib is None:
        raise RuntimeError("tomllib unavailable")
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _pyproject_has_project(path: Path) -> bool:
    """A pyproject.toml that only configures tools (black, ruff…) declares nothing."""
    try:
        return bool(_load_toml(path).get("project"))
    except (OSError, ValueError, RuntimeError):
        return False


# ---------------------------------------------------------------- markers
def _marker_ok(marker: str, env: dict[str, str], notes: list[str], groups: set[str] | None = None) -> bool:
    if not marker:
        return True
    try:
        m = Marker(marker)
    except InvalidMarker:
        notes.append(f"unparseable marker kept: {marker}")
        return True
    try:
        if groups is not None:  # PEP 751 lock-file markers may reference extras / dependency_groups
            lock_env: dict[str, Any] = dict(env, extras=frozenset(), dependency_groups=frozenset(groups))
            try:
                return m.evaluate(lock_env, context="lock_file")  # packaging >= 25
            except TypeError:
                pass
        return m.evaluate(dict(env, extra=""))
    except (UndefinedEnvironmentName, UndefinedComparison, ValueError, TypeError) as exc:
        notes.append(f"marker '{marker}' not evaluable ({exc.__class__.__name__}); kept")
        return True


# ---------------------------------------------------------------- readers
def expected_from_uv_lock(path: Path, env: dict[str, str], groups: tuple[str, ...] = ("dev",)) -> tuple[dict[str, Expected], list[str]]:
    """Walk uv.lock from its project roots, following only edges whose markers hold for *env*."""
    notes: list[str] = []
    data = _load_toml(path)
    packages: list[dict[str, Any]] = data.get("package", [])
    by_name: dict[str, list[dict[str, Any]]] = {}
    for pkg in packages:
        by_name.setdefault(normalize(pkg["name"]), []).append(pkg)

    def pick(edge: dict[str, Any]) -> dict[str, Any] | None:
        cands = by_name.get(normalize(edge.get("name", "")), [])
        if "version" in edge:
            cands = [c for c in cands if c.get("version") == edge["version"]] or cands
        return cands[0] if cands else None

    roots = [p for p in packages if any(k in (p.get("source") or {}) for k in ("editable", "virtual"))]
    if not roots:
        notes.append("uv.lock has no project root; every locked package is expected")
        roots_edges = [{"name": p["name"]} for p in packages]
    else:
        roots_edges = []
    out: dict[str, Expected] = {}
    queue: list[tuple[dict[str, Any], list[str]]] = []
    for root in roots:
        src = root.get("source") or {}
        if "editable" in src:  # uv sync installs the project itself (virtual roots are not installed)
            out[normalize(root["name"])] = Expected(normalize(root["name"]), root["name"], editable_root=True)
        edges = list(root.get("dependencies", []))
        for g in groups:
            edges += (root.get("dev-dependencies") or {}).get(g, [])
        for e in edges:
            queue.append((e, []))
    for e in roots_edges:
        queue.append((e, []))
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    while queue:
        edge, _ = queue.pop()
        if not _marker_ok(edge.get("marker", ""), env, notes):
            continue
        pkg = pick(edge)
        if pkg is None:
            notes.append(f"uv.lock edge to unknown package {edge.get('name')}")
            continue
        extras = tuple(sorted(edge.get("extra", []) or []))
        key = (normalize(pkg["name"]), str(pkg.get("version", "")), extras)
        if key in seen:
            continue
        seen.add(key)
        name = normalize(pkg["name"])
        if name not in out:
            src = pkg.get("source") or {}
            out[name] = Expected(name, pkg["name"], exact=str(pkg.get("version", "")),
                                 editable_root="editable" in src or "virtual" in src)
        for dep in pkg.get("dependencies", []) or []:
            queue.append((dep, []))
        for ex in extras:
            for dep in (pkg.get("optional-dependencies") or {}).get(ex, []):
                queue.append((dep, []))
    return out, notes


def uv_lock_staleness(lock: Path, pyproject: Path) -> str:
    """Compare pyproject's declared dependency names against the lock's recorded metadata."""
    try:
        proj = _load_toml(pyproject).get("project", {})
        data = _load_toml(lock)
    except (OSError, ValueError, RuntimeError):
        return ""
    name = normalize(proj.get("name", ""))
    root = next((p for p in data.get("package", []) if normalize(p.get("name", "")) == name), None)
    if root is None:
        return "pyproject's project is not in uv.lock — run `uv lock`" if name else ""
    def key(name: str, spec: str) -> tuple[str, SpecifierSet | str]:
        try:
            return normalize(name), SpecifierSet(spec)
        except InvalidSpecifier:
            return normalize(name), spec

    locked = {key(r["name"], str(r.get("specifier", ""))) for r in (root.get("metadata") or {}).get("requires-dist", [])}
    declared = set()
    for spec in proj.get("dependencies", []):
        try:
            req = Requirement(spec)
        except InvalidRequirement:
            continue
        declared.add(key(req.name, str(req.specifier)))
    if declared != locked:
        added = sorted({d[0] for d in declared - locked})
        return ("pyproject.toml dependencies changed since uv.lock was written"
                + (f" (new/changed: {', '.join(added)})" if added else "") + " — run `uv lock`")
    return ""


def expected_from_pylock(path: Path, env: dict[str, str]) -> tuple[dict[str, Expected], list[str]]:
    notes: list[str] = []
    data = _load_toml(path)
    groups = set(data.get("default-groups", []) or [])
    out: dict[str, Expected] = {}
    for pkg in data.get("packages", []):
        if not _marker_ok(pkg.get("marker", ""), env, notes, groups=groups):
            continue
        name = normalize(pkg["name"])
        editable = bool((pkg.get("directory") or {}).get("editable"))
        out[name] = Expected(name, pkg["name"], exact=str(pkg.get("version", "")), editable_root=editable)
    return out, notes


def _iter_requirement_lines(path: Path, notes: list[str], depth: int = 0):
    if depth > 5:
        notes.append(f"-r nesting too deep at {path.name}")
        return
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        notes.append(f"cannot read {path}: {exc}")
        return
    raw = re.sub(r"\\\r?\n", " ", raw)  # line continuations
    for line in raw.splitlines():
        line = re.split(r"(^|\s)#", line, maxsplit=1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r", "--requirement")):
            inc = line.split(maxsplit=1)[1] if " " in line else line[2:]
            yield from _iter_requirement_lines((path.parent / inc.strip()).resolve(), notes, depth + 1)
            continue
        if line.startswith(("-e", "--editable")):
            notes.append(f"editable requirement not checked: {line}")
            continue
        if line.startswith("-"):
            continue  # -c, --index-url, --hash-only lines …
        yield re.split(r"\s--?[a-z]", line, maxsplit=1)[0].strip()  # drop trailing --hash options


def expected_from_requirements(path: Path, env: dict[str, str]) -> tuple[dict[str, Expected], list[str]]:
    notes: list[str] = []
    out: dict[str, Expected] = {}
    for line in _iter_requirement_lines(path, notes):
        try:
            req = Requirement(line)
        except InvalidRequirement:
            notes.append(f"unparseable requirement skipped: {line}")
            continue
        if req.url:
            notes.append(f"URL requirement not version-checked: {req.name}")
        if req.marker is not None and not _marker_ok(str(req.marker), env, notes):
            continue
        out[normalize(req.name)] = _expected_from_req(req)
    return out, notes


def expected_from_pyproject(path: Path, env: dict[str, str]) -> tuple[dict[str, Expected], list[str]]:
    notes: list[str] = []
    proj = _load_toml(path).get("project", {})
    out: dict[str, Expected] = {}
    if "dependencies" in proj.get("dynamic", []):
        notes.append("dependencies are dynamic in pyproject.toml — cannot check them statically")
    for spec in proj.get("dependencies", []):
        try:
            req = Requirement(spec)
        except InvalidRequirement:
            notes.append(f"unparseable dependency skipped: {spec}")
            continue
        if req.marker is not None and not _marker_ok(str(req.marker), env, notes):
            continue
        out[normalize(req.name)] = _expected_from_req(req)
    if proj.get("name"):
        n = normalize(proj["name"])
        out.setdefault(n, Expected(n, proj["name"], editable_root=True))
    return out, notes


def _expected_from_req(req: Requirement) -> Expected:
    pins = [s.version for s in req.specifier if s.operator in ("==", "===") and "*" not in s.version]
    if len(pins) == 1 and len(req.specifier) == 1:
        return Expected(normalize(req.name), req.name, exact=pins[0])
    return Expected(normalize(req.name), req.name, spec=str(req.specifier))


# ---------------------------------------------------------------- comparison
def _same_version(a: str, b: str) -> bool:
    try:
        return Version(a) == Version(b)
    except InvalidVersion:
        return a == b


def compute_drift(project: Path, installed: dict[str, str], env: dict[str, str]) -> Drift:
    src = primary_source(project)
    drift = Drift(src)
    if src is None or src.foreign_tool:
        if src is not None:
            drift.notes.append(f"Locked by {src.foreign_tool}; EnvWarden leaves syncing to that tool.")
        return drift
    readers = {"uv.lock": expected_from_uv_lock, "pylock.toml": expected_from_pylock,
               "requirements.txt": expected_from_requirements, "pyproject.toml": expected_from_pyproject}
    try:
        expected, notes = readers[src.kind](Path(src.path), env)
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        drift.notes.append(f"could not read {src.kind}: {exc}")
        return drift
    drift.notes += notes
    if src.kind == "uv.lock" and (project / "pyproject.toml").is_file():
        drift.stale = uv_lock_staleness(Path(src.path), project / "pyproject.toml")
    have = {normalize(k): v for k, v in installed.items()}
    for name, exp in sorted(expected.items()):
        drift.checked += 1
        got = have.get(name)
        if got is None:
            drift.missing.append(exp.display)
        elif exp.editable_root:
            continue
        elif exp.exact and not _same_version(got, exp.exact):
            drift.mismatched.append((exp.display, got, f"=={exp.exact}"))
        elif exp.spec:
            try:
                if not SpecifierSet(exp.spec).contains(got, prereleases=True):
                    drift.mismatched.append((exp.display, got, exp.spec))
            except (InvalidSpecifier, InvalidVersion):
                drift.notes.append(f"could not compare {exp.display} {got} against {exp.spec}")
    if src.is_lock:
        drift.extra = sorted(display for n, display in ((normalize(k), k) for k in installed)
                             if n not in expected and n not in BASE_TOOLS)
    return drift


def requires_python_conflict(project: Path, python_version: str) -> str:
    """Message if the env's Python does not satisfy the project's requires-python, else ''."""
    spec = ""
    for f, key in ((project / "uv.lock", None), (project / "pyproject.toml", "project")):
        if f.is_file():
            try:
                data = _load_toml(f)
            except (OSError, ValueError, RuntimeError):
                continue
            spec = (data.get(key, {}) if key else data).get("requires-python", "") or spec
            if spec:
                break
    if not spec or not python_version or python_version == "?":
        return ""
    try:
        if SpecifierSet(spec).contains(python_version, prereleases=True):
            return ""
    except (InvalidSpecifier, InvalidVersion):
        return ""
    return f"the venv runs Python {python_version} but the project requires-python {spec}"
