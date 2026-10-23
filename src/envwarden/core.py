# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Qt-free environment manager. Every public operation returns an OpResult.

Governance rules (deny-first):
* Mutating operations are serialised by one lock.
* Only directories strictly inside the managed root are ever deleted.
  Adopted (external) environments are *unregistered*, never deleted.
* Environments are never copied or moved on disk — venvs embed absolute
  paths, so a copy silently drives the original. Clone / rename / restore
  rebuild a fresh environment from a frozen package list instead.
* Wipe and upgrade-all take an automatic snapshot first.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from . import lockfiles, probe, scanner, security, workspace
from .audit import AuditLog
from .backend import Backend, detect_backend
from .filelock import InterProcessLock
from .paths import AppPaths, is_venv, is_within, venv_bin, venv_python
from .procs import run
from .versions import normalize, requirement_name, version_key

NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
WINDOWS_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
BASE_PACKAGES = {"pip", "setuptools", "wheel"}
HISTORY_LIMIT = 200


@dataclass
class OpResult:
    ok: bool
    message: str
    data: Any = None


@dataclass
class EnvInfo:
    name: str
    path: str
    managed: bool
    python_version: str = "?"
    packages: dict[str, str] = field(default_factory=dict)
    has_pip: bool = False
    health: str = "bad"  # ok | warn | bad
    health_detail: str = ""
    size_mb: float = 0.0
    meta: dict[str, Any] = field(default_factory=dict)
    base_executable: str = ""
    kind: str = "external"  # managed | project | external
    markers: dict[str, str] = field(default_factory=dict)  # PEP 508 environment of THIS env

    @property
    def project_dir(self) -> str:
        return str(self.meta.get("project_dir") or "")

    @property
    def project(self) -> str:
        return str(self.meta.get("project") or "—")

    @property
    def template(self) -> str:
        return str(self.meta.get("template") or "—")


TRUST_WARNING = (
    "First sync for {project}.\n\n"
    "Syncing dependencies is not just a file comparison: installing can run Python code — this project's "
    "build backend / setup.py and the build scripts of any dependency installed from source. "
    "Only continue for projects you trust. You are asked once per project."
)


@dataclass
class SyncPlan:
    argv: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    source: str = ""
    description: str = ""
    exact: bool = False  # removes packages that are not in the lock
    blocked: str = ""
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = [self.description]
        if self.exact:
            lines.append("Exact: packages not in the lock will be REMOVED (a safety snapshot is taken first).")
        lines += [f"! {w}" for w in self.warnings]
        return "\n".join(lines)


def valid_name(name: str) -> bool:
    return bool(NAME_PATTERN.match(name or "")) and name.lower().split(".")[0] not in WINDOWS_RESERVED and not name.endswith(".")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3]


def dir_size_mb(path: Path) -> float:
    total = 0
    for dirpath, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(dirpath, f)).st_size
            except OSError:
                continue
    return round(total / (1024 * 1024), 1)


TRASH_MARK = ".envwarden-trash-"
OWNER_MARKER = ".envwarden-owner.json"
TOKEN_RE = re.compile(r"[0-9a-f]{64}")
TOMB_NAME = re.compile(r"\.[^/\\]+" + re.escape(TRASH_MARK) + r"\d{8}-\d{6}-\d{3}")
# everything a venv may contain at top level (lower-cased); anything else means "not ours"
VENV_TOP_LEVEL = {"pyvenv.cfg", "lib", "lib64", "bin", "scripts", "include", "share", "etc", "man",
                  "cachedir.tag", ".gitignore", ".lock", "pyvenv.cfg.tmp", "conda-meta", OWNER_MARKER}


class EnvInUseError(OSError):
    """The environment folder could not be moved aside — something has files open in it."""


def _force_rmtree(path: Path) -> list[str]:
    """Delete a tree; return the paths that could not be removed (empty list = success).

    Safety: never follows symlinks and never changes the mode of a file that is a
    symlink or has other hard links. A venv's ``python`` is often a symlink to the
    system interpreter, and uv installs packages as hard links into its shared
    cache — chmod on either would alter files OUTSIDE the venv.
    Only Windows needs a permission change at all (to clear the read-only flag);
    POSIX unlink depends on the parent directory's permissions, not the file's.
    """
    leftovers: list[str] = []

    def onexc(func: Callable, p: str, exc: Any) -> None:
        exc = exc[1] if isinstance(exc, tuple) else exc  # 3.11 onerror passes exc_info
        if not isinstance(exc, PermissionError):
            if not isinstance(exc, FileNotFoundError):
                leftovers.append(p)
            return
        try:
            st = os.lstat(p)
        except OSError:
            return
        if os.name == "nt" and not stat.S_ISLNK(st.st_mode) and st.st_nlink <= 1:
            try:
                os.chmod(p, stat.S_IWRITE | stat.S_IREAD)  # clears FILE_ATTRIBUTE_READONLY only
                func(p)
                return
            except OSError:
                pass
        leftovers.append(p)

    if not os.path.lexists(path):
        return []
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=onexc)
    else:  # Python 3.11
        shutil.rmtree(path, onerror=onexc)
    if os.path.lexists(path) and not leftovers:
        leftovers.append(str(path))
    return leftovers


def _retire(path: Path) -> tuple[Path, str]:
    """Atomically move a venv folder aside and stamp it with a random ownership token.

    Fails (nothing changed) if the folder is in use on Windows. Returns (tomb, token);
    token is '' if the marker could not be written — such a tomb is never auto-purged.
    """
    tomb = path.with_name(f".{path.name}{TRASH_MARK}{_stamp()}")
    try:
        os.rename(path, tomb)
    except OSError as exc:
        raise EnvInUseError(exc.errno or 0,
                            f"'{path}' is in use (close any Python, shell, IDE or terminal using it) — {exc.strerror or exc}",
                            str(path)) from exc
    token = secrets.token_hex(32)  # random: never derived from path or time
    marker = {"format": 1, "token": token, "original": str(path), "created": _now()}
    try:
        fd = os.open(tomb / OWNER_MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(marker, fh)
    except OSError:
        token = ""
    return tomb, token


def _drop_marker(folder: Path) -> None:
    try:
        (folder / OWNER_MARKER).unlink(missing_ok=True)
    except OSError:
        pass


def _purge_tomb(tomb: Path) -> list[str]:
    """Delete a tomb, removing its ownership marker LAST.

    If something inside is locked, the marker survives with the leftovers, so a
    later purge can still prove the folder is ours. Returns leftover paths.
    """
    if not os.path.lexists(tomb):
        return []
    leftovers: list[str] = []
    try:
        entries = list(os.scandir(tomb))
    except OSError:
        return [str(tomb)]
    for e in entries:
        if e.name == OWNER_MARKER:
            continue
        if e.is_dir(follow_symlinks=False):
            leftovers += _force_rmtree(Path(e.path))
        else:
            try:
                os.unlink(e.path)
            except OSError:
                leftovers.append(e.path)
    if leftovers:
        return leftovers
    try:
        (tomb / OWNER_MARKER).unlink(missing_ok=True)
        os.rmdir(tomb)
    except OSError:
        return [str(tomb)]
    return []


class BusyError(RuntimeError):
    """Another process (or EnvManager) holds the mutation lock."""


class _MutationLock:
    """Thread re-entrant lock that also holds an inter-process file lock while entered.

    Every mutating EnvManager operation runs inside it, so 'one change at a time'
    holds across GUI windows, the CLI and any other process using this app home —
    not just inside one EnvManager object.
    """

    def __init__(self, path: Path, timeout: float) -> None:
        self._rlock = threading.RLock()
        self._ipl = InterProcessLock(path)
        self._depth = 0
        self.timeout = timeout
        self.operation = "change"

    def __enter__(self) -> "_MutationLock":
        self._rlock.acquire()
        if self._depth == 0:
            if not self._ipl.acquire(timeout=self.timeout):
                self._rlock.release()
                h = self._ipl.holder()
                who = (f"pid {h.get('pid')} — {h.get('operation')} since {h.get('since')}" if h else "another process")
                raise BusyError(f"Another EnvWarden is changing environments right now ({who}). "
                                "Nothing was changed; try again when it finishes.")
            self._ipl.write_holder(self.operation)
        self._depth += 1
        return self

    def __exit__(self, *_exc: Any) -> None:
        self._depth -= 1
        if self._depth == 0:
            self._ipl.release()
        self._rlock.release()


def mutating(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Run a public mutating operation under the cross-process lock; busy -> OpResult(False)."""
    import functools

    @functools.wraps(fn)
    def wrapper(self: "EnvManager", *args: Any, **kwargs: Any) -> Any:
        try:
            if self._mutex._depth == 0:
                self._mutex.operation = fn.__name__
            with self._mutex:
                return fn(self, *args, **kwargs)
        except BusyError as exc:
            return OpResult(False, str(exc), {"busy": True})

    return wrapper


class EnvManager:
    def __init__(self, paths: AppPaths | None = None, backend: Backend | None = None) -> None:
        self.paths = paths or AppPaths.create()
        self.backend = backend or detect_backend(os.environ.get("ENVWARDEN_BACKEND") or self._settings().get("backend", "auto"))
        self.audit = AuditLog(self.paths.audit)
        timeout = float(os.environ.get("ENVWARDEN_LOCK_TIMEOUT") or self._settings().get("lock_timeout", 3))
        self._mutex = _MutationLock(self.paths.home / "locks" / "mutation.lock", timeout)

    # ------------------------------------------------------------------ settings / registry
    def _read_json(self, path: Path, default: Any) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return default

    def _write_json(self, path: Path, payload: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)  # atomic

    def _settings(self) -> dict[str, Any]:
        return self._read_json(self.paths.settings, {})

    def _save_settings(self, settings: dict[str, Any]) -> None:
        self._write_json(self.paths.settings, settings)

    def _registry_data(self) -> dict[str, Any]:
        data = self._read_json(self.paths.registry, {})
        return data if isinstance(data, dict) else {}

    def _registry(self) -> dict[str, str]:
        adopted = self._registry_data().get("adopted", {})
        return {k: v for k, v in adopted.items() if isinstance(k, str) and isinstance(v, str)} \
            if isinstance(adopted, dict) else {}

    def _save_registry(self, adopted: dict[str, str]) -> None:
        data = self._registry_data()  # keep any other keys (forward compatibility)
        data["adopted"] = dict(sorted(adopted.items()))
        self._write_json(self.paths.registry, data)

    def _registered_by_path(self) -> dict[str, str]:
        """normcased resolved path -> env name, for every known env."""
        out: dict[str, str] = {}
        for name, p in self.env_paths().items():
            try:
                out[os.path.normcase(str(Path(p).resolve()))] = name
            except OSError:
                out[os.path.normcase(str(p))] = name
        return out

    def _unique_name(self, wanted: str) -> str:
        base = wanted if valid_name(wanted) else "env"
        name, n = base, 2
        while self.exists(name) or not valid_name(name):
            name = f"{base[:58]}-{n}"
            n += 1
        return name

    def meta(self, name: str) -> dict[str, Any]:
        return self._read_json(self.paths.meta / f"{name}.json", {})

    def _save_meta(self, name: str, meta: dict[str, Any]) -> None:
        self._write_json(self.paths.meta / f"{name}.json", meta)

    def _history(self, name: str, action: str, **extra: Any) -> None:
        meta = self.meta(name)
        hist = meta.setdefault("history", [])
        hist.append({"ts": _now(), "action": action, **extra})
        meta["history"] = hist[-HISTORY_LIMIT:]
        self._save_meta(name, meta)

    # ------------------------------------------------------------------ discovery
    def env_paths(self) -> dict[str, Path]:
        found: dict[str, Path] = {}
        for d in sorted(self.paths.envs.iterdir()) if self.paths.envs.exists() else []:
            if d.is_dir() and is_venv(d):
                found[d.name] = d
        for name, p in self._registry().items():
            found.setdefault(name, Path(p))
        return found

    def is_managed(self, name: str) -> bool:
        return is_within(self.paths.envs / name, self.paths.envs) and is_venv(self.paths.envs / name)

    def exists(self, name: str) -> bool:
        return name in self.env_paths() or (self.paths.envs / name).exists()

    def python_of(self, name: str) -> Path:
        path = self.env_paths().get(name)
        if path is None:
            raise KeyError(f"Environment '{name}' is not registered.")
        return venv_python(path)

    def inspect(self, name: str, with_size: bool = True) -> EnvInfo:
        path = self.env_paths()[name]
        info = EnvInfo(name=name, path=str(path), managed=self.is_managed(name), meta=self.meta(name))
        info.kind = self._kind(name, path, info.meta)
        problems: list[str] = []
        if not path.exists() or not is_venv(path):
            info.health_detail = "Directory no longer exists (or is no longer a venv)"
            return info
        cfg = probe.read_pyvenv_cfg(path)
        home = cfg.get("home", "")
        if home and not Path(home).exists():
            problems.append(f"Base interpreter folder missing: {home}")
        try:
            data = probe.info(venv_python(path))
        except probe.ProbeError as exc:
            info.health_detail = f"Interpreter failed: {exc}"
            return info
        info.python_version = data.get("version", "?")
        info.packages = {n: v for n, v in data.get("packages", [])}
        info.has_pip = bool(data.get("has_pip"))
        info.base_executable = data.get("base_executable", "")
        info.markers = dict(data.get("markers") or {})
        if data.get("prefix") == data.get("base_prefix"):
            problems.append("Interpreter is not running as a virtual environment")
        moved = probe.relocation_problem(path)
        if moved:
            problems.append(moved)
        if not info.has_pip and self.backend.kind == "pip":
            problems.append("pip is not installed (install uv, or run 'python -m ensurepip' in the env)")
        info.health = "warn" if problems else "ok"
        info.health_detail = "; ".join(problems) or f"Python {info.python_version} · {data.get('implementation', '')}"
        if with_size:
            info.size_mb = dir_size_mb(path)
        return info

    def _kind(self, name: str, path: Path, meta: dict[str, Any]) -> str:
        if self.is_managed(name):
            return "managed"
        pdir = meta.get("project_dir")
        if pdir and os.path.normcase(str(Path(pdir))) == os.path.normcase(str(Path(path).parent)):
            return "project"
        return "external"

    def inventory(self, with_size: bool = True) -> list[EnvInfo]:
        out: list[EnvInfo] = []
        for name in self.env_paths():
            try:
                out.append(self.inspect(name, with_size))
            except Exception as exc:  # one broken env must not hide the rest
                out.append(EnvInfo(name=name, path=str(self.env_paths().get(name, "")), managed=False, health_detail=str(exc)))
        return out

    # ------------------------------------------------------------------ helpers
    def _require(self, name: str) -> Path:
        if name not in self.env_paths():
            raise KeyError(f"Environment '{name}' does not exist.")
        return self.python_of(name)

    def _check_new_name(self, name: str) -> str | None:
        if not valid_name(name):
            return "Invalid name. Use letters, digits, '.', '_' or '-' (max 64, not a Windows reserved name)."
        if self.exists(name):
            return f"An environment named '{name}' already exists."
        return None

    def _python_spec_for(self, info: EnvInfo) -> str:
        """Interpreter to rebuild with: the source's base interpreter if it still exists."""
        if info.base_executable and Path(info.base_executable).exists():
            return info.base_executable
        return info.python_version if info.python_version != "?" else ""

    def _freeze(self, py: Path) -> tuple[bool, list[str], str]:
        res = run(self.backend.freeze_argv(py), timeout=300)
        if not res.ok:
            return False, [], res.output
        lines = [ln.strip() for ln in res.stdout.splitlines() if ln.strip() and not ln.startswith("#")]
        return True, lines, ""

    def _install_lines(self, py: Path, lines: list[str]) -> tuple[bool, str]:
        installable = [ln for ln in lines if requirement_name(ln) and normalize(requirement_name(ln) or "") not in BASE_PACKAGES]
        skipped = [ln for ln in lines if ln not in installable and normalize(requirement_name(ln) or ln) not in BASE_PACKAGES]
        if not installable:
            return True, "Nothing to install." + (f"\nSkipped (editable/URL): {', '.join(skipped)}" if skipped else "")
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8", dir=self.paths.temp) as fh:
            fh.write("\n".join(installable) + "\n")
            req = Path(fh.name)
        try:
            res = run(self.backend.install_requirements_argv(py, req), timeout=3600)
        finally:
            req.unlink(missing_ok=True)
        msg = res.output
        if skipped:
            msg += f"\n\nSkipped (editable/URL/local — reinstall manually): {', '.join(skipped)}"
        return res.ok, msg

    # ------------------------------------------------------------------ lifecycle
    @mutating
    def create(self, name: str, python: str = "", template: str = "", project: str = "",
               requirements: list[str] | None = None) -> OpResult:
        with self._mutex:
            problem = self._check_new_name(name)
            if problem:
                return OpResult(False, problem)
            target = self.paths.envs / name
            try:
                argv = self.backend.venv_argv(target, python)
            except LookupError as exc:
                return OpResult(False, str(exc))
            res = run(argv, timeout=1800)
            if not res.ok:
                if target.exists() and is_within(target, self.paths.envs):
                    _force_rmtree(target)  # partial new folder; nothing of the user's
                self.audit.record("CREATE_ENV", "failed", res.output[-500:], name=name)
                return OpResult(False, res.output)
            self._save_meta(name, {"created": _now(), "project": project or "", "template": template or "",
                                   "python_request": python or "default", "backend": self.backend.kind, "history": []})
            messages = [res.output]
            lines: list[str] = list(requirements or [])
            if template:
                tfile = self.template_path(template)
                if tfile and tfile.exists():
                    lines += [ln for ln in tfile.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
            ok = True
            if lines:
                ok, msg = self._install_lines(venv_python(target), lines)
                messages.append(msg)
            self._history(name, "create", project=project)
            self.audit.record("CREATE_ENV", "success" if ok else "partial", f"Created '{name}'", name=name,
                              python=python or "default", template=template, backend=self.backend.kind)
            return OpResult(ok, "\n\n".join(m for m in messages if m) or f"Created '{name}'.",
                            {"name": name})

    @mutating
    def adopt(self, source: str, name: str, project: str = "") -> OpResult:
        """Register an existing venv in place. Nothing on disk is touched."""
        with self._mutex:
            src = Path(source).expanduser().resolve()
            if not is_venv(src) or not venv_python(src).exists():
                return OpResult(False, f"'{src}' is not a virtual environment (no pyvenv.cfg / interpreter).")
            problem = self._check_new_name(name)
            if problem:
                return OpResult(False, problem)
            if any(Path(p).resolve() == src for p in self.env_paths().values()):
                return OpResult(False, "That environment is already registered.")
            adopted = self._registry()
            adopted[name] = str(src)
            self._save_registry(adopted)
            meta: dict[str, Any] = {"created": _now(), "project": project, "adopted": True, "origin": "manual",
                                    "history": []}
            parent = src.parent
            if workspace.project_markers(parent) or src.name in workspace.CONVENTIONAL_VENV_NAMES:
                meta["project_dir"] = str(parent)
                meta["project"] = project or parent.name
            self._save_meta(name, meta)
            self._history(name, "adopt", source=str(src))
            self.audit.record("ADOPT_ENV", "success", f"Adopted '{src}' as '{name}'", name=name, source=str(src))
            return OpResult(True, f"Registered '{src}' as '{name}' (left in place).")

    @mutating
    def rebuild_copy(self, source: str, target: str, project: str = "", action: str = "clone") -> OpResult:
        """Create *target* as a fresh environment reproducing *source*'s packages."""
        with self._mutex:
            if source not in self.env_paths():
                return OpResult(False, f"Environment '{source}' does not exist.")
            problem = self._check_new_name(target)
            if problem:
                return OpResult(False, problem)
            info = self.inspect(source, with_size=False)
            ok, lines, err = self._freeze(venv_python(Path(info.path)))
            if not ok:
                return OpResult(False, f"Could not read packages from '{source}': {err}")
            src_meta = self.meta(source)
            created = self.create(target, python=self._python_spec_for(info),
                                  template=src_meta.get("template", ""), project=project or src_meta.get("project", ""),
                                  requirements=lines)
            if not created.ok and not self.exists(target):
                return created
            self._history(target, action, source=source)
            self.audit.record(action.upper() + "_ENV", "success" if created.ok else "partial",
                              f"Rebuilt '{source}' as '{target}' ({len(lines)} packages)", source=source, target=target)
            return OpResult(created.ok, f"'{target}' rebuilt from '{source}' ({len(lines)} pinned packages).\n\n{created.message}")

    def clone(self, source: str, target: str, project: str = "") -> OpResult:
        return self.rebuild_copy(source, target, project, action="clone")

    @mutating
    def rename(self, old: str, new: str) -> OpResult:
        with self._mutex:
            if old not in self.env_paths():
                return OpResult(False, f"Environment '{old}' does not exist.")
            problem = self._check_new_name(new)
            if problem:
                return OpResult(False, problem)
            if not self.is_managed(old):
                adopted = self._registry()
                adopted[new] = adopted.pop(old)
                self._save_registry(adopted)
                self._move_meta(old, new)
                self.audit.record("RENAME_ENV", "success", f"Re-labelled adopted '{old}' as '{new}'", old=old, new=new)
                return OpResult(True, f"Adopted environment re-labelled '{old}' → '{new}' (files untouched).")
            built = self.rebuild_copy(old, new, action="rename")
            if not built.ok:
                return OpResult(False, f"Rename aborted; '{old}' left intact.\n\n{built.message}")
            meta_old = self.meta(old)
            meta_new = self.meta(new)
            meta_new["history"] = (meta_old.get("history", []) + meta_new.get("history", []))[-HISTORY_LIMIT:]
            meta_new["created"] = meta_old.get("created", meta_new.get("created"))
            self._save_meta(new, meta_new)
            self._delete_dir(old)
            (self.paths.meta / f"{old}.json").unlink(missing_ok=True)
            self.audit.record("RENAME_ENV", "success", f"Renamed '{old}' → '{new}' (rebuilt)", old=old, new=new)
            return OpResult(True, f"Renamed '{old}' → '{new}'.\n\n{built.message}")

    def _move_meta(self, old: str, new: str) -> None:
        src = self.paths.meta / f"{old}.json"
        if src.exists():
            os.replace(src, self.paths.meta / f"{new}.json")

    def _delete_dir(self, name: str) -> None:
        target = self.paths.envs / name
        if not is_within(target, self.paths.envs) or not is_venv(target):
            raise PermissionError(f"Refusing to delete '{target}': not a managed environment.")
        self._remove_venv_dir(target)

    def _remove_venv_dir(self, path: Path, kind: str = "") -> None:
        """Retire then purge. Raises EnvInUseError with nothing changed if the env is busy."""
        tomb, token = _retire(path)
        left = _purge_tomb(tomb)
        if left:
            self._remember_trash(tomb, path, kind or ("managed" if is_within(path, self.paths.envs) else "project"),
                                 token)

    def _remember_trash(self, tomb: Path, original: Path, kind: str, token: str) -> None:
        """Record a retired folder for a later purge. The token must match the marker inside the tomb."""
        data = self._registry_data()
        trash = [t for t in data.get("trash", []) if isinstance(t, (str, dict))]
        if not any(isinstance(t, dict) and t.get("path") == str(tomb) for t in trash):
            trash.append({"path": str(tomb), "original": str(original), "kind": kind, "created": _now(),
                          "token": token})
        data["trash"] = trash
        self._write_json(self.paths.registry, data)

    def _remember_preserved(self, tomb: Path, original: Path, name: str) -> None:
        """An ORIGINAL environment kept aside after a blocked rollback. Never purged automatically."""
        data = self._registry_data()
        kept = [k for k in data.get("preserved", []) if isinstance(k, dict)]
        kept.append({"path": str(tomb), "original": str(original), "env": name, "created": _now()})
        data["preserved"] = kept
        self._write_json(self.paths.registry, data)

    def _tomb_refusal(self, entry: Any) -> str:
        """Why a trash entry must NOT be deleted ('' = verified safe). Fail closed on any doubt."""
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) \
                or not isinstance(entry.get("original"), str):
            return "legacy/unstructured record without provenance"
        tomb, orig = Path(entry["path"]), Path(entry["original"])
        if not tomb.is_absolute() or not orig.is_absolute():
            return "relative path"
        if not TOMB_NAME.fullmatch(tomb.name) or tomb.name.split(TRASH_MARK)[0] != f".{orig.name}":
            return "name is not an EnvWarden tomb of the recorded original"
        if os.path.normcase(os.path.abspath(tomb.parent)) != os.path.normcase(os.path.abspath(orig.parent)):
            return "tomb is not beside its recorded original"
        if os.path.islink(tomb):
            return "tomb is a symlink/junction"
        if not tomb.is_dir():
            return ""  # already gone — the record can simply be dropped
        try:
            if tomb.resolve().parent != orig.parent.resolve():
                return "resolved location differs from the recorded parent"
            if len(orig.parent.resolve().parts) < 2:
                return "parent is a drive root"
            names = {e.name.lower() for e in os.scandir(tomb)}
        except OSError as exc:
            return f"cannot inspect: {exc}"
        unexpected = sorted(names - VENV_TOP_LEVEL)
        if unexpected:
            return f"contains non-venv entries: {', '.join(unexpected[:5])}"
        return self._ownership_refusal(entry, tomb)

    @staticmethod
    def _ownership_refusal(entry: dict[str, Any], tomb: Path) -> str:
        """Proof the folder is the one EnvWarden retired: its marker holds the same random token."""
        token = entry.get("token")
        if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
            return "record has no ownership token (made before 4.2.2, or the marker could not be written)"
        marker = tomb / OWNER_MARKER
        try:
            st = os.lstat(marker)
        except OSError:
            return "ownership marker missing"
        if not stat.S_ISREG(st.st_mode) or st.st_size > 4096:
            return "ownership marker is not a small regular file"
        try:
            data = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return "ownership marker unreadable"
        if not isinstance(data, dict) or data.get("format") != 1 or not isinstance(data.get("token"), str):
            return "ownership marker malformed"
        if not secrets.compare_digest(data["token"], token):
            return "ownership token does not match"
        if os.path.normcase(str(data.get("original", ""))) != os.path.normcase(entry["original"]):
            return "ownership marker names a different original"
        return ""

    @mutating
    def purge_trash(self) -> OpResult:
        """Retry deleting retired venv folders that were partly locked last time.

        Only records with verified provenance are deleted; anything doubtful is
        reported and left on disk (an abandoned tomb is better than a wrong delete).
        """
        data = self._registry_data()
        remaining: list[Any] = []
        refused: list[str] = []
        removed = 0
        for entry in data.get("trash", []):
            reason = self._tomb_refusal(entry)
            label = entry.get("path") if isinstance(entry, dict) else str(entry)
            if reason:
                refused.append(f"{label}: {reason}")
                remaining.append(entry)
                self.audit.record("PURGE_TRASH", "refused", reason, path=str(label))
                continue
            tomb = Path(entry["path"])
            if tomb.is_dir() and _purge_tomb(tomb):
                remaining.append(entry)  # still locked; retry next time
            else:
                removed += 1
        data["trash"] = remaining
        self._write_json(self.paths.registry, data)
        locked = len(remaining) - len(refused)
        msg = f"Purged {removed} retired folder(s); {locked} still locked."
        if refused:
            msg += "\nNot deleted (could not verify they are EnvWarden leftovers — remove by hand if sure):\n" \
                   + "\n".join(f"  {r}" for r in refused)
        kept = data.get("preserved", [])
        if kept:
            msg += "\nPreserved original environments awaiting manual recovery:\n" + "\n".join(
                f"  {k.get('env')}: {k.get('path')} (was {k.get('original')})" for k in kept if isinstance(k, dict))
        return OpResult(not refused and not locked, msg, {"remaining": remaining, "refused": refused})

    def _guard_external_venv(self, name: str) -> Path:
        """Deny-first checks before touching a venv that lives outside the managed store."""
        raw = self._registry().get(name)
        if not raw:
            raise PermissionError(f"'{name}' is not a registered external environment.")
        path = Path(raw).resolve()
        if not is_venv(path):
            raise PermissionError(f"Refusing: '{path}' has no pyvenv.cfg — not a virtualenv.")
        if len(path.parts) < 3:
            raise PermissionError(f"Refusing: '{path}' is too close to the drive root.")
        protected = {Path.home().resolve(), self.paths.home}
        protected |= {Path(w).expanduser().resolve() for w in self.workspaces()}
        if path in protected or any(is_within(p, path) for p in protected):
            raise PermissionError(f"Refusing: '{path}' is or contains a protected folder.")
        markers = workspace.project_markers(path)
        if markers or (path / ".git").exists():
            raise PermissionError(f"Refusing: '{path}' looks like a project root ({', '.join(markers) or '.git'}).")
        return path

    @mutating
    def delete(self, name: str, remove_files: bool = False) -> OpResult:
        with self._mutex:
            if name not in self.env_paths():
                return OpResult(False, f"Environment '{name}' does not exist.")
            if not self.is_managed(name) and remove_files:
                try:
                    path = self._guard_external_venv(name)
                except PermissionError as exc:
                    self.audit.record("DELETE_PROJECT_VENV", "denied", str(exc), name=name)
                    return OpResult(False, str(exc))
                try:
                    self._remove_venv_dir(path)
                except EnvInUseError as exc:
                    self.audit.record("DELETE_PROJECT_VENV", "in-use", exc.strerror or str(exc), name=name)
                    return OpResult(False, f"Nothing was deleted. {exc.strerror or exc}")
                adopted = self._registry()
                adopted.pop(name, None)
                self._save_registry(adopted)
                (self.paths.meta / f"{name}.json").unlink(missing_ok=True)
                self.audit.record("DELETE_PROJECT_VENV", "success", str(path), name=name)
                return OpResult(True, f"Deleted venv folder {path} and unregistered '{name}'.")
            if not self.is_managed(name):
                adopted = self._registry()
                adopted.pop(name, None)
                self._save_registry(adopted)
                (self.paths.meta / f"{name}.json").unlink(missing_ok=True)
                self.audit.record("UNREGISTER_ENV", "success", f"Unregistered adopted '{name}'", name=name)
                return OpResult(True, f"'{name}' unregistered. Its files were left where they are.")
            try:
                self._delete_dir(name)
            except EnvInUseError as exc:
                self.audit.record("DELETE_ENV", "in-use", exc.strerror or str(exc), name=name)
                return OpResult(False, f"Nothing was deleted. {exc.strerror or exc}")
            except (OSError, PermissionError) as exc:
                self.audit.record("DELETE_ENV", "failed", str(exc), name=name)
                return OpResult(False, f"Delete failed: {exc}")
            (self.paths.meta / f"{name}.json").unlink(missing_ok=True)
            self.audit.record("DELETE_ENV", "success", f"Deleted '{name}'", name=name)
            return OpResult(True, f"Environment '{name}' deleted.")

    # ------------------------------------------------------------------ packages
    @mutating
    def install(self, name: str, specs: list[str]) -> OpResult:
        with self._mutex:
            py = self._require(name)
            bad = [s for s in specs if not requirement_name(s)]
            if bad or not specs:
                return OpResult(False, "Rejected (deny-first): only plain requirement specifiers are allowed here, "
                                       f"e.g. 'requests' or 'requests>=2.32'. Offending: {', '.join(bad) or '(empty)'}")
            res = run(self.backend.install_argv(py, specs), timeout=1800)
            self._history(name, "install", packages=specs)
            self.audit.record("INSTALL", "success" if res.ok else "failed", " ".join(specs), name=name)
            return OpResult(res.ok, res.output)

    @mutating
    def uninstall(self, name: str, packages: list[str]) -> OpResult:
        with self._mutex:
            py = self._require(name)
            bad = [p for p in packages if not requirement_name(p)]
            if bad or not packages:
                return OpResult(False, f"Rejected: invalid package names {bad}")
            res = run(self.backend.uninstall_argv(py, packages), timeout=900)
            self._history(name, "uninstall", packages=packages)
            self.audit.record("UNINSTALL", "success" if res.ok else "failed", " ".join(packages), name=name)
            return OpResult(res.ok, res.output)

    @mutating
    def install_requirements(self, name: str, req_file: str) -> OpResult:
        with self._mutex:
            py = self._require(name)
            path = Path(req_file).expanduser()
            if not path.is_file():
                return OpResult(False, f"Requirements file not found: {path}")
            res = run(self.backend.install_requirements_argv(py, path), timeout=3600)
            self._history(name, "install_requirements", file=str(path))
            self.audit.record("INSTALL_REQUIREMENTS", "success" if res.ok else "failed", str(path), name=name)
            return OpResult(res.ok, res.output)

    def outdated(self, name: str) -> OpResult:
        py = self._require(name)
        res = run(self.backend.outdated_argv(py), timeout=300)
        if not res.ok:
            return OpResult(False, res.output)
        try:
            rows = json.loads(res.stdout or "[]")
        except ValueError:
            return OpResult(False, f"Unreadable output:\n{res.stdout[:500]}")
        rows = [r for r in rows if isinstance(r, dict)]
        return OpResult(True, f"{len(rows)} outdated package(s) in '{name}'.", rows)

    def check(self, name: str) -> OpResult:
        """Real dependency-conflict check (pip check / uv pip check)."""
        py = self._require(name)
        res = run(self.backend.check_argv(py), timeout=300)
        self.audit.record("DEPENDENCY_CHECK", "clean" if res.ok else "conflicts", "", name=name)
        return OpResult(True, res.output if res.output.strip() else "No broken requirements.", {"clean": res.ok})

    @mutating
    def upgrade_all(self, name: str) -> OpResult:
        with self._mutex:
            py = self._require(name)
            info = self.inspect(name, with_size=False)
            pkgs = sorted(p for p in info.packages if normalize(p) not in BASE_PACKAGES)
            if not pkgs:
                return OpResult(True, "No packages to upgrade.")
            snap = self.snapshot(name, reason="pre-upgrade")
            if not snap.ok:
                self.audit.record("UPGRADE_ALL", "denied", "safety snapshot failed", name=name)
                return OpResult(False, f"Upgrade aborted: the safety snapshot failed, so nothing was changed."
                                       f"\n\n{snap.message}")
            res = run(self.backend.install_argv(py, pkgs, upgrade=True), timeout=3600)
            self._history(name, "upgrade_all", count=len(pkgs))
            self.audit.record("UPGRADE_ALL", "success" if res.ok else "failed", f"{len(pkgs)} packages", name=name,
                              safety_snapshot=(snap.data or {}).get("id", ""))
            note = f"Safety snapshot: {snap.data['id']}\n\n"
            return OpResult(res.ok, note + res.output)

    @mutating
    def wipe(self, name: str) -> OpResult:
        with self._mutex:
            py = self._require(name)
            info = self.inspect(name, with_size=False)
            pkgs = sorted(p for p in info.packages if normalize(p) not in BASE_PACKAGES)
            if not pkgs:
                return OpResult(True, "Environment already contains only base tooling.")
            snap = self.snapshot(name, reason="pre-wipe")
            if not snap.ok:
                return OpResult(False, f"Wipe aborted: safety snapshot failed.\n{snap.message}")
            res = run(self.backend.uninstall_argv(py, pkgs), timeout=1800)
            self._history(name, "wipe", count=len(pkgs))
            self.audit.record("WIPE_ENV", "success" if res.ok else "failed", f"{len(pkgs)} packages", name=name,
                              safety_snapshot=snap.data["id"])
            return OpResult(res.ok, f"Removed {len(pkgs)} packages. Safety snapshot: {snap.data['id']}\n\n{res.output}")

    def export_requirements(self, name: str, output: str) -> OpResult:
        py = self._require(name)
        ok, lines, err = self._freeze(py)
        if not ok:
            return OpResult(False, err)
        out = Path(output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.audit.record("EXPORT_REQUIREMENTS", "success", str(out), name=name, count=len(lines))
        return OpResult(True, f"Wrote {len(lines)} pins to {out}")

    def compare(self, a: str, b: str) -> OpResult:
        ia, ib = self.inspect(a, False), self.inspect(b, False)
        pa = {normalize(k): (k, v) for k, v in ia.packages.items()}
        pb = {normalize(k): (k, v) for k, v in ib.packages.items()}
        only_a = sorted(pa[k][0] for k in pa.keys() - pb.keys())
        only_b = sorted(pb[k][0] for k in pb.keys() - pa.keys())
        diffs = sorted((pa[k][0], pa[k][1], pb[k][1]) for k in pa.keys() & pb.keys() if pa[k][1] != pb[k][1])
        same = len(pa.keys() & pb.keys()) - len(diffs)

        def arrow(va: str, vb: str) -> str:
            return "▲" if version_key(vb) > version_key(va) else "▼"

        lines = [f"{a}  (Python {ia.python_version})   vs   {b}  (Python {ib.python_version})", ""]
        lines.append(f"ONLY IN {a} ({len(only_a)})")
        lines += [f"  + {n}" for n in only_a] or ["  (none)"]
        lines.append(f"\nONLY IN {b} ({len(only_b)})")
        lines += [f"  + {n}" for n in only_b] or ["  (none)"]
        lines.append(f"\nVERSION DIFFERENCES ({len(diffs)})")
        lines += [f"  {n}: {va} → {vb} {arrow(va, vb)}" for n, va, vb in diffs] or ["  (none)"]
        lines.append(f"\nIDENTICAL: {same}")
        return OpResult(True, "\n".join(lines), {"only_a": only_a, "only_b": only_b, "diffs": diffs})

    # ------------------------------------------------------------------ snapshots
    @mutating
    def snapshot(self, name: str, reason: str = "manual") -> OpResult:
        with self._mutex:
            py = self._require(name)
            ok, lines, err = self._freeze(py)
            if not ok:
                self.audit.record("SNAPSHOT", "failed", err[-300:], name=name)
                return OpResult(False, err)
            info = self.inspect(name, with_size=False)
            snap_id = f"{name}@{_stamp()}"
            sdir = self.paths.snapshots / name / snap_id.split("@", 1)[1]
            sdir.mkdir(parents=True, exist_ok=True)
            (sdir / "requirements.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
            self._write_json(sdir / "snapshot.json", {
                "id": snap_id, "env": name, "taken": _now(), "reason": reason,
                "python_version": info.python_version, "base_executable": info.base_executable,
                "package_count": len(lines), "backend": self.backend.kind,
            })
            self._history(name, "snapshot", id=snap_id, reason=reason)
            self.audit.record("SNAPSHOT", "success", snap_id, name=name, reason=reason, packages=len(lines))
            return OpResult(True, f"Snapshot {snap_id} ({len(lines)} packages).", {"id": snap_id, "dir": str(sdir)})

    def _snapshot_dir(self, snap_id: str) -> Path | None:
        if "@" not in snap_id:
            return None
        env, stamp = snap_id.split("@", 1)
        d = self.paths.snapshots / env / stamp
        return d if is_within(d, self.paths.snapshots) and d.is_dir() else None

    def list_snapshots(self, env: str = "") -> list[dict[str, Any]]:
        out = []
        for meta_file in self.paths.snapshots.glob("*/*/snapshot.json"):
            m = self._read_json(meta_file, {})
            if m and (not env or m.get("env") == env):
                out.append(m)
        return sorted(out, key=lambda m: m.get("taken", ""), reverse=True)

    def snapshot_requirements(self, snap_id: str) -> str:
        d = self._snapshot_dir(snap_id)
        return (d / "requirements.txt").read_text(encoding="utf-8") if d else ""

    @mutating
    def restore_snapshot(self, snap_id: str, target: str, project: str = "") -> OpResult:
        d = self._snapshot_dir(snap_id)
        if not d:
            return OpResult(False, f"Snapshot '{snap_id}' not found.")
        m = self._read_json(d / "snapshot.json", {})
        lines = [ln for ln in (d / "requirements.txt").read_text(encoding="utf-8").splitlines() if ln.strip()]
        python = m.get("base_executable") if m.get("base_executable") and Path(m["base_executable"]).exists() else m.get("python_version", "")
        res = self.create(target, python=python, project=project or f"restored:{m.get('env', '')}", requirements=lines)
        if self.exists(target):
            self._history(target, "restore", snapshot=snap_id)
        self.audit.record("RESTORE_SNAPSHOT", "success" if res.ok else "partial", snap_id, target=target)
        return OpResult(res.ok, f"Restored {snap_id} → '{target}'.\n\n{res.message}")

    @mutating
    def delete_snapshot(self, snap_id: str) -> OpResult:
        d = self._snapshot_dir(snap_id)
        if not d:
            return OpResult(False, f"Snapshot '{snap_id}' not found.")
        shutil.rmtree(d)
        self.audit.record("DELETE_SNAPSHOT", "success", snap_id)
        return OpResult(True, f"Deleted snapshot {snap_id}.")

    # ------------------------------------------------------------------ templates
    def template_path(self, name: str) -> Path | None:
        if not valid_name(name):
            return None
        p = self.paths.templates / f"{name}.txt"
        return p if is_within(p, self.paths.templates) else None

    def list_templates(self) -> list[tuple[str, int]]:
        out = []
        for f in sorted(self.paths.templates.glob("*.txt")):
            lines = [ln for ln in f.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip() and not ln.startswith("#")]
            out.append((f.stem, len(lines)))
        return out

    @mutating
    def save_template(self, env: str, template: str, unpinned: bool = False) -> OpResult:
        path = self.template_path(template)
        if path is None:
            return OpResult(False, "Invalid template name.")
        ok, lines, err = self._freeze(self._require(env))
        if not ok:
            return OpResult(False, err)
        if unpinned:
            lines = sorted({requirement_name(ln) or ln for ln in lines}, key=str.lower)
        path.write_text(f"# EnvWarden template from '{env}' — {_now()}\n" + "\n".join(lines) + "\n", encoding="utf-8")
        self.audit.record("SAVE_TEMPLATE", "success", template, env=env, unpinned=unpinned)
        return OpResult(True, f"Template '{template}' saved ({len(lines)} entries).")

    @mutating
    def delete_template(self, template: str) -> OpResult:
        path = self.template_path(template)
        if path is None or not path.exists():
            return OpResult(False, f"Template '{template}' not found.")
        path.unlink()
        self.audit.record("DELETE_TEMPLATE", "success", template)
        return OpResult(True, f"Template '{template}' deleted.")

    # ------------------------------------------------------------------ scanning / security
    def scan(self, name: str, project_dir: str) -> OpResult:
        py = self._require(name)
        root = Path(project_dir).expanduser()
        if not root.is_dir():
            return OpResult(False, f"Not a directory: {root}")
        try:
            ctx = probe.scan_context(py)
        except probe.ProbeError as exc:
            return OpResult(False, f"Could not introspect '{name}': {exc}")
        report = scanner.scan_project(root, ctx)
        out = self.paths.scans / f"{name}-{_stamp()}.requirements.txt"
        out.write_text("\n".join(report.requirements_lines()) + "\n", encoding="utf-8")
        self.audit.record("SCAN_PROJECT", "success", report.project_root, name=name,
                          imports=len(report.findings), missing=len(report.missing))
        return OpResult(True, report.summary() + f"\nRequirements draft: {out}", {"report": report, "requirements_file": str(out)})

    def security_audit(self, name: str) -> OpResult:
        info = self.inspect(name, with_size=False)
        if not info.packages:
            return OpResult(False, "No packages found (environment could not be inspected).")
        report = security.audit(info.packages)
        status = "error" if report.errors and not report.findings else ("vulnerable" if report.findings else "clean")
        self.audit.record("SECURITY_AUDIT", status, f"{len(report.findings)} findings", name=name,
                          queried=report.queried, packages=report.vulnerable_packages)
        if report.errors and not report.findings:
            return OpResult(False, "OSV query failed: " + "; ".join(report.errors[:3]), report)
        return OpResult(True, f"{len(report.findings)} known vulnerabilit{'y' if len(report.findings) == 1 else 'ies'} "
                              f"across {len(report.vulnerable_packages)} of {report.queried} packages.", report)

    # ------------------------------------------------------------------ temp envs
    @mutating
    def create_temp(self, project_dir: str = "") -> OpResult:
        target = self.paths.temp / f"tmp-{_stamp()}"
        try:
            argv = self.backend.venv_argv(target)
        except LookupError as exc:
            return OpResult(False, str(exc))
        res = run(argv, timeout=1800)
        if not res.ok:
            return OpResult(False, res.output)
        msg = [f"Temporary environment: {target}"]
        ok = True
        if project_dir:
            try:
                report = scanner.scan_project(Path(project_dir), probe.scan_context(venv_python(target)))
            except (probe.ProbeError, OSError) as exc:
                return OpResult(False, f"Temp env created at {target}, but the scan failed: {exc}", {"path": str(target)})
            lines = report.requirements_lines()
            if lines:
                ok, out = self._install_lines(venv_python(target), lines)
                msg.append(out)
            msg.append(report.summary())
        self.audit.record("CREATE_TEMP_ENV", "success" if ok else "partial", str(target), project_dir=project_dir)
        return OpResult(ok, "\n\n".join(msg), {"path": str(target)})

    @mutating
    def purge_temp(self) -> OpResult:
        removed, locked = 0, []
        for d in self.paths.temp.iterdir():
            if d.is_dir() and is_within(d, self.paths.temp):
                if _force_rmtree(d):
                    locked.append(d.name)
                else:
                    removed += 1
            elif d.is_file():
                d.unlink(missing_ok=True)
        self.audit.record("PURGE_TEMP", "success" if not locked else "partial", f"{removed} removed", locked=locked)
        msg = f"Removed {removed} temporary environment(s)."
        if locked:
            msg += f" {len(locked)} still in use: {', '.join(locked)}"
        return OpResult(not locked, msg)

    # ------------------------------------------------------------------ activation
    def activation_command(self, name: str) -> str:
        bindir = venv_bin(self.env_paths()[name])
        if os.name == "nt":
            return f'"{bindir / "Activate.ps1"}"' if (bindir / "Activate.ps1").exists() else f'"{bindir / "activate.bat"}"'
        return f'source "{bindir / "activate"}"'

    def open_shell(self, name: str) -> OpResult:
        env_dir = self.env_paths()[name]
        bindir = venv_bin(env_dir)
        cwd = self.meta(name).get("project_dir") or str(env_dir)
        try:
            if os.name == "nt":
                act = bindir / "activate.bat"
                wt = shutil.which("wt")
                argv = ([wt, "-d", cwd, "cmd.exe", "/k", str(act)] if wt else ["cmd.exe", "/k", str(act)])
                subprocess.Popen(argv, cwd=cwd, creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
            else:
                term = os.environ.get("TERMINAL") or shutil.which("x-terminal-emulator") or shutil.which("gnome-terminal")
                if not term:
                    return OpResult(False, f"No terminal emulator found. Run:\n  {self.activation_command(name)}")
                sep = ["--"] if term.endswith("gnome-terminal") else ["-e"]
                subprocess.Popen([term, *sep, "bash", "--rcfile", str(bindir / "activate"), "-i"], cwd=cwd)
        except OSError as exc:
            return OpResult(False, f"Could not open a shell: {exc}")
        self._history(name, "shell")
        self.audit.record("OPEN_SHELL", "success", "", name=name)
        return OpResult(True, f"Opened an activated shell for '{name}'.")

    @mutating
    def set_project(self, name: str, project: str, project_dir: str = "") -> OpResult:
        meta = self.meta(name)
        meta["project"] = project
        if project_dir:
            meta["project_dir"] = project_dir
        self._save_meta(name, meta)
        return OpResult(True, f"Saved labels for '{name}'.")

    # ------------------------------------------------------------------ workspaces & projects
    def workspaces(self) -> list[str]:
        ws = self._settings().get("workspaces", [])
        return [w for w in ws if isinstance(w, str)] if isinstance(ws, list) else []

    @mutating
    def add_workspace(self, folder: str) -> OpResult:
        path = Path(folder).expanduser()
        if not path.is_dir():
            return OpResult(False, f"Not a folder: {path}")
        resolved = path.resolve()
        if len(resolved.parts) < 2 or resolved == Path(resolved.anchor):
            return OpResult(False, "Pick a projects folder (e.g. C:\\dev), not a whole drive.")
        settings = self._settings()
        current = [w for w in settings.get("workspaces", []) if isinstance(w, str)]
        if any(os.path.normcase(str(Path(w).resolve())) == os.path.normcase(str(resolved)) for w in current):
            return OpResult(True, f"{resolved} is already a workspace.")
        settings["workspaces"] = current + [str(resolved)]
        self._save_settings(settings)
        self.audit.record("ADD_WORKSPACE", "success", str(resolved))
        return OpResult(True, f"Added workspace {resolved}.")

    @mutating
    def remove_workspace(self, folder: str) -> OpResult:
        settings = self._settings()
        key = os.path.normcase(str(Path(folder).expanduser()))
        keep = [w for w in settings.get("workspaces", []) if os.path.normcase(str(Path(w))) != key]
        settings["workspaces"] = keep
        self._save_settings(settings)
        self.audit.record("REMOVE_WORKSPACE", "success", folder)
        return OpResult(True, f"Removed workspace {folder}. Registered environments are kept.")

    def _register_found(self, venv: Path, project_dir: str, origin: str) -> str:
        name = self._unique_name(workspace.suggest_env_name(venv, project_dir))
        adopted = self._registry()
        adopted[name] = str(venv)
        self._save_registry(adopted)
        meta = {"created": _now(), "origin": origin, "adopted": True,
                "project": Path(project_dir).name if project_dir else "", "history": []}
        if project_dir:
            meta["project_dir"] = project_dir
        self._save_meta(name, meta)
        self._history(name, "discovered" if origin == "workspace" else origin, path=str(venv))
        return name

    @mutating
    def discover(self, max_depth: int | None = None) -> OpResult:
        """Walk the workspaces, register new venvs in place, prune vanished workspace entries."""
        with self._mutex:
            roots = self.workspaces()
            if not roots:
                return OpResult(False, "No workspace folders yet. Add one (e.g. C:\\dev) first.")
            depth = int(max_depth or self._settings().get("scan_depth", workspace.DEFAULT_DEPTH))
            result = workspace.discover(roots, depth, set(self._settings().get("workspace_exclude", [])))
            known = self._registered_by_path()
            home_key = os.path.normcase(str(self.paths.home))
            added: list[str] = []
            for v in result.venvs:
                key = os.path.normcase(str(Path(v.path).resolve()))
                if key in known or key.startswith(home_key):
                    # backfill the project link for envs adopted before workspaces existed
                    name = known.get(key)
                    if name and v.project_dir and not self.meta(name).get("project_dir"):
                        m = self.meta(name)
                        m["project_dir"] = v.project_dir
                        m.setdefault("project", Path(v.project_dir).name)
                        self._save_meta(name, m)
                    continue
                name = self._register_found(Path(v.path), v.project_dir, "workspace")
                known[key] = name
                added.append(name)
            pruned: list[str] = []
            adopted = self._registry()
            for name, p in list(adopted.items()):
                if self.meta(name).get("origin") == "workspace" and not is_venv(Path(p)):
                    adopted.pop(name)
                    (self.paths.meta / f"{name}.json").unlink(missing_ok=True)
                    pruned.append(name)
            if pruned:
                self._save_registry(adopted)
            by_path = self._registered_by_path()
            projects = []
            for proj in result.projects:
                projects.append({
                    "name": proj.name, "path": proj.path, "markers": proj.markers, "status": proj.status,
                    "venvs": [{"path": vp, "env": by_path.get(os.path.normcase(str(Path(vp).resolve())), "")}
                              for vp in proj.venvs],
                })
            snapshot = {"scanned": _now(), "roots": result.roots, "projects": projects,
                        "loose_venvs": [v.path for v in result.venvs if not v.project_dir],
                        "dirs_visited": result.dirs_visited, "truncated": result.truncated, "errors": result.errors}
            self._write_json(self.paths.home / "projects.json", snapshot)
            self.audit.record("DISCOVER", "success", f"{len(result.projects)} projects, {len(result.venvs)} venvs",
                              added=added, pruned=pruned, roots=result.roots)
            without = sum(1 for p in projects if p["status"] == "no-venv")
            msg = (f"Scanned {result.dirs_visited} folders: {len(result.projects)} projects, {len(result.venvs)} venvs "
                   f"({without} project(s) without a venv). Registered {len(added)} new, pruned {len(pruned)}.")
            if result.truncated:
                msg += f"\nStopped after {workspace.MAX_DIRS} folders — choose a narrower workspace."
            if result.errors:
                msg += "\n" + "\n".join(result.errors[:5])
            return OpResult(True, msg, {"added": added, "pruned": pruned, "snapshot": snapshot})

    def projects(self) -> dict[str, Any]:
        """Last discovery snapshot (projects with/without venvs)."""
        return self._read_json(self.paths.home / "projects.json", {"projects": [], "roots": []})

    def env_for_project(self, project_dir: str) -> str:
        key = os.path.normcase(str(Path(project_dir).resolve()))
        for name in self.env_paths():
            pdir = self.meta(name).get("project_dir")
            if pdir and os.path.normcase(str(Path(pdir).resolve())) == key:
                return name
        return ""

    @mutating
    def create_in_project(self, project_dir: str, python: str = "", venv_dirname: str = ".venv",
                          name: str = "", sync: bool = False, trust: bool = False) -> OpResult:
        """Create <project>/.venv — but never when the project already has a venv."""
        with self._mutex:
            proj = Path(project_dir).expanduser()
            if not proj.is_dir():
                return OpResult(False, f"Project folder not found: {proj}")
            proj = proj.resolve()
            if not re.fullmatch(r"\.?[A-Za-z0-9_-]{1,40}", venv_dirname):
                return OpResult(False, "Venv folder name must be simple, e.g. .venv")
            existing = workspace.venvs_in_project(proj)
            if existing:
                known = self._registered_by_path()
                names = []
                for v in existing:
                    key = os.path.normcase(str(v.resolve()))
                    names.append(known.get(key) or self._register_found(v, str(proj), "project"))
                return OpResult(False, "This project already has a virtualenv — nothing was created:\n"
                                + "\n".join(f"  {v}  → registered as '{n}'" for v, n in zip(existing, names, strict=True)),
                                {"existing": names})
            target = proj / venv_dirname
            if target.exists():
                return OpResult(False, f"'{target}' exists but is not a virtualenv; refusing to overwrite it.")
            env_name = name.strip() or workspace.suggest_env_name(target, str(proj))
            if name.strip():
                problem = self._check_new_name(env_name)
                if problem:
                    return OpResult(False, problem)
            else:
                env_name = self._unique_name(env_name)
            try:
                argv = self.backend.venv_argv(target, python)
            except LookupError as exc:
                return OpResult(False, str(exc))
            res = run(argv, timeout=1800)
            if not res.ok:
                self.audit.record("CREATE_PROJECT_VENV", "failed", res.output[-400:], project=str(proj))
                return OpResult(False, res.output)
            adopted = self._registry()
            adopted[env_name] = str(target)
            self._save_registry(adopted)
            self._save_meta(env_name, {"created": _now(), "origin": "project", "adopted": True,
                                       "project": proj.name, "project_dir": str(proj),
                                       "python_request": python or "default", "backend": self.backend.kind,
                                       "history": []})
            self._history(env_name, "create_in_project", path=str(target))
            self.audit.record("CREATE_PROJECT_VENV", "success", str(target), name=env_name, python=python or "default")
            msg = f"Created {target} (registered as '{env_name}')."
            ok = True
            if sync:
                sres = self.sync_project(env_name, trust=trust)
                ok = sres.ok
                msg += "\n\n" + sres.message
            return OpResult(ok, msg, {"name": env_name, "path": str(target)})

    def sync_plan(self, name: str) -> SyncPlan:
        """Decide how 'sync project dependencies' would run, without running anything.

        Lock files win: uv.lock (``uv sync --frozen`` into THIS venv) or pylock.toml
        (``uv pip sync``). Both are exact — packages not in the lock are removed.
        Poetry/Pipenv locks are left to their tools. A Python that doesn't satisfy
        requires-python is refused, because uv sync would silently delete and
        rebuild the venv on another interpreter.
        """
        pdir = self.meta(name).get("project_dir")
        if not pdir or not Path(pdir).is_dir():
            return SyncPlan(blocked="This environment is not linked to a project folder.")
        proj = Path(pdir)
        py = self._require(name)
        env_dir = self.env_paths()[name]
        warnings: list[str] = []
        for src in lockfiles.detect_sources(proj):
            if src.foreign_tool:
                return SyncPlan(source=src.kind, blocked=f"{src.kind} found — this project is managed by "
                                f"{src.foreign_tool}. EnvWarden won't fight its lock; use that tool.")
            if src.kind in ("uv.lock", "pylock.toml"):
                if self.backend.kind != "uv":
                    warnings.append(f"{src.kind} ignored: uv is not installed (install uv to sync exactly from the lock)")
                    continue
                conflict = lockfiles.requires_python_conflict(proj, self.inspect(name, with_size=False).python_version)
                if conflict:
                    return SyncPlan(source=src.kind, blocked=f"Refused: {conflict}. An exact sync would delete and "
                                    "rebuild the venv on another Python. Use RECREATE with a matching Python first.")
                if src.kind == "uv.lock":
                    stale = lockfiles.uv_lock_staleness(Path(src.path), proj / "pyproject.toml")
                    if stale:
                        warnings.append(stale)
                    return SyncPlan([str(self.backend.uv_path), "sync", "--frozen", "--project", str(proj)],
                                    {"UV_PROJECT_ENVIRONMENT": str(env_dir)}, src.kind,
                                    f"Exact sync from {src.path} (uv sync --frozen)", True, warnings=warnings)
                return SyncPlan(self.backend.pip_argv(py, "sync", src.path), {}, src.kind,
                                f"Exact sync from {src.path} (uv pip sync)", True, warnings=warnings)
            if src.kind == "requirements.txt":
                return SyncPlan(self.backend.install_requirements_argv(py, Path(src.path)), {}, src.kind,
                                f"Install {src.path}", warnings=warnings)
            if src.kind == "pyproject.toml":
                return SyncPlan(self.backend.pip_argv(py, "install", "-e", str(proj)), {}, src.kind,
                                f"Editable install of {proj} (pyproject.toml)", warnings=warnings)
        if (proj / "setup.py").is_file():
            return SyncPlan(self.backend.pip_argv(py, "install", "-e", str(proj)), {}, "setup.py",
                            f"Editable install of {proj} (setup.py)", warnings=warnings)
        return SyncPlan(blocked="\n".join(warnings + ["No lock file, requirements.txt or pyproject.toml "
                                                       "dependencies in the project."]))

    def plan_sync(self, name: str) -> tuple[list[str], str]:
        plan = self.sync_plan(name)
        return plan.argv, plan.blocked or plan.summary()

    def _trust_key(self, project_dir: str) -> str:
        return os.path.normcase(str(Path(project_dir).resolve()))

    def is_trusted(self, project_dir: str) -> bool:
        return self._trust_key(project_dir) in set(self._settings().get("trusted_projects", []))

    def _trust(self, project_dir: str) -> None:
        settings = self._settings()
        trusted = [t for t in settings.get("trusted_projects", []) if isinstance(t, str)]
        key = self._trust_key(project_dir)
        if key not in trusted:
            settings["trusted_projects"] = trusted + [key]
            self._save_settings(settings)
            self.audit.record("TRUST_PROJECT", "granted", key)

    @mutating
    def sync_project(self, name: str, trust: bool = False) -> OpResult:
        """Sync a project venv. The first sync of a project needs ``trust=True`` (see TRUST_WARNING)."""
        with self._mutex:
            plan = self.sync_plan(name)
            if plan.blocked:
                self.audit.record("SYNC_PROJECT", "denied", plan.blocked[:300], name=name)
                return OpResult(False, plan.blocked)
            project_dir = self.meta(name)["project_dir"]
            if not self.is_trusted(project_dir):
                if not trust:
                    self.audit.record("SYNC_PROJECT", "needs-trust", project_dir, name=name)
                    return OpResult(False, TRUST_WARNING.format(project=project_dir),
                                    {"needs_trust": True, "project": project_dir})
                self._trust(project_dir)
            snap_note = ""
            if plan.exact:  # an exact sync can remove packages: no way back = no sync
                snap = self.snapshot(name, reason="pre-sync")
                if not snap.ok:
                    self.audit.record("SYNC_PROJECT", "denied", "safety snapshot failed", name=name)
                    return OpResult(False, f"Exact sync aborted: the safety snapshot failed, so nothing was "
                                           f"changed.\n\n{snap.message}")
                snap_note = f"Safety snapshot: {snap.data['id']}\n"
            res = run(plan.argv, timeout=3600, cwd=Path(self.meta(name)["project_dir"]), extra_env=plan.env)
            self._history(name, "sync_project", source=plan.source, exact=plan.exact)
            self.audit.record("SYNC_PROJECT", "success" if res.ok else "failed", plan.description, name=name,
                              source=plan.source, exact=plan.exact)
            return OpResult(res.ok, f"{plan.summary()}\n{snap_note}\n{res.output}")

    def drift(self, name: str, info: EnvInfo | None = None) -> lockfiles.Drift | None:
        """Declared/locked vs installed for a project-linked env (None when not linked)."""
        info = info or self.inspect(name, with_size=False)
        pdir = info.meta.get("project_dir")
        if not pdir or not Path(pdir).is_dir():
            return None
        if info.health == "bad":
            d = lockfiles.Drift(lockfiles.primary_source(Path(pdir)))
            d.notes.append("environment interpreter is not working — cannot compare")
            return d
        return lockfiles.compute_drift(Path(pdir), info.packages, info.markers)

    def drift_all(self, infos: list[EnvInfo]) -> dict[str, lockfiles.Drift]:
        out: dict[str, lockfiles.Drift] = {}
        for info in infos:
            try:
                d = self.drift(info.name, info)
            except Exception as exc:  # never let one odd project break the view
                d = lockfiles.Drift(None)
                d.notes.append(f"drift check failed: {exc}")
            if d is not None:
                out[info.name] = d
        return out

    @mutating
    def recreate(self, name: str, python: str = "") -> OpResult:
        """Rebuild an environment *at its own path* with the same (or a chosen) Python and pins.

        ``python`` switches interpreter (e.g. '3.12' to satisfy requires-python, or to
        move off an end-of-life version); empty keeps the current one.

        Fixes moved/copied venvs and venvs whose base interpreter was upgraded or
        removed. Package list comes from the live env, else the newest snapshot.
        """
        with self._mutex:
            if name not in self.env_paths():
                return OpResult(False, f"Environment '{name}' does not exist.")
            path = self.env_paths()[name]
            try:
                if self.is_managed(name):
                    guarded = path.resolve()
                else:
                    guarded = self._guard_external_venv(name)
            except PermissionError as exc:
                return OpResult(False, str(exc))
            info = self.inspect(name, with_size=False)
            source = "live environment"
            ok, lines, _err = self._freeze(venv_python(guarded)) if info.health != "bad" else (False, [], "")
            snap_id = ""
            if ok:
                snap = self.snapshot(name, reason="pre-recreate")
                if not snap.ok:
                    self.audit.record("RECREATE_ENV", "denied", "safety snapshot failed", name=name)
                    return OpResult(False, f"Recreate aborted: the safety snapshot failed, so nothing was "
                                           f"changed.\n\n{snap.message}")
                snap_id = snap.data["id"]
            else:
                snaps = self.list_snapshots(name)
                if snaps:
                    snap_id = snaps[0]["id"]
                    lines = [ln for ln in self.snapshot_requirements(snap_id).splitlines() if ln.strip()]
                    source = f"snapshot {snap_id}"
                else:
                    lines, source = [], "nothing (no working interpreter and no snapshot)"
            override = python.strip()
            python = override or self._python_spec_for(info)
            if not python:
                python = workspace.venv_python_version(guarded)
            if python and not override and not Path(python).exists() and self.backend.kind == "uv":
                python = ".".join(python.split(".")[:2])  # let uv pick/download the matching minor
            try:
                tomb, token = _retire(guarded)  # old env kept intact until the new one is proven
            except EnvInUseError as exc:
                self.audit.record("RECREATE_ENV", "in-use", exc.strerror or str(exc), name=name)
                return OpResult(False, f"Nothing was changed. {exc.strerror or exc}")

            def rollback(reason: str) -> OpResult:
                left = _force_rmtree(guarded)
                if left:
                    # new folder can't be cleared — keep the ORIGINAL safe beside it (never auto-purged);
                    # drop its ownership marker so no trash record can ever match it
                    _drop_marker(tomb)
                    self._remember_preserved(tomb, guarded, name)
                    self.audit.record("RECREATE_ENV", "failed", reason[-300:], name=name, rollback="blocked")
                    return OpResult(False, f"Recreate failed and the new folder could not be removed; the original "
                                           f"environment is preserved at {tomb}.\n\n{reason}")
                os.rename(tomb, guarded)
                _drop_marker(guarded)  # restored env must not carry a tomb marker
                self.audit.record("RECREATE_ENV", "rolled-back", reason[-300:], name=name)
                return OpResult(False, f"Recreate failed — the original environment was restored unchanged.\n\n{reason}")

            try:
                argv = self.backend.venv_argv(guarded, python)
            except LookupError:
                argv = self.backend.venv_argv(guarded, "")
            res = run(argv, timeout=1800)
            if not res.ok or not venv_python(guarded).exists():
                return rollback(res.output)
            msg = [f"Recreated {guarded} with Python {python or 'default'}; packages from {source}."]
            okp = True
            if lines:
                okp, out = self._install_lines(venv_python(guarded), lines)
                msg.append(out)
                if not okp and info.health != "bad":
                    return rollback(out)  # old env worked: don't swap it for a half-installed one
            if _purge_tomb(tomb):
                self._remember_trash(tomb, guarded, "recreate", token)
            self._history(name, "recreate", source=source, python=python or "default")
            self.audit.record("RECREATE_ENV", "success" if okp else "partial", str(guarded), name=name,
                              snapshot=snap_id, packages=len(lines))
            return OpResult(okp, "\n\n".join(msg))

    @mutating
    def startup_maintenance(self, discover: bool = True) -> OpResult:
        """Retry purging retired folders, then rescan workspaces (if any)."""
        msgs = []
        if self._registry_data().get("trash") or self._registry_data().get("preserved"):
            msgs.append(self.purge_trash().message)
        data: dict[str, Any] = {}
        if discover and self.workspaces():
            res = self.discover()
            msgs.append(res.message)
            data = res.data or {}
        return OpResult(True, "\n".join(msgs) or "Nothing to do.", data)
