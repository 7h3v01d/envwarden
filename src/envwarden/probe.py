# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Introspect an environment with ONE isolated subprocess of its own interpreter.

Replaces the old "python --version" + "pip list" + health-check triple: it is
faster, works in pip-less (uv-made) environments, and the answers come from
the environment itself rather than from a global pip.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .procs import run

INFO_PROBE = r"""
import json, os, platform, sys, importlib.util
def _fv(i):
    v = "%d.%d.%d" % (i.major, i.minor, i.micro)
    return v if i.releaselevel == "final" else v + i.releaselevel[0] + str(i.serial)
markers = {
    "implementation_name": sys.implementation.name,
    "implementation_version": _fv(sys.implementation.version),
    "os_name": os.name, "platform_machine": platform.machine(), "platform_release": platform.release(),
    "platform_system": platform.system(), "platform_version": platform.version(),
    "python_full_version": platform.python_version(), "platform_python_implementation": platform.python_implementation(),
    "python_version": ".".join(platform.python_version_tuple()[:2]), "sys_platform": sys.platform,
}
try:
    import importlib.metadata as md
except Exception:
    md = None
seen = {}
if md is not None:
    for d in md.distributions():
        try:
            n = d.metadata['Name']
        except Exception:
            n = None
        if n and n.lower() not in seen:
            seen[n.lower()] = [n, d.version]
print(json.dumps({
    "version": sys.version.split()[0],
    "implementation": sys.implementation.name,
    "executable": sys.executable,
    "base_executable": getattr(sys, "_base_executable", ""),
    "prefix": sys.prefix,
    "base_prefix": sys.base_prefix,
    "has_pip": importlib.util.find_spec("pip") is not None,
    "markers": markers,
    "packages": sorted(seen.values(), key=lambda t: t[0].lower()),
}))
"""

SCAN_PROBE = r"""
import json, sys
import importlib.metadata as md
try:
    pd = md.packages_distributions()
except Exception:
    pd = {}
print(json.dumps({
    "stdlib": sorted(getattr(sys, "stdlib_module_names", ())),
    "builtins": sorted(sys.builtin_module_names),
    "packages_distributions": {k: list(v) for k, v in pd.items()},
    "installed": {d.metadata['Name']: d.version for d in md.distributions() if d.metadata['Name']},
}))
"""


class ProbeError(RuntimeError):
    pass


def _probe(python: Path, code: str, timeout: float) -> dict[str, Any]:
    if not python.exists():
        raise ProbeError(f"Interpreter missing: {python}")
    res = run([str(python), "-I", "-c", code], timeout=timeout)
    if not res.ok:
        raise ProbeError(res.output.splitlines()[-1] if res.output else "probe failed")
    try:
        return json.loads(res.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise ProbeError(f"Unreadable probe output: {exc}") from exc


def info(python: Path, timeout: float = 60) -> dict[str, Any]:
    return _probe(python, INFO_PROBE, timeout)


def scan_context(python: Path, timeout: float = 120) -> dict[str, Any]:
    return _probe(python, SCAN_PROBE, timeout)


def read_pyvenv_cfg(env_dir: Path) -> dict[str, str]:
    cfg: dict[str, str] = {}
    try:
        for line in (env_dir / "pyvenv.cfg").read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                cfg[k.strip().lower()] = v.strip()
    except OSError:
        pass
    return cfg


_PY_IN_LAUNCHER = re.compile(
    rb"((?:[A-Za-z]:\\|\\\\|/)[^\x00\r\n\"'<>|*?]{0,400}?[\\/](?:Scripts|bin)[\\/]python[0-9.]*(?:w)?(?:\.exe)?)",
    re.IGNORECASE,
)


def _norm(p: str) -> str:
    return os.path.normcase(os.path.normpath(p))


def _launcher_targets(bindir: Path) -> list[str]:
    """Interpreter paths embedded in pip's launcher (script shebang or Windows .exe trampoline)."""
    for name in ("pip.exe", "pip3.exe", "pip", "pip3"):
        f = bindir / name
        if f.is_file() and not f.is_symlink():
            try:
                with open(f, "rb") as fh:
                    blob = fh.read(4 * 1024 * 1024)
            except OSError:
                return []
            return [m.decode("utf-8", "replace") for m in _PY_IN_LAUNCHER.findall(blob)]
    return []


def relocation_problem(env_dir: Path) -> str:
    """Detect a venv that was moved/copied on disk (launchers still point elsewhere).

    Venvs embed absolute paths in activate scripts and entry-point launchers
    (pip.exe etc.). When those point at another directory, running them acts
    on a *different* environment — the failure the old copy-based clone made.
    """
    from .paths import venv_bin

    here = _norm(str(env_dir.resolve()))
    bindir = venv_bin(env_dir)

    for target in _launcher_targets(bindir):
        try:
            owner = _norm(str(Path(target).parent.parent.resolve()))
        except OSError:
            owner = _norm(str(Path(target).parent.parent))
        if owner != here:
            return f"pip launcher runs '{target}' (environment was moved or copied on disk)"

    cfg = read_pyvenv_cfg(env_dir)
    if cfg.get("relocatable", "").lower() == "true":
        return ""
    script = bindir / ("activate.bat" if (bindir / "activate.bat").exists() else "activate")
    try:
        text = script.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    m = re.search(r'VIRTUAL_ENV\s*=\s*["\']?([^"\'\r\n]+)', text)
    if not m:
        return ""
    recorded = m.group(1).strip().rstrip("\\/")
    if "$(" in recorded or "%~" in recorded or "%%~" in recorded:  # relative/templated forms
        return ""
    if _norm(recorded) != here:
        return f"Scripts point at '{recorded}' (environment was moved or copied on disk)"
    return ""
