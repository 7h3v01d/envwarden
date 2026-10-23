# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Delete / recreate safety (S1–S5), plus Windows-only and live-network checks.

Lock emulation only ever targets files these tests create — never anything
outside tmp_path.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from envwarden import core
from envwarden.backend import Backend
from envwarden.core import EnvManager, _force_rmtree
from envwarden.paths import venv_python

WINDOWS = os.name == "nt"


def _emulate_windows_lock(monkeypatch, locked_root: Path) -> None:
    """Windows semantics for an env that is in use: its folder can't be renamed and
    the in-use files can't be unlinked."""
    root = os.path.normcase(str(locked_root.resolve()))
    real_rename, real_unlink = os.rename, os.unlink

    def is_locked(p) -> bool:
        return os.path.normcase(os.path.abspath(os.fsdecode(p))).startswith(root)

    def rename(src, dst, *a, **k):
        if is_locked(src):
            raise PermissionError(13, "The process cannot access the file because it is being used", os.fsdecode(src))
        return real_rename(src, dst, *a, **k)

    def unlink(p, *a, dir_fd=None, **k):
        full = os.fsdecode(p) if dir_fd is None else os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}")
                                                                  if os.path.exists("/proc/self/fd") else "",
                                                                  os.fsdecode(p))
        if is_locked(full) and Path(full).name.startswith("python"):
            raise PermissionError(13, "in use", full)
        return real_unlink(p, *a, dir_fd=dir_fd, **k)

    monkeypatch.setattr(os, "rename", rename)
    monkeypatch.setattr(os, "unlink", unlink)


# S1 — force-delete must never change files OUTSIDE the tree (symlink / hard-link targets)
@pytest.mark.skipif(WINDOWS, reason="POSIX symlink/hardlink semantics; Windows covered by S1b")
def test_s1_force_rmtree_never_chmods_through_links(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "system_python"
    target.write_text("#!/bin/sh\n", encoding="utf-8")
    target.chmod(0o755)
    shared = outside / "uv_cache_file.py"
    shared.write_text("x = 1\n", encoding="utf-8")
    shared.chmod(0o644)

    tree = tmp_path / "venv"
    (tree / "bin").mkdir(parents=True)
    os.symlink(target, tree / "bin" / "python")
    os.link(shared, tree / "bin" / "hardlinked.py")

    real_unlink = os.unlink
    victims = {"python", "hardlinked.py"}

    def failing_unlink(p, *a, **k):
        if Path(os.fsdecode(p)).name in victims:
            raise PermissionError(13, "denied", os.fsdecode(p))
        return real_unlink(p, *a, **k)

    monkeypatch.setattr(os, "unlink", failing_unlink)
    left = _force_rmtree(tree)
    monkeypatch.undo()

    assert stat.S_IMODE(target.stat().st_mode) == 0o755  # system interpreter untouched
    assert stat.S_IMODE(shared.stat().st_mode) == 0o644  # shared cache file untouched
    assert left  # failures are reported, not swallowed


# S2 — an env that is in use is refused, untouched, and still registered
@pytest.mark.skipif(not os.path.exists("/proc/self/fd"), reason="emulation needs /proc (Linux); Windows uses S4")
def test_s2_delete_in_use_env_changes_nothing(shared_mgr, monkeypatch):
    m: EnvManager = shared_mgr
    assert m.clone("base", "busy").ok
    env = m.paths.envs / "busy"
    _emulate_windows_lock(monkeypatch, env)
    res = m.delete("busy")
    monkeypatch.undo()
    assert not res.ok and "in use" in res.message
    assert "busy" in m.env_paths()
    info = m.inspect("busy", False)
    assert info.health == "ok", info.health_detail
    assert "six" in {k.lower() for k in info.packages}


# S3 — recreate never destroys an env it cannot rebuild: restore on failure
def test_s3_recreate_rolls_back_when_creation_fails(shared_mgr, monkeypatch):
    m: EnvManager = shared_mgr
    assert m.clone("base", "rb").ok
    before = m.inspect("rb", False).packages
    monkeypatch.setattr(Backend, "venv_argv",
                        lambda self, target, python="": [sys.executable, "-c", "raise SystemExit(3)"])
    res = m.recreate("rb")
    monkeypatch.undo()
    assert not res.ok and "restored" in res.message
    after = m.inspect("rb", False)
    assert after.health == "ok" and after.packages == before
    assert not list(m.paths.envs.glob(f".rb{core.TRASH_MARK}*"))  # no tombstone of THIS env left behind


def test_s3b_recreate_in_use_changes_nothing(shared_mgr, monkeypatch):
    m: EnvManager = shared_mgr
    assert m.clone("base", "rb-busy").ok
    env = m.paths.envs / "rb-busy"
    real_rename = os.rename

    def rename(src, dst, *a, **k):
        if os.path.normcase(os.path.abspath(os.fsdecode(src))) == os.path.normcase(str(env.resolve())):
            raise PermissionError(13, "in use", os.fsdecode(src))
        return real_rename(src, dst, *a, **k)

    monkeypatch.setattr(os, "rename", rename)
    res = m.recreate("rb-busy")
    monkeypatch.undo()
    assert not res.ok and "Nothing was changed" in res.message
    assert m.inspect("rb-busy", False).health == "ok"


# S5 — partly-locked leftovers are remembered and purged later; discovery ignores them
def test_s5_leftover_trash_is_tracked_and_purged(shared_mgr, monkeypatch):
    m: EnvManager = shared_mgr
    assert m.clone("base", "sticky").ok
    real_unlink = os.unlink

    def unlink(p, *a, dir_fd=None, **k):
        """pyvenv.cfg inside a tomb is 'in use' — whether unlinked by full path or via dir_fd."""
        full = os.fsdecode(p)
        if dir_fd is not None and os.path.exists("/proc/self/fd"):
            full = os.path.join(os.readlink(f"/proc/self/fd/{dir_fd}"), full)
        if Path(full).name == "pyvenv.cfg" and core.TRASH_MARK in full:
            raise PermissionError(13, "in use", full)
        return real_unlink(p, *a, dir_fd=dir_fd, **k) if dir_fd is not None else real_unlink(p, *a, **k)

    monkeypatch.setattr(os, "unlink", unlink)
    res = m.delete("sticky")
    monkeypatch.undo()
    assert res.ok and "sticky" not in m.env_paths()
    trash = m._registry_data().get("trash", [])
    assert trash and core.TRASH_MARK in trash[0]["path"]
    assert trash[0]["original"].endswith("sticky") and trash[0]["kind"] == "managed"
    tomb = Path(trash[0]["path"])
    assert (tomb / core.OWNER_MARKER).exists(), "marker must survive a partial delete (deleted last)"
    assert len(trash[0]["token"]) == 64
    assert m.purge_trash().ok
    assert not Path(trash[0]["path"]).exists() and m._registry_data()["trash"] == []


# ---------------------------------------------------------------- Windows-only (run in CI)
@pytest.mark.skipif(not WINDOWS, reason="real Windows file locking")
def test_s4_windows_running_python_blocks_delete_and_recreate(shared_mgr):
    m: EnvManager = shared_mgr
    assert m.clone("base", "winbusy").ok
    py = venv_python(m.paths.envs / "winbusy")
    proc = subprocess.Popen([str(py), "-c", "import time; time.sleep(60)"])
    try:
        time.sleep(1.5)
        res = m.delete("winbusy")
        assert not res.ok and "in use" in res.message, res.message
        assert m.inspect("winbusy", False).health == "ok"
        res = m.recreate("winbusy")
        assert not res.ok and "Nothing was changed" in res.message, res.message
        assert m.inspect("winbusy", False).health == "ok"
    finally:
        proc.kill()
        proc.wait(10)
    time.sleep(1.0)
    assert m.delete("winbusy").ok


@pytest.mark.skipif(not WINDOWS or not shutil.which("py"), reason="needs the Windows py launcher")
def test_s6_windows_py_launcher_env_recreates_with_same_python(mgr):
    from envwarden.backend import resolve_python
    exe = resolve_python(f"{sys.version_info.major}.{sys.version_info.minor}")
    assert exe, "py launcher could not resolve the running Python version"
    res = mgr.create("pylaunch", python=exe, requirements=["six"])
    assert res.ok, res.message
    before = mgr.inspect("pylaunch", False)
    res = mgr.recreate("pylaunch")
    assert res.ok, res.message
    after = mgr.inspect("pylaunch", False)
    assert after.health == "ok", after.health_detail
    assert after.python_version == before.python_version
    assert "six" in {k.lower() for k in after.packages}


@pytest.mark.skipif(not WINDOWS, reason="Windows .exe launcher path embedding")
def test_s7_windows_copied_venv_exe_launcher_detected(shared_mgr, tmp_path):
    from envwarden.probe import relocation_problem
    copy = tmp_path / "copied"
    shutil.copytree(shared_mgr.paths.envs / "base", copy)
    assert (copy / "Scripts" / "pip.exe").exists()
    assert "moved or copied" in relocation_problem(copy)
    assert relocation_problem(shared_mgr.paths.envs / "base") == ""


# ---------------------------------------------------------------- live network (CI only)
network = pytest.mark.skipif(os.environ.get("ENVWARDEN_NETWORK_TESTS") != "1",
                             reason="set ENVWARDEN_NETWORK_TESTS=1 to hit OSV.dev and PyPI")


@network
def test_n1_live_osv_flags_old_jinja2_and_not_current_six():
    from envwarden import pypi, security
    six_latest = pypi.lookup("six").latest
    report = security.audit({"jinja2": "2.10", "six": six_latest})
    assert not report.errors, report.errors
    jinja = [f for f in report.findings if f.package == "jinja2"]
    assert jinja and any(a.startswith("CVE-") for f in jinja for a in f.aliases)
    assert any(f.fixed_in for f in jinja)
    assert not [f for f in report.findings if f.package == "six"]


@network
def test_n2_live_pypi_orders_requests_versions():
    from envwarden import pypi
    from envwarden.versions import version_key
    info = pypi.lookup("requests")
    assert info.versions[0] == info.latest
    assert version_key(info.versions[0]) > version_key("2.9.2")
