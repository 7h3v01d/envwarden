# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Fixes from the external adversarial review of 4.2.0 (S8–S13, R12–R13, T1, N3–N4)."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from envwarden import core, netio
from envwarden.audit import AuditLog
from envwarden.core import EnvManager, OpResult

SRC = Path(__file__).resolve().parents[1] / "src"


def _forge_trash(mgr: EnvManager, entries: list) -> None:
    data = mgr._registry_data()
    data["trash"] = entries
    mgr.paths.registry.write_text(json.dumps(data), encoding="utf-8")


def _stamp() -> str:
    return "20261023-120000-000"


def _tomb(original: Path) -> Path:
    """Exactly how core._retire names a tomb: '.' + original name + mark + stamp."""
    return original.with_name(f".{original.name}{core.TRASH_MARK}{_stamp()}")


# S8 — a forged / corrupted trash record must never delete an arbitrary folder
def test_s8_forged_trash_records_cannot_delete_outside_folders(mgr, tmp_path):
    outside = tmp_path / "outside"
    legacy = outside / ".victim.envwarden-trash-TEST"                      # the reviewer's exact repro
    legacy.mkdir(parents=True)
    (legacy / "DO_NOT_DELETE.txt").write_text("precious", encoding="utf-8")

    forged = _tomb(outside / "victim")                                     # well-formed name, wrong contents
    forged.mkdir()
    (forged / "thesis.docx").write_text("precious", encoding="utf-8")

    elsewhere = _tomb(tmp_path / "elsewhere" / ".venv")                   # venv-like, not beside original
    (elsewhere / "lib").mkdir(parents=True)

    target = tmp_path / "real-data"                                        # symlinked tomb
    target.mkdir()
    (target / "lib").mkdir()
    link = _tomb(outside / ".venv")
    try:
        os.symlink(target, link, target_is_directory=True)
        has_link = True
    except OSError:
        has_link = False

    entries = [
        str(legacy),
        {"path": str(forged), "original": str(outside / "victim"), "kind": "project", "created": "x"},
        {"path": str(elsewhere), "original": str(outside / ".venv"), "kind": "project", "created": "x"},
        {"path": "relative/.venv" + core.TRASH_MARK + _stamp(), "original": "relative/.venv"},
    ]
    if has_link:
        entries.append({"path": str(link), "original": str(outside / ".venv"), "kind": "project", "created": "x"})
    _forge_trash(mgr, entries)

    res = mgr.purge_trash()
    assert not res.ok and len(res.data["refused"]) == len(entries)
    reasons = " | ".join(res.data["refused"])
    assert "without provenance" in reasons and "non-venv entries" in reasons
    assert "not beside its recorded original" in reasons and "relative path" in reasons
    if has_link:
        assert "symlink" in reasons
    assert (legacy / "DO_NOT_DELETE.txt").exists()
    assert (forged / "thesis.docx").exists()
    assert (elsewhere / "lib").exists()
    if has_link:
        assert (target / "lib").exists() and os.path.islink(link)


def _genuine_tomb(tmp_path: Path) -> tuple[Path, Path, str]:
    """A tomb made exactly the way EnvWarden makes one: a venv-shaped folder retired by core._retire."""
    original = tmp_path / "proj" / ".venv"
    (original / "lib" / "site-packages").mkdir(parents=True)
    (original / "pyvenv.cfg").write_text("home = x\n", encoding="utf-8")
    tomb, token = core._retire(original)
    assert token and (tomb / core.OWNER_MARKER).exists()
    return original, tomb, token


def _record(tomb: Path, original: Path, token: str | None) -> dict:
    rec = {"path": str(tomb), "original": str(original), "kind": "project", "created": "x"}
    if token is not None:
        rec["token"] = token
    return rec


def test_s8b_genuine_tomb_is_still_purged(mgr, tmp_path):
    original, tomb, token = _genuine_tomb(tmp_path)
    _forge_trash(mgr, [_record(tomb, original, token)])
    res = mgr.purge_trash()
    assert res.ok, res.message
    assert not tomb.exists() and mgr._registry_data()["trash"] == []


# S8c–S8f — the reviewer's 4.2.1 bypass and its variants: venv-shaped, well-named, correctly placed
def _venv_shaped_victim(tmp_path: Path) -> tuple[Path, Path, Path]:
    original = tmp_path / "outside" / "victim"
    tomb = _tomb(original)
    (tomb / "lib").mkdir(parents=True)
    (tomb / "pyvenv.cfg").write_text("home = x\n", encoding="utf-8")
    precious = tomb / "lib" / "precious.bin"
    precious.write_text("precious", encoding="utf-8")
    return original, tomb, precious


def test_s8c_forged_venv_shaped_tomb_without_token_survives(mgr, tmp_path):
    original, tomb, precious = _venv_shaped_victim(tmp_path)
    _forge_trash(mgr, [_record(tomb, original, None)])            # the exact 4.2.1 bypass
    res = mgr.purge_trash()
    assert not res.ok and tomb.exists() and precious.exists()
    assert "ownership token" in res.message


def test_s8d_tomb_with_wrong_token_survives(mgr, tmp_path):
    original, tomb, precious = _venv_shaped_victim(tmp_path)
    (tomb / core.OWNER_MARKER).write_text(json.dumps({"format": 1, "token": "a" * 64, "original": str(original)}),
                                          encoding="utf-8")
    _forge_trash(mgr, [_record(tomb, original, "b" * 64)])
    res = mgr.purge_trash()
    assert not res.ok and precious.exists() and "does not match" in res.message


def test_s8e_correct_token_but_wrong_original_survives(mgr, tmp_path):
    original, tomb, precious = _venv_shaped_victim(tmp_path)
    (tomb / core.OWNER_MARKER).write_text(json.dumps({"format": 1, "token": "c" * 64,
                                                      "original": str(tmp_path / "somewhere" / "else")}),
                                          encoding="utf-8")
    _forge_trash(mgr, [_record(tomb, original, "c" * 64)])
    res = mgr.purge_trash()
    assert not res.ok and precious.exists() and "different original" in res.message


def test_s8e2_marker_that_is_a_symlink_survives(mgr, tmp_path):
    original, tomb, precious = _venv_shaped_victim(tmp_path)
    real = tmp_path / "real-marker.json"
    real.write_text(json.dumps({"format": 1, "token": "d" * 64, "original": str(original)}), encoding="utf-8")
    try:
        os.symlink(real, tomb / core.OWNER_MARKER)
    except OSError:
        pytest.skip("symlinks not permitted here")
    _forge_trash(mgr, [_record(tomb, original, "d" * 64)])
    res = mgr.purge_trash()
    assert not res.ok and precious.exists() and "regular file" in res.message


def test_s8f_genuine_tomb_with_correct_token_is_deleted_and_marker_goes_last(mgr, tmp_path, monkeypatch):
    original, tomb, token = _genuine_tomb(tmp_path)
    (tomb / "lib" / "locked.pyd").write_text("x", encoding="utf-8")
    real_unlink = os.unlink
    order: list[str] = []

    def unlink(p, *a, dir_fd=None, **k):
        name = Path(os.fsdecode(p)).name
        order.append(name)
        if name == "locked.pyd" and getattr(unlink, "locked", True):
            raise PermissionError(13, "in use", os.fsdecode(p))
        return real_unlink(p, *a, dir_fd=dir_fd, **k) if dir_fd is not None else real_unlink(p, *a, **k)

    monkeypatch.setattr(os, "unlink", unlink)
    _forge_trash(mgr, [_record(tomb, original, token)])
    res = mgr.purge_trash()
    assert not res.ok and "1 still locked" in res.message
    assert (tomb / core.OWNER_MARKER).exists(), "marker must outlive locked leftovers"
    assert core.OWNER_MARKER not in order
    unlink.locked = False
    res = mgr.purge_trash()
    monkeypatch.undo()
    assert res.ok, res.message
    assert not tomb.exists()
    assert order[-1] == core.OWNER_MARKER, "ownership marker must be the last thing removed"


def test_s8g_restored_and_preserved_envs_carry_no_marker(shared_mgr, monkeypatch):
    m = shared_mgr
    assert m.clone("base", "markerless").ok
    from envwarden.backend import Backend
    monkeypatch.setattr(Backend, "venv_argv", lambda self, t, p="": [sys.executable, "-c", "raise SystemExit(5)"])
    res = m.recreate("markerless")
    monkeypatch.undo()
    assert not res.ok and "restored" in res.message
    assert not (m.paths.envs / "markerless" / core.OWNER_MARKER).exists()


# S12 — the ORIGINAL env kept aside by a blocked rollback must never be auto-purged
def test_s12_blocked_rollback_preserves_original_forever(shared_mgr, monkeypatch):
    m = shared_mgr
    assert m.clone("base", "keepme").ok
    env = m.paths.envs / "keepme"
    from envwarden.backend import Backend
    monkeypatch.setattr(Backend, "venv_argv", lambda self, t, p="": [sys.executable, "-c", "raise SystemExit(4)"])
    real = core._force_rmtree

    def cannot_clear_new_folder(path):
        return [str(path)] if Path(path) == env else real(path)

    monkeypatch.setattr(core, "_force_rmtree", cannot_clear_new_folder)
    env.mkdir(exist_ok=True)  # the 'new' half-built folder that cannot be removed
    res = m.recreate("keepme")
    monkeypatch.undo()
    assert not res.ok and "preserved" in res.message
    kept = m._registry_data().get("preserved", [])
    assert kept and kept[-1]["env"] == "keepme"
    tomb = Path(kept[-1]["path"])
    assert (tomb / "pyvenv.cfg").exists()
    assert not (tomb / core.OWNER_MARKER).exists(), "preserved original must not be matchable as trash"
    assert not any(isinstance(t, dict) and t.get("path") == str(tomb) for t in m._registry_data().get("trash", []))
    m.purge_trash()
    assert (tomb / "pyvenv.cfg").exists(), "start-up purge deleted the preserved original"


# S9 / S11 / S13 — every 'snapshot first' operation fails CLOSED when the snapshot fails
def _spy_runs(monkeypatch) -> list[list[str]]:
    calls: list[list[str]] = []
    real = core.run

    def spy(argv, *a, **k):
        calls.append([str(x) for x in argv])
        return real(argv, *a, **k)

    monkeypatch.setattr(core, "run", spy)
    return calls


def _fail_snapshots(monkeypatch, mgr) -> None:
    monkeypatch.setattr(mgr, "snapshot", lambda name, reason="manual": OpResult(False, "disk full (simulated)"))


def test_s9_exact_sync_aborts_when_snapshot_fails(mgr, tmp_path, monkeypatch):
    if mgr.backend.kind != "uv":
        pytest.skip("exact lock sync needs uv")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0.1"\nrequires-python = ">=3.8"\n'
                                         'dependencies = []\n', encoding="utf-8")
    (proj / "uv.lock").write_text('version = 1\nrevision = 3\nrequires-python = ">=3.8"\n\n[[package]]\n'
                                  'name = "demo"\nversion = "0.1"\nsource = { virtual = "." }\n', encoding="utf-8")
    res = mgr.create_in_project(str(proj))
    assert res.ok, res.message
    name = res.data["name"]
    assert mgr.sync_plan(name).exact
    calls = _spy_runs(monkeypatch)
    _fail_snapshots(monkeypatch, mgr)
    res = mgr.sync_project(name, trust=True)
    assert not res.ok and "snapshot failed" in res.message
    assert not any("sync" in c for c in calls), calls


def test_s11_upgrade_all_aborts_when_snapshot_fails(shared_mgr, monkeypatch):
    m = shared_mgr
    assert m.clone("base", "noupgrade").ok
    before = m.inspect("noupgrade", False).packages
    calls = _spy_runs(monkeypatch)
    _fail_snapshots(monkeypatch, m)
    res = m.upgrade_all("noupgrade")
    monkeypatch.undo()
    assert not res.ok and "snapshot failed" in res.message
    assert not any("--upgrade" in c for c in calls)
    assert m.inspect("noupgrade", False).packages == before


def test_s13_recreate_aborts_when_snapshot_fails(shared_mgr, monkeypatch):
    m = shared_mgr
    assert m.clone("base", "norecreate").ok
    cfg = (m.paths.envs / "norecreate" / "pyvenv.cfg").read_text(encoding="utf-8")
    _fail_snapshots(monkeypatch, m)
    res = m.recreate("norecreate")
    monkeypatch.undo()
    assert not res.ok and "snapshot failed" in res.message
    assert (m.paths.envs / "norecreate" / "pyvenv.cfg").read_text(encoding="utf-8") == cfg


# S10 — 'one change at a time' holds across PROCESSES, and a dead holder leaves no stale lock
def test_s10_other_process_holding_lock_blocks_mutation(mgr):
    assert mgr.create("shared-target").ok
    script = textwrap.dedent(f"""
        import sys, time
        sys.path.insert(0, {str(SRC)!r})
        from envwarden.paths import AppPaths
        from envwarden.core import EnvManager
        m = EnvManager(AppPaths.create(__import__('pathlib').Path({str(mgr.paths.home)!r})))
        m._mutex.operation = "held-by-test"
        m._mutex.__enter__()
        print("READY", flush=True)
        time.sleep(60)
    """)
    proc = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "READY"
        mgr._mutex.timeout = 0.3
        res = mgr.delete("shared-target")
        assert not res.ok and res.data.get("busy") and "held-by-test" in res.message
        assert "shared-target" in mgr.env_paths()
        assert not mgr.install("shared-target", ["six"]).ok
    finally:
        proc.kill()
        proc.wait(10)
    mgr._mutex.timeout = 5
    assert mgr.delete("shared-target").ok  # OS released the lock when the holder died


def test_s10b_two_managers_in_one_process_serialise(mgr):
    other = EnvManager(mgr.paths)
    other._mutex.timeout = 0.2
    with mgr._mutex:
        res = other.add_workspace(str(mgr.paths.home))
        assert not res.ok and res.data.get("busy")
    assert other.add_workspace(str(mgr.paths.home.parent)).ok


# R12 — concurrent audit writers keep one valid chain
def test_r12_two_audit_writers_keep_chain_intact(tmp_path):
    a, b = AuditLog(tmp_path / "a.jsonl"), AuditLog(tmp_path / "a.jsonl")
    for i in range(10):
        (a if i % 2 else b).record("EVT", "ok", str(i))
    res = AuditLog(tmp_path / "a.jsonl").verify()
    assert res.ok and res.records == 10


def test_r12b_parallel_processes_append_without_forking_chain(tmp_path):
    log = tmp_path / "audit.jsonl"
    writer = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(SRC)!r})
        from envwarden.audit import AuditLog
        a = AuditLog(__import__('pathlib').Path({str(log)!r}))
        for i in range(60):
            a.record("P" + sys.argv[1], "ok", str(i))
    """)
    procs = [subprocess.Popen([sys.executable, "-c", writer, str(n)]) for n in range(3)]
    for p in procs:
        assert p.wait(120) == 0
    res = AuditLog(log).verify()
    assert res.ok, res
    assert res.records == 180


def test_r13_audit_tail_read_handles_long_lines(tmp_path):
    a = AuditLog(tmp_path / "a.jsonl")
    a.record("BIG", "ok", "x" * 200_000)
    a.record("SMALL", "ok", "y")
    assert AuditLog(tmp_path / "a.jsonl").verify().ok


# T1 — first sync of a project requires explicit trust; nothing runs without it
def test_t1_first_sync_requires_trust(mgr, tmp_path, monkeypatch):
    proj = tmp_path / "untrusted"
    proj.mkdir()
    (proj / "requirements.txt").write_text("six\n", encoding="utf-8")
    res = mgr.create_in_project(str(proj))
    assert res.ok, res.message
    name = res.data["name"]
    calls = _spy_runs(monkeypatch)
    res = mgr.sync_project(name)
    assert not res.ok and res.data.get("needs_trust") and "run Python code" in res.message
    assert calls == [] and not mgr.is_trusted(str(proj))
    res = mgr.sync_project(name, trust=True)
    assert res.ok, res.message
    assert mgr.is_trusted(str(proj))
    assert mgr.sync_project(name).ok  # remembered
    assert any(r.get("event") == "TRUST_PROJECT" for r in mgr.audit.tail())


# N3 / N4 — HTTPS on every hop; bounded responses
def test_n3_redirect_away_from_https_is_refused():
    import urllib.request
    handler = netio.HttpsOnlyRedirectHandler()
    req = urllib.request.Request("https://pypi.org/pypi/x/json")
    with pytest.raises(netio.NetError):
        handler.redirect_request(req, None, 302, "Found", {}, "http://evil.example/x.json")
    with pytest.raises(netio.NetError):
        handler.redirect_request(req, None, 302, "Found", {}, "ftp://evil.example/x.json")
    ok = handler.redirect_request(req, None, 302, "Found", {}, "https://pypi.org/pypi/X/json")
    assert ok is not None and ok.full_url.startswith("https://")


def test_n4_oversized_response_is_refused():
    class Resp:
        headers: dict = {}

        def __init__(self, n):
            self._b = io.BytesIO(b"x" * n)

        def read(self, size=-1):
            return self._b.read(size)

    assert netio.read_capped(Resp(1000), limit=2000) == b"x" * 1000
    with pytest.raises(netio.NetError):
        netio.read_capped(Resp(5000), limit=2000)

    class Declared(Resp):
        headers = {"Content-Length": "999999999"}

    with pytest.raises(netio.NetError):
        netio.read_capped(Declared(10), limit=2000)


def test_lock_released_on_exception(mgr):
    with pytest.raises(RuntimeError):
        with mgr._mutex:
            raise RuntimeError("boom")
    other = EnvManager(mgr.paths)
    other._mutex.timeout = 0.2
    assert other.add_workspace(str(mgr.paths.home.parent)).ok
    time.sleep(0)
