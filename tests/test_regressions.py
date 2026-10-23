# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Regression tests for every defect reproduced in the v3 manager.

Each test is tagged with the original bug (R#) and was proven to fail when
its fix is reverted — see tests/revert_check.py.
"""

from __future__ import annotations

import json
import shutil
import threading

import pytest

from envwarden import netio, pypi, security
from envwarden.audit import AuditLog
from envwarden.core import valid_name
from envwarden.paths import venv_python
from envwarden.probe import relocation_problem

from conftest import spin, wait_idle


# R1 — Manage tab silently missing (builder returned None)
# R2 — every background action crashed (set_busy undefined)
def test_r1_r2_window_builds_all_tabs_and_runs_actions(qapp, mgr):
    from envwarden.ui.main_window import MainWindow

    w = MainWindow(mgr)
    wait_idle(qapp, w)
    titles = [w.tabs.tabText(i) for i in range(w.tabs.count())]
    assert {"PROJECTS", "LIFECYCLE", "PACKAGES"} <= set(titles) and len(titles) == 11
    for i in range(w.tabs.count()):
        assert w.tabs.widget(i) is not None

    results = []
    w.mutate("noop", lambda: __import__("envwarden.core", fromlist=["OpResult"]).OpResult(True, "done"),
             after=results.append)
    wait_idle(qapp, w)
    assert results and results[0].ok
    w.close()


# R2b — callbacks must run on the GUI thread, never in the worker thread
def test_r2b_task_callbacks_run_on_gui_thread(qapp):
    from envwarden.ui.workers import TaskRunner

    runner = TaskRunner()
    seen = {}
    runner.submit("t", lambda: threading.get_ident(), on_done=lambda r: seen.update(cb=threading.get_ident(), worker=r))
    for _ in range(50):
        spin(qapp, 20)
        if "cb" in seen and not runner.active:
            break
    assert seen["cb"] == threading.get_ident()
    assert seen["worker"] != threading.get_ident()
    assert runner.active == 0  # refs released after thread finished


def test_r2c_second_mutation_is_refused_while_one_runs(qapp):
    from envwarden.ui.workers import TaskRunner

    gate = threading.Event()
    runner = TaskRunner()
    try:
        assert runner.submit("a", gate.wait, 5, on_done=lambda r: None, mutating=True)
        assert not runner.submit("b", lambda: None, on_done=lambda r: None, mutating=True)
    finally:
        gate.set()
        for _ in range(100):
            spin(qapp, 20)
            if not runner.active:
                break
    for _ in range(100):
        spin(qapp, 20)
        if not runner.active:
            break
    assert runner.submit("c", lambda: None, on_done=lambda r: None, mutating=True)
    for _ in range(100):
        spin(qapp, 20)
        if not runner.active:
            break


# R3 — clone by copytree: installs into the "clone" landed in the source
def test_r3_clone_is_isolated_from_source(shared_mgr):
    m = shared_mgr
    res = m.clone("base", "base-clone")
    assert res.ok, res.message
    assert m.install("base-clone", ["tomli"]).ok
    assert "tomli" not in {k.lower() for k in m.inspect("base", False).packages}
    clone = m.inspect("base-clone", False)
    assert "tomli" in {k.lower() for k in clone.packages}
    assert "six" in {k.lower() for k in clone.packages}  # pins reproduced
    assert clone.health == "ok", clone.health_detail


# R4 — rename by os.rename left launchers pointing at the old path
def test_r4_rename_rebuilds_and_scripts_point_to_new_location(shared_mgr):
    m = shared_mgr
    assert m.clone("base", "ren-src").ok
    res = m.rename("ren-src", "ren-dst")
    assert res.ok, res.message
    assert "ren-src" not in m.env_paths()
    assert not (m.paths.envs / "ren-src").exists()
    assert relocation_problem(m.paths.envs / "ren-dst") == ""
    assert m.install("ren-dst", ["tomli"]).ok
    assert "tomli" in {k.lower() for k in m.inspect("ren-dst", False).packages}


def test_r4b_copied_venvs_are_flagged_unhealthy(shared_mgr, tmp_path):
    """Envs damaged by the old tool's copy/move are detected, not reported 'OK'."""
    copy = tmp_path / "copied-venv"
    shutil.copytree(shared_mgr.paths.envs / "base", copy, symlinks=True)
    assert relocation_problem(copy) != ""


# R5 — fallback 'security' table flagged packages regardless of version
def test_r5_audit_reports_only_osv_matches_for_exact_versions(monkeypatch):
    sent = []

    def fake(url, payload=None, timeout=20):
        sent.append((url, payload))
        if url == security.OSV_BATCH:
            return {"results": [{"vulns": [{"id": "GHSA-xxxx"}]}, {}]}  # sorted: old-lib, pip
        return {"id": "GHSA-xxxx", "aliases": ["CVE-2099-0001"], "summary": "Bad thing",
                "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"ecosystem": "PyPI", "name": "Old_Lib"},
                              "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.4.2"}]}]}]}

    monkeypatch.setattr(netio, "http_json", fake)
    report = security.audit({"pip": "26.2.2", "old-lib": "1.0.0"})
    queries = sent[0][1]["queries"]
    assert {"package": {"name": "pip", "ecosystem": "PyPI"}, "version": "26.2.2"} in queries
    assert [f.package for f in report.findings] == ["old-lib"]  # pip NOT flagged
    f = report.findings[0]
    assert f.headline_id == "CVE-2099-0001" and f.fixed_in == ["1.4.2"] and f.severity == "HIGH"


def test_r5b_audit_network_failure_is_reported_not_silent(monkeypatch):
    def boom(url, payload=None, timeout=20):
        raise netio.NetError("Network error: offline")

    monkeypatch.setattr(netio, "http_json", boom)
    report = security.audit({"six": "1.17.0"})
    assert report.findings == [] and report.errors


# R6 — PyPI versions sorted as strings (2.9.2 shown as newest)
def test_r6_pypi_versions_are_pep440_ordered(monkeypatch):
    f = [{"yanked": False}]
    data = {"info": {"name": "requests", "version": "2.32.3", "license_expression": "Apache-2.0"},
            "releases": {"2.9.2": f, "2.32.3": f, "2.10.0": f, "3.0.0rc1": f, "2.32.1": [{"yanked": True}], "0.1": []}}
    monkeypatch.setattr(netio, "http_json", lambda url, payload=None, timeout=20: data)
    info = pypi.lookup("requests")
    assert info.versions == ["2.32.3", "2.10.0", "2.9.2"]
    assert info.yanked == ["2.32.1"]
    assert pypi.lookup("requests", include_pre=True).versions[0] == "3.0.0rc1"


def test_r6b_pypi_rejects_non_project_names():
    with pytest.raises(ValueError):
        pypi.lookup("../../evil")


# R7 — package box passed anything to pip (options, URLs, index overrides)
@pytest.mark.parametrize("spec", ["--index-url=https://evil.example/simple", "-r /etc/passwd",
                                  "-e .", "git+https://x/y.git", "pkg @ https://x/y.whl", "../local"])
def test_r7_install_rejects_pip_options_and_urls(shared_mgr, spec):
    res = shared_mgr.install("base", [spec])
    assert not res.ok and "Rejected" in res.message


# R8 — delete used rmtree on whatever path; adopted envs must never be deleted
def test_r8_delete_of_adopted_env_only_unregisters(shared_mgr, tmp_path):
    external = tmp_path / "proj" / ".venv"
    assert shared_mgr.backend.kind in ("uv", "pip")
    from envwarden.procs import run
    assert run(shared_mgr.backend.venv_argv(external)).ok
    assert shared_mgr.adopt(str(external), "external").ok
    assert not shared_mgr.is_managed("external")
    assert shared_mgr.delete("external").ok
    assert venv_python(external).exists()
    assert "external" not in shared_mgr.env_paths()


def test_r8b_delete_dir_refuses_paths_outside_root(mgr):
    with pytest.raises(PermissionError):
        mgr._delete_dir("..")
    with pytest.raises(PermissionError):
        mgr._delete_dir("does-not-exist")


# R9 — wipe had no safety net
def test_r9_wipe_takes_safety_snapshot_and_restore_brings_packages_back(shared_mgr):
    m = shared_mgr
    assert m.clone("base", "wipe-me").ok
    res = m.wipe("wipe-me")
    assert res.ok, res.message
    assert "six" not in {k.lower() for k in m.inspect("wipe-me", False).packages}
    snaps = m.list_snapshots("wipe-me")
    assert snaps and snaps[0]["reason"] == "pre-wipe"
    assert "six==" in m.snapshot_requirements(snaps[0]["id"]).lower()
    assert m.restore_snapshot(snaps[0]["id"], "wipe-restored").ok
    assert "six" in {k.lower() for k in m.inspect("wipe-restored", False).packages}


# R10 — audit log was plain appends; edits were undetectable
def test_r10_audit_chain_detects_edits(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.record("EVT", "success", f"n{i}")
    assert log.verify().ok and log.verify().records == 5
    lines = (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[2])
    rec["detail"] = "forged"
    lines[2] = json.dumps(rec)
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    bad = AuditLog(tmp_path / "a.jsonl").verify()
    assert not bad.ok and bad.first_bad_seq == 3


def test_r10b_audit_chain_detects_deleted_line(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(4):
        log.record("EVT", "success", f"n{i}")
    lines = (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()
    del lines[1]
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not AuditLog(tmp_path / "a.jsonl").verify().ok


# R11 — names like CON or '..' were accepted on Windows / traversal
@pytest.mark.parametrize("name,ok", [("vibe-dev", True), ("py3.12_env", True), ("CON", False), ("nul.txt", False),
                                      ("..", False), ("a/b", False), ("", False), ("x" * 65, False), ("trail.", False)])
def test_r11_name_validation(name, ok):
    assert valid_name(name) is ok
