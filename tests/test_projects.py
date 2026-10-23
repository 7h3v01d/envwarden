# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Project-local venv management (P1–P8). Revert-proven via tests/revert_check.py."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from envwarden import workspace
from envwarden.paths import venv_python
from envwarden.probe import relocation_problem
from envwarden.procs import run


def _make_venv(mgr, path: Path) -> Path:
    res = run(mgr.backend.venv_argv(path))
    assert res.ok, res.output
    return path


@pytest.fixture
def ws(mgr, tmp_path):
    """A workspace with: alpha (pyproject + .venv), beta (requirements, NO venv),
    gamma (loose .py + venv311), a venv hidden in node_modules, and deep nesting."""
    root = tmp_path / "dev"
    (root / "alpha").mkdir(parents=True)
    (root / "alpha" / "pyproject.toml").write_text('[project]\nname = "alpha"\nversion = "0.1"\n', encoding="utf-8")
    _make_venv(mgr, root / "alpha" / ".venv")
    (root / "beta").mkdir()
    (root / "beta" / "requirements.txt").write_text("six\n", encoding="utf-8")
    (root / "gamma").mkdir()
    (root / "gamma" / "main.py").write_text("print('hi')\n", encoding="utf-8")
    _make_venv(mgr, root / "gamma" / "venv311")
    _make_venv(mgr, root / "web" / "node_modules" / "pkg" / ".venv")
    (root / "group" / "sub" / "delta").mkdir(parents=True)
    (root / "group" / "sub" / "delta" / "setup.py").write_text("", encoding="utf-8")
    assert mgr.add_workspace(str(root)).ok
    return root


# P1 — discovery finds project venvs, links owners, reports projects WITHOUT a venv
def test_p1_discovery_links_projects_and_reports_missing(ws):
    res = workspace.discover([str(ws)])
    by_name = {p.name: p for p in res.projects}
    assert set(by_name) == {"alpha", "beta", "gamma", "delta"}
    assert by_name["alpha"].status == "has-venv" and by_name["alpha"].venvs[0].endswith(".venv")
    assert by_name["beta"].status == "no-venv"
    assert by_name["gamma"].venvs and by_name["gamma"].venvs[0].endswith("venv311")
    assert not any("node_modules" in v.path for v in res.venvs)       # pruned
    assert not any(".venv" in Path(p.path).parts for p in res.projects)  # never walked into a venv


# P2 — registering is in place and idempotent; names come from the project
def test_p2_discover_registers_in_place_idempotently(mgr, ws):
    first = mgr.discover()
    assert first.ok, first.message
    assert sorted(first.data["added"]) == ["alpha", "gamma-venv311"]
    assert Path(mgr.env_paths()["alpha"]) == (ws / "alpha" / ".venv").resolve()
    assert mgr.inspect("alpha", False).kind == "project"
    assert mgr.discover().data["added"] == []          # second scan adds nothing
    assert len(mgr.env_paths()) == 2


# P3 — the key requirement: never build a second venv when one exists
def test_p3_create_in_project_refuses_when_venv_exists(mgr, ws):
    before = sorted(p.name for p in (ws / "alpha").iterdir())
    res = mgr.create_in_project(str(ws / "alpha"))
    assert not res.ok and "already has a virtualenv" in res.message
    assert res.data["existing"] == ["alpha"]           # and it got registered
    assert sorted(p.name for p in (ws / "alpha").iterdir()) == before


def test_p3b_create_in_project_builds_dot_venv_and_syncs(mgr, ws):
    res = mgr.create_in_project(str(ws / "beta"), sync=True, trust=True)
    assert res.ok, res.message
    venv = ws / "beta" / ".venv"
    assert venv_python(venv).exists()
    info = mgr.inspect(res.data["name"], False)
    assert info.kind == "project" and info.project_dir == str((ws / "beta").resolve())
    assert "six" in {k.lower() for k in info.packages}  # requirements.txt installed
    assert mgr.env_for_project(str(ws / "beta")) == res.data["name"]


# P4 — a project venv that was copied in from elsewhere is repaired in place
def test_p4_recreate_in_place_repairs_moved_project_venv(mgr, ws, tmp_path):
    src = mgr.create_in_project(str(ws / "beta"), sync=True, trust=True)
    assert src.ok, src.message
    epsilon = ws / "epsilon"
    epsilon.mkdir()
    (epsilon / "requirements.txt").write_text("six\n", encoding="utf-8")
    shutil.copytree(ws / "beta" / ".venv", epsilon / ".venv", symlinks=True)  # what people do by hand
    mgr.discover()
    name = mgr.env_for_project(str(epsilon))
    assert name and mgr.inspect(name, False).health == "warn"
    assert relocation_problem(epsilon / ".venv")
    res = mgr.recreate(name)
    assert res.ok, res.message
    assert relocation_problem(epsilon / ".venv") == ""
    after = mgr.inspect(name, False)
    assert after.health == "ok", after.health_detail
    assert "six" in {k.lower() for k in after.packages}
    assert Path(mgr.env_paths()[name]) == (epsilon / ".venv").resolve()  # same path, same name


# P5 — deleting a project venv folder is allowed, but never a project root
def test_p5_delete_project_venv_folder(mgr, ws):
    mgr.discover()
    res = mgr.delete("alpha", remove_files=True)
    assert res.ok, res.message
    assert not (ws / "alpha" / ".venv").exists()
    assert (ws / "alpha" / "pyproject.toml").exists()


def test_p5b_delete_refuses_venv_that_is_a_project_root(mgr, tmp_path):
    odd = tmp_path / "odd"
    _make_venv(mgr, odd)
    (odd / "pyproject.toml").write_text("[project]\nname='odd'\n", encoding="utf-8")  # someone's project IS the venv
    assert mgr.adopt(str(odd), "odd").ok
    res = mgr.delete("odd", remove_files=True)
    assert not res.ok and "project root" in res.message
    assert (odd / "pyproject.toml").exists() and venv_python(odd).exists()


def test_p5c_delete_without_flag_only_unregisters(mgr, ws):
    mgr.discover()
    assert mgr.delete("alpha").ok
    assert venv_python(ws / "alpha" / ".venv").exists()


# P6 — vanished workspace venvs are pruned; manually adopted ones are kept
def test_p6_rescan_prunes_vanished_workspace_entries_only(mgr, ws, tmp_path):
    mgr.discover()
    manual = _make_venv(mgr, tmp_path / "elsewhere" / ".venv")
    assert mgr.adopt(str(manual), "manual-one").ok
    shutil.rmtree(ws / "gamma" / "venv311")
    shutil.rmtree(manual)
    res = mgr.discover()
    assert res.data["pruned"] == ["gamma-venv311"]
    assert "manual-one" in mgr.env_paths() and "alpha" in mgr.env_paths()


# P7 — registry writes must not drop other keys (workspaces/projects survive adopt/delete)
def test_p7_registry_preserves_unknown_keys(mgr, tmp_path):
    import json
    mgr.paths.registry.write_text(json.dumps({"adopted": {}, "future_key": [1, 2]}), encoding="utf-8")
    v = _make_venv(mgr, tmp_path / "x" / ".venv")
    assert mgr.adopt(str(v), "xenv").ok
    data = json.loads(mgr.paths.registry.read_text(encoding="utf-8"))
    assert data["future_key"] == [1, 2] and "xenv" in data["adopted"]


# P8 — workspace guard rails
def test_p8_workspace_rejects_drive_root_and_dedupes(mgr, tmp_path):
    anchor = Path(tmp_path.anchor)
    assert not mgr.add_workspace(str(anchor)).ok
    assert mgr.add_workspace(str(tmp_path)).ok
    assert mgr.add_workspace(str(tmp_path)).ok and len(mgr.workspaces()) == 1
    assert not mgr.add_workspace(str(tmp_path / "missing")).ok


def test_p8b_adopt_links_project_automatically(mgr, ws):
    assert mgr.adopt(str(ws / "alpha" / ".venv"), "alpha-manual").ok
    info = mgr.inspect("alpha-manual", False)
    assert info.kind == "project" and info.project_dir == str((ws / "alpha").resolve())


def test_suggest_env_name():
    assert workspace.suggest_env_name(Path("/d/My Proj/.venv"), "/d/My Proj") == "My-Proj"
    assert workspace.suggest_env_name(Path("/d/tool/py311"), "/d/tool") == "tool-py311"
