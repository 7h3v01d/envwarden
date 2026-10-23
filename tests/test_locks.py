# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Lock files, drift and lock-aware sync (L1–L10)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from envwarden import lockfiles
from envwarden.backend import Backend

LINUX = {"implementation_name": "cpython", "implementation_version": "3.12.4", "os_name": "posix",
         "platform_machine": "x86_64", "platform_release": "6.1", "platform_system": "Linux",
         "platform_version": "#1", "python_full_version": "3.12.4", "platform_python_implementation": "CPython",
         "python_version": "3.12", "sys_platform": "linux"}
WINDOWS = dict(LINUX, os_name="nt", platform_system="Windows", sys_platform="win32")

UV_LOCK = '''version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "colorama"
version = "0.4.6"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "colorama", marker = "sys_platform == 'win32'" },
    { name = "requests", extra = ["socks"] },
    { name = "six" },
]

[package.dev-dependencies]
dev = [
    { name = "iniconfig" },
]

[package.metadata]
requires-dist = [
    { name = "colorama", marker = "sys_platform == 'win32'" },
    { name = "requests", extras = ["socks"], specifier = "<3,>=2.31" },
    { name = "six", specifier = ">=1.16" },
]

[[package]]
name = "iniconfig"
version = "2.3.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pysocks"
version = "1.7.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]

[package.optional-dependencies]
socks = [
    { name = "pysocks" },
]

[[package]]
name = "six"
version = "1.17.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "urllib3"
version = "2.5.0"
source = { registry = "https://pypi.org/simple" }
'''

PYPROJECT = '''[project]
name = "demo"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["six>=1.16", "colorama; sys_platform == 'win32'", "requests[socks]>=2.31,<3"]
'''


def _proj(tmp: Path, lock: str = UV_LOCK, pyproject: str = PYPROJECT) -> Path:
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    if lock:
        (tmp / "uv.lock").write_text(lock, encoding="utf-8")
    return tmp


# L1 — markers evaluated against the TARGET env; extras and dev group followed
def test_l1_uv_lock_walk_respects_target_markers(tmp_path):
    p = _proj(tmp_path)
    linux, _ = lockfiles.expected_from_uv_lock(p / "uv.lock", LINUX)
    win, _ = lockfiles.expected_from_uv_lock(p / "uv.lock", WINDOWS)
    assert "colorama" not in linux and "colorama" in win
    assert {"six", "requests", "urllib3", "pysocks", "iniconfig", "demo"} <= set(linux)
    assert linux["six"].exact == "1.17.0" and linux["demo"].editable_root


def test_l1b_drift_reports_missing_and_wrong_versions(tmp_path):
    p = _proj(tmp_path)
    installed = {"demo": "0.1.0", "six": "1.16.0", "requests": "2.32.3", "urllib3": "2.5.0", "iniconfig": "2.3.1",
                 "pip": "25.2"}
    d = lockfiles.compute_drift(p, installed, LINUX)
    assert d.source.kind == "uv.lock"
    assert d.missing == ["pysocks"]
    assert d.mismatched == [("six", "1.16.0", "==1.17.0")]
    assert d.status == "2 drifted" and not d.extra  # pip is a base tool, not 'extra'


# L2 — pylock.toml markers, including PEP 751 dependency_groups
def test_l2_pylock_markers(tmp_path):
    (tmp_path / "pylock.toml").write_text('''lock-version = "1.0"
created-by = "test"
default-groups = ["dev"]

[[packages]]
name = "colorama"
version = "0.4.6"
marker = "sys_platform == 'win32'"

[[packages]]
name = "pytest"
version = "8.4.2"
marker = "'dev' in dependency_groups"

[[packages]]
name = "sphinx"
version = "8.0.0"
marker = "'docs' in dependency_groups"

[[packages]]
name = "demo"
directory = { path = ".", editable = true }
''', encoding="utf-8")
    exp, notes = lockfiles.expected_from_pylock(tmp_path / "pylock.toml", LINUX)
    assert set(exp) == {"pytest", "demo"}, notes
    assert exp["pytest"].exact == "8.4.2" and exp["demo"].editable_root


# L3 — requirements: -r includes, markers, hashes, ranges, editables
def test_l3_requirements_parsing(tmp_path):
    (tmp_path / "base.txt").write_text("six==1.17.0 \\\n    --hash=sha256:abc\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text(
        "-r base.txt\n# comment\nrequests>=2.31,<3  # inline\npywin32; sys_platform == 'win32'\n"
        "-e ./local\n--index-url https://example/simple\n", encoding="utf-8")
    exp, notes = lockfiles.expected_from_requirements(tmp_path / "requirements.txt", LINUX)
    assert set(exp) == {"six", "requests"}
    assert exp["six"].exact == "1.17.0" and exp["requests"].spec == "<3,>=2.31"
    assert any("editable" in n for n in notes)
    d = lockfiles.compute_drift(tmp_path, {"six": "1.17.0", "requests": "3.1.0", "extra-pkg": "1"}, LINUX)
    assert d.mismatched == [("requests", "3.1.0", "<3,>=2.31")]
    assert d.extra == []  # requirements list direct deps only: extras are not drift


# L4 — tool-config-only pyproject is not a dependency source
def test_l4_tool_only_pyproject_is_not_a_source(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\nline-length = 120\n", encoding="utf-8")
    assert lockfiles.detect_sources(tmp_path) == []
    assert lockfiles.compute_drift(tmp_path, {}, LINUX).status == "no deps declared"


# L5 — stale lock detection compares declarations, not mtimes
def test_l5_stale_lock_detection(tmp_path):
    p = _proj(tmp_path)
    assert lockfiles.uv_lock_staleness(p / "uv.lock", p / "pyproject.toml") == ""  # same deps, reordered specifiers
    (p / "pyproject.toml").write_text(PYPROJECT.replace('"six>=1.16"', '"six>=1.16", "httpx"'), encoding="utf-8")
    msg = lockfiles.uv_lock_staleness(p / "uv.lock", p / "pyproject.toml")
    assert "httpx" in msg and "uv lock" in msg
    assert lockfiles.compute_drift(p, {}, LINUX).status == "lock stale"


# L6 — packages outside an exact lock are listed (a sync would remove them)
def test_l6_extra_packages_listed_for_locks(tmp_path):
    p = _proj(tmp_path)
    installed = {"demo": "0.1.0", "six": "1.17.0", "requests": "2.32.3", "urllib3": "2.5.0",
                 "iniconfig": "2.3.1", "pysocks": "1.7.1", "rich": "14.0.0"}
    d = lockfiles.compute_drift(p, installed, LINUX)
    assert d.drifted == 0 and d.extra == ["rich"] and d.status == "in sync (+1 extra)"


# L7 — precedence and foreign locks
def test_l7_source_precedence_and_poetry_lock_is_not_fought(mgr, tmp_path):
    p = _proj(tmp_path / "proj")
    (p / "requirements.txt").write_text("six\n", encoding="utf-8")
    (p / "pylock.toml").write_text('lock-version = "1.0"\n', encoding="utf-8")
    assert [s.kind for s in lockfiles.detect_sources(p)] == ["uv.lock", "pylock.toml", "requirements.txt",
                                                              "pyproject.toml"]
    q = tmp_path / "poetryproj"
    q.mkdir()
    (q / "poetry.lock").write_text("# poetry\n", encoding="utf-8")
    (q / "requirements.txt").write_text("six\n", encoding="utf-8")
    res = mgr.create_in_project(str(q))
    assert res.ok, res.message
    plan = mgr.sync_plan(res.data["name"])
    assert plan.blocked and "Poetry" in plan.blocked and not plan.argv


def test_l7b_lock_needs_uv_else_falls_back_with_warning(mgr, tmp_path, monkeypatch):
    p = _proj(tmp_path / "proj")
    (p / "requirements.txt").write_text("six\n", encoding="utf-8")
    res = mgr.create_in_project(str(p))
    assert res.ok, res.message
    monkeypatch.setattr(mgr, "backend", Backend("pip"))
    plan = mgr.sync_plan(res.data["name"])
    assert plan.source == "requirements.txt" and not plan.exact
    assert any("uv is not installed" in w for w in plan.warnings)


# L8 — never let uv sync silently rebuild the venv on another Python
def test_l8_requires_python_conflict_blocks_exact_sync(mgr, tmp_path, monkeypatch):
    if mgr.backend.kind != "uv":
        pytest.skip("exact lock sync needs uv")
    p = _proj(tmp_path / "proj", lock="")
    res = mgr.create_in_project(str(p))
    assert res.ok, res.message
    major, minor = (int(x) for x in mgr.inspect(res.data["name"], False).python_version.split(".")[:2])
    future = f">={major}.{minor + 1}"  # one minor newer than whatever Python the venv actually got
    (p / "uv.lock").write_text(UV_LOCK.replace('requires-python = ">=3.11"', f'requires-python = "{future}"'),
                               encoding="utf-8")
    plan = mgr.sync_plan(res.data["name"])
    assert plan.blocked and "requires-python" in plan.blocked and "RECREATE" in plan.blocked
    assert not mgr.sync_project(res.data["name"], trust=True).ok
    assert (p / ".venv" / "pyvenv.cfg").exists()


# L9 — real exact sync from uv.lock: installs the lock, removes extras, snapshots first
@pytest.mark.skipif(os.environ.get("ENVWARDEN_NETWORK_TESTS") != "1", reason="needs PyPI (ENVWARDEN_NETWORK_TESTS=1)")
def test_l9_exact_uv_sync_installs_lock_and_snapshots(mgr, tmp_path):
    if mgr.backend.kind != "uv":
        pytest.skip("needs uv")
    lock = '''version = 1
revision = 3
requires-python = ">=3.11"

[[package]]
name = "demo"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "six" }]

[package.metadata]
requires-dist = [{ name = "six", specifier = "==1.16.0" }]

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/71/39/171f1c67cd00715f190ba0b100d606d440a28c93c7714febeca8b79af85e/six-1.16.0.tar.gz", hash = "sha256:1e61c37477a1626458e36f7b1d82aa5c9b094fa4802892072e49de9c60c4c926", size = 34041 }
wheels = [{ url = "https://files.pythonhosted.org/packages/d9/5a/e7c31adbe875f2abbb91bd84cf2dc52d792b5a01506781dbcf25c91daf11/six-1.16.0-py2.py3-none-any.whl", hash = "sha256:8abb2f1d86890a2dfb989f9a77cfcfd3e47c2a354b01111771326f8aa26e0254", size = 11053 }]
'''
    p = _proj(tmp_path / "proj", lock=lock,
              pyproject='[project]\nname = "demo"\nversion = "0.1.0"\nrequires-python = ">=3.11"\n'
                        'dependencies = ["six==1.16.0"]\n[tool.uv]\npackage = false\n')
    res = mgr.create_in_project(str(p))
    assert res.ok, res.message
    name = res.data["name"]
    assert mgr.install(name, ["iniconfig"]).ok
    before = mgr.drift(name)
    assert before.missing == ["six"] and "iniconfig" in before.extra
    res = mgr.sync_project(name, trust=True)
    assert res.ok, res.message
    after = mgr.drift(name)
    assert after.status == "in sync", after.describe()
    assert mgr.list_snapshots(name)[0]["reason"] == "pre-sync"
    assert "iniconfig" not in {k.lower() for k in mgr.inspect(name, False).packages}


# L10 — recreate can switch Python (to satisfy requires-python / leave an EOL version)
def test_l10_recreate_switches_python(mgr):
    from envwarden.backend import discover_pythons
    assert mgr.create("switch", requirements=["six"]).ok
    current = mgr.inspect("switch", False).python_version
    others = [p for p in discover_pythons(mgr.backend)
              if ".".join(p.version.split(".")[:2]) != ".".join(current.split(".")[:2])]
    if not others:
        pytest.skip("only one Python minor version installed")
    target = others[0]
    res = mgr.recreate("switch", target.path)
    assert res.ok, res.message
    after = mgr.inspect("switch", False)
    assert after.python_version.split(".")[:2] == target.version.split(".")[:2]
    assert after.health == "ok" and "six" in {k.lower() for k in after.packages}
