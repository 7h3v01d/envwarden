# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
from __future__ import annotations

from pathlib import Path

from envwarden.scanner import scan_project

CTX = {
    "stdlib": ["json", "os", "sys", "ast"],
    "builtins": ["sys"],
    "packages_distributions": {"requests": ["requests"], "yaml": ["PyYAML"]},
    "installed": {"requests": "2.32.3", "PyYAML": "6.0.2"},
}


def _project(tmp: Path) -> Path:
    (tmp / "pyproject.toml").write_text(
        '[project]\nname="demo"\ndependencies=["requests>=2", "click"]\n', encoding="utf-8")
    pkg = tmp / "src" / "demo"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    (pkg / "app.py").write_text(
        "import json, os\nimport requests\nimport yaml\nimport cv2\nfrom . import helpers\nfrom demo import x\n",
        encoding="utf-8")
    (pkg / "broken.py").write_text("def (:\n", encoding="utf-8")
    venv = tmp / ".venv" / "lib"
    venv.mkdir(parents=True)
    (tmp / ".venv" / "pyvenv.cfg").write_text("home=x\n", encoding="utf-8")
    (venv / "junk.py").write_text("import should_not_be_seen\n", encoding="utf-8")
    return tmp


def test_scan_resolves_against_environment_metadata(tmp_path):
    rep = scan_project(_project(tmp_path), CTX)
    dists = {f.distribution: f for f in rep.findings}
    assert set(dists) == {"requests", "PyYAML", "opencv-python"}
    assert dists["PyYAML"].installed_version == "6.0.2"          # via packages_distributions, not a table
    assert dists["opencv-python"].missing                          # fallback mapping for not-installed module
    assert "should_not_be_seen" not in str(rep.findings)          # venvs pruned
    assert rep.parse_errors and "broken.py" in rep.parse_errors[0]
    assert rep.undeclared == ["opencv-python", "pyyaml"]
    assert rep.unused_declared == ["click"]
    assert "requests==2.32.3" in rep.requirements_lines()


def test_project_overrides_from_json(tmp_path):
    (tmp_path / "setup.py").write_text("", encoding="utf-8")
    (tmp_path / "envwarden.json").write_text('{"package_mappings": {"cv2": "opencv-python-headless"}, '
                                             '"exclude": ["legacy"]}', encoding="utf-8")
    (tmp_path / "main.py").write_text("import cv2\n", encoding="utf-8")
    (tmp_path / "legacy").mkdir()
    (tmp_path / "legacy" / "old.py").write_text("import oldthing\n", encoding="utf-8")
    rep = scan_project(tmp_path, CTX)
    assert [f.distribution for f in rep.findings] == ["opencv-python-headless"]
