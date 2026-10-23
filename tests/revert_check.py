# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Revert-proof harness: re-introduce each original defect and confirm its test FAILS.

    python tests/revert_check.py

Copies src/ and tests/ to a temp dir, applies one revert at a time, runs the
matching test(s), and requires a non-zero exit. Exit code 0 = every
regression test is proven to guard its fix.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (id, file, original snippet, reverted snippet, pytest -k expression)
REVERTS = [
    ("R1 tab builder returns None", "src/envwarden/ui/main_window.py",
     "        right.addStretch(1)\n        return w\n\n    # ------------------------------------------------------------------ PACKAGES",
     "        right.addStretch(1)\n        return None\n\n    # ------------------------------------------------------------------ PACKAGES",
     "test_r1_r2"),
    ("R2b callback runs in worker thread", "src/envwarden/ui/workers.py",
     "worker.finished.connect(self._on_finished)",
     "worker.finished.connect(self._on_finished, Qt.ConnectionType.DirectConnection)",
     "test_r2b"),
    ("R2c no mutation exclusivity", "src/envwarden/ui/workers.py",
     "if mutating and self._mutating_token is not None:\n            return False",
     "if False:\n            return False",
     "test_r2c"),
    ("R3 clone by copytree", "src/envwarden/core.py",
     '        return self.rebuild_copy(source, target, project, action="clone")',
     '        shutil.copytree(self.paths.envs / source, self.paths.envs / target, symlinks=True)\n'
     '        return OpResult(True, "copied")',
     "test_r3"),
    ("R4 rename by os.rename", "src/envwarden/core.py",
     '            built = self.rebuild_copy(old, new, action="rename")',
     '            (self.paths.envs / old).rename(self.paths.envs / new)\n'
     '            built = OpResult(True, "moved")',
     "test_r4_"),
    ("R4b relocation never detected", "src/envwarden/probe.py",
     "    from .paths import venv_bin\n\n    here =",
     "    return ''\n    from .paths import venv_bin\n\n    here =",
     "test_r4b"),
    ("R5 version not sent to OSV", "src/envwarden/security.py",
     '"version": v} for n, v in chunk]',
     '} for n, v in chunk]',
     "test_r5_"),
    ("R6 string version sort", "src/envwarden/versions.py",
     "            return (1, Version(v))",
     "            return (1, v)",
     "test_r6_"),
    ("R7 package box accepts anything", "src/envwarden/versions.py",
     '    spec = spec.strip()\n    if not spec or spec.startswith("-")',
     '    return spec\n    spec = spec.strip()\n    if not spec or spec.startswith("-")',
     "test_r7"),
    ("R8 adopted env deleted", "src/envwarden/core.py",
     '            if not self.is_managed(name):\n                adopted = self._registry()\n                adopted.pop(name, None)',
     '            if False:\n                adopted = self._registry()\n                adopted.pop(name, None)',
     "test_r8_"),
    ("R9 wipe without snapshot", "src/envwarden/core.py",
     '            snap = self.snapshot(name, reason="pre-wipe")',
     '            snap = OpResult(True, "", {"id": "none"})',
     "test_r9"),
    ("R10 audit hash not checked", "src/envwarden/audit.py",
     'if rec.get("hash") != _digest(rec):',
     "if False:",
     "test_r10_"),
    ("R11 any name accepted", "src/envwarden/core.py",
     "def valid_name(name: str) -> bool:\n",
     "def valid_name(name: str) -> bool:\n    return bool(name)\n",
     "test_r11"),
    ("P1 node_modules not pruned", "src/envwarden/workspace.py",
     '".git", ".hg", ".svn", "node_modules", ', '".git", ".hg", ".svn", ', "test_p1"),
    ("P2 rescan re-registers duplicates", "src/envwarden/core.py",
     "if key in known or key.startswith(home_key):", "if False:", "test_p2"),
    ("P3 builds a second venv beside an existing one", "src/envwarden/core.py",
     "            existing = workspace.venvs_in_project(proj)\n            if existing:",
     "            existing = workspace.venvs_in_project(proj)\n            if False:", "test_p3_"),
    ("P4 recreate does not rebuild", "src/envwarden/core.py",
     "            try:\n                tomb = _retire(guarded)  # old env kept intact",
     "            return OpResult(True, 'skipped rebuild')\n            try:\n                tomb = _retire(guarded)  # old env kept intact",
     "test_p4"),
    ("P5b project root deletable", "src/envwarden/core.py",
     'if markers or (path / ".git").exists():', "if False:", "test_p5b"),
    ("P6 prune removes manual entries", "src/envwarden/core.py",
     'if self.meta(name).get("origin") == "workspace" and not is_venv(Path(p)):',
     "if not is_venv(Path(p)):", "test_p6"),
    ("P7 registry overwrite drops keys", "src/envwarden/core.py",
     "data = self._registry_data()  # keep any other keys", "data = {}  # keep any other keys", "test_p7"),
    ("P8 drive root accepted as workspace", "src/envwarden/core.py",
     "if len(resolved.parts) < 2 or resolved == Path(resolved.anchor):", "if False:", "test_p8_"),
    ("S1 force-delete chmods through symlinks/hardlinks", "src/envwarden/core.py",
     'if os.name == "nt" and not stat.S_ISLNK(st.st_mode) and st.st_nlink <= 1:', "if True:", "test_s1"),
    ("S2 delete without atomic retire", "src/envwarden/core.py",
     "        tomb = _retire(path)\n        left = _force_rmtree(tomb)", "        tomb = path\n        left = _force_rmtree(tomb)",
     "test_s2"),
    ("S3 recreate without rollback", "src/envwarden/core.py",
     "                return rollback(res.output)", "                return OpResult(False, res.output)", "test_s3_"),
    ("S5 leftovers forgotten", "src/envwarden/core.py",
     "        if left:\n            self._remember_trash(tomb, path, kind or",
     "        if False:\n            self._remember_trash(tomb, path, kind or", "test_s5"),
    ("L1 markers not evaluated", "src/envwarden/lockfiles.py",
     "    if not marker:\n        return True\n    try:\n        m = Marker(marker)",
     "    return True\n    if not marker:\n        return True\n    try:\n        m = Marker(marker)", "test_l1"),
    ("L3 requirement markers ignored", "src/envwarden/lockfiles.py",
     "        if req.marker is not None and not _marker_ok(str(req.marker), env, notes):\n            continue\n        out[normalize(req.name)] = _expected_from_req(req)\n    return out, notes\n\n\ndef expected_from_pyproject",
     "        out[normalize(req.name)] = _expected_from_req(req)\n    return out, notes\n\n\ndef expected_from_pyproject",
     "test_l3"),
    ("L4 tool-only pyproject treated as source", "src/envwarden/lockfiles.py",
     'and (k != "pyproject.toml" or _pyproject_has_project(project / k))]', "]", "test_l4"),
    ("L5 stale lock never detected", "src/envwarden/lockfiles.py",
     '    """Compare pyproject\'s declared dependency names against the lock\'s recorded metadata."""',
     '    """Compare pyproject\'s declared dependency names against the lock\'s recorded metadata."""\n    return ""',
     "test_l5"),
    ("L6 extras reported for plain requirements", "src/envwarden/lockfiles.py",
     "    if src.is_lock:\n        drift.extra", "    if True:\n        drift.extra", "test_l3"),
    ("L7 poetry lock synced anyway", "src/envwarden/core.py",
     "            if src.foreign_tool:\n                return SyncPlan(", "            if False:\n                return SyncPlan(",
     "test_l7_"),
    ("L8 requires-python guard removed", "src/envwarden/core.py",
     "                if conflict:\n                    return SyncPlan(", "                if False:\n                    return SyncPlan(",
     "test_l8"),
    ("L10 recreate ignores chosen Python", "src/envwarden/core.py",
     "            override = python.strip()", '            override = ""', "test_l10"),
    ("L9 exact sync without safety snapshot", "src/envwarden/core.py",
     "            if plan.exact:  # an exact sync", "            if False:  # an exact sync", "test_l9"),
    ("S8 trash contents not checked", "src/envwarden/core.py",
     "        if unexpected:\n            return f\"contains non-venv entries", "        if False:\n            return f\"contains non-venv entries",
     "test_s8_"),
    ("S8 tomb location not checked", "src/envwarden/core.py",
     '            return "tomb is not beside its recorded original"', '            pass', "test_s8_"),
    ("S12 preserved original recorded as trash", "src/envwarden/core.py",
     "self._remember_preserved(tomb, guarded, name)", 'self._remember_trash(tomb, guarded, "recreate")', "test_s12"),
    ("S9 exact sync ignores failed snapshot", "src/envwarden/core.py",
     '                if not snap.ok:\n                    self.audit.record("SYNC_PROJECT", "denied"',
     '                if False:\n                    self.audit.record("SYNC_PROJECT", "denied"', "test_s9"),
    ("S11 upgrade-all ignores failed snapshot", "src/envwarden/core.py",
     '            if not snap.ok:\n                self.audit.record("UPGRADE_ALL", "denied"',
     '            if False:\n                self.audit.record("UPGRADE_ALL", "denied"', "test_s11"),
    ("S13 recreate ignores failed snapshot", "src/envwarden/core.py",
     '                if not snap.ok:\n                    self.audit.record("RECREATE_ENV", "denied"',
     '                if False:\n                    self.audit.record("RECREATE_ENV", "denied"', "test_s13"),
    ("S10 process-local lock only", "src/envwarden/core.py",
     "            if not self._ipl.acquire(timeout=self.timeout):", "            if False:", "test_s10"),
    ("R12 audit appends from stale tail", "src/envwarden/audit.py",
     "            self._seq, self._last = self._load_tail()\n            seq", "            seq", "test_r12"),
    ("T1 sync without trust", "src/envwarden/core.py",
     "            if not self.is_trusted(project_dir):\n                if not trust:",
     "            if False:\n                if not trust:", "test_t1"),
    ("N3 redirects off HTTPS followed", "src/envwarden/netio.py",
     '        if not str(newurl).lower().startswith("https://"):', "        if False:", "test_n3"),
    ("N4 response size unbounded", "src/envwarden/netio.py",
     "        if total > limit:", "        if False:", "test_n4"),
]


def main() -> int:
    failures = 0
    skipped = 0
    for rid, rel, old, new, kexpr in REVERTS:
        with tempfile.TemporaryDirectory(prefix="ew-revert-") as tmp:
            dst = Path(tmp)
            shutil.copytree(ROOT / "src", dst / "src")
            shutil.copytree(ROOT / "tests", dst / "tests")
            target = dst / rel
            text = target.read_text(encoding="utf-8")
            if old not in text:
                print(f"[STALE ] {rid}: revert pattern not found in {rel}")
                failures += 1
                continue
            text = text.replace(old, new, 1)
            if "Qt.ConnectionType" in new:
                text = text.replace("from PyQt6.QtCore import ", "from PyQt6.QtCore import Qt, ", 1)
            target.write_text(text, encoding="utf-8")
            res = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x",
                                  "tests", "-k", kexpr], cwd=dst, capture_output=True, text=True, timeout=900)
            last = res.stdout.strip().splitlines()[-1] if res.stdout.strip() else ""
            if res.returncode == 0 and "skipped" in last and "passed" not in last:
                print(f"[SKIP  ] {rid}  ({kexpr}) — test skipped here (e.g. needs network/Windows)")
                skipped += 1
                continue
            if res.returncode not in (0, 5):  # 5 = no tests collected
                print(f"[CAUGHT] {rid}  ({kexpr})")
            else:
                print(f"[MISSED] {rid}  ({kexpr}) exit={res.returncode}\n{res.stdout[-800:]}")
                failures += 1
    caught = len(REVERTS) - failures - skipped
    print(f"\n{caught}/{len(REVERTS) - skipped} reverts caught by their regression tests"
          + (f" ({skipped} skipped in this environment)." if skipped else "."))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
