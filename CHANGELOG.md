# Changelog

## 4.2.1 — 2026-10-23

Fixes from an external adversarial review of 4.2.0. Every finding was reproduced against the code before
fixing; none were rejected. Each fix has a regression test and is in the revert harness (45/45 caught).

### Fixed — release blockers
- **S8 (high):** start-up trash purge deleted any folder whose name contained the trash marker, from a
  plain path in `registry.json` — a corrupted or hand-edited registry could delete an arbitrary directory
  (reproduced). Trash records now carry provenance (tomb + original path + kind); a folder is deleted only if
  its name is exactly the tomb of the recorded original, it sits beside that original, it is not a
  symlink/junction, and it contains nothing but venv files. Anything doubtful — including 4.2.0-format
  records — is left on disk and reported. Fail closed.
- **S12 (high, found during verification):** if recreate's rollback could not clear the half-built folder,
  the preserved *original* environment was recorded as trash, so the next start-up would have deleted it.
  It is now recorded as "preserved" and is never purged automatically.
- **S10 / R12 (high):** "one change at a time" was per `EnvManager` object. Two GUIs, the GUI and CLI, or two
  managers could mutate concurrently, and two audit writers forked the chain (reproduced: `seq 1, 1`). All
  mutating operations now hold an OS-level inter-process lock (fcntl/msvcrt, no new dependency), failing
  fast with who holds it; the audit log appends under its own lock after re-reading the real tail.
- **S9 / S11 / S13 (high/medium):** exact sync, upgrade-all and recreate carried on when their safety
  snapshot failed (reproduced for upgrade-all). They now abort with nothing changed, as wipe already did.

### Changed / hardened
- **T1:** the first sync of each project requires explicit trust (GUI prompt; CLI `--trust`): installing can
  run the project's build backend / setup.py and dependencies' build scripts. Trust is remembered and audited.
- **N3 / N4:** HTTPS is enforced on every redirect hop (urllib allowed https→http/ftp); responses are read
  in chunks and capped.
- **Reproducible installs:** `uv.lock` + hash-pinned `requirements-lock.txt` (all platforms, includes the
  pinned setuptools build backend) + CycloneDX SBOM. `setup.bat` and CI install only from the hashed set with
  `--no-build-isolation`; CI fails if the lock or SBOM is stale. New `relock.bat`.
- Audit log reads its tail backwards from the end (constant cost per append), fsyncs each record.
- Docs: audit log described accurately as tamper-evident (not keyed); delete boundaries stated precisely.


## 4.2.0 — 2026-10-23

### Fixed — safety (found while reproducing Windows file-lock behaviour)
- **S1 (critical, Linux):** when force-delete hit a file it could not remove, it chmod-ed it — following
  symlinks and hard links. A venv's `python` is a symlink to the system interpreter and uv hard-links
  packages from its shared cache, so a failed delete could make the *system Python* and cached packages
  unreadable. Force-delete now never changes a link's target, never touches multiply-linked files, and only
  clears the read-only flag on Windows.
- **S2:** delete reported success while in-use files remained, and the half-removed folder silently vanished
  from the list. Venv folders are now renamed aside first — the rename fails atomically if anything is in
  use, so nothing changes and you are told why.
- **S3:** recreate removed the old venv before building the new one; a failure lost the environment. The old
  folder is now kept until the new venv works, and restored on any failure.
- **S5:** leftovers from partly-locked deletes are tracked and retried at start-up; discovery ignores them.

### Added
- **Lock-file aware sync:** `uv.lock` → `uv sync --frozen` into the project's own venv; `pylock.toml`
  (PEP 751) → `uv pip sync`. Exact syncs take a safety snapshot first. Refused when the venv's Python
  doesn't satisfy `requires-python` (uv would silently delete and rebuild it). `poetry.lock`/`Pipfile.lock`
  projects are left to their own tools.
- **Drift detection:** DRIFT column + detail panel on PROJECTS, drift line in the overview, `envwarden drift`
  (exit 1 on drift). Markers are evaluated against the target venv's own environment; stale `uv.lock`
  detected by comparing declarations, not timestamps.
- **Recreate on another Python** (GUI picker / `recreate --python`) — to satisfy `requires-python` or leave
  an end-of-life version.
- **CI:** GitHub Actions matrix (Windows/Linux × 3.11/3.13 × uv/pip), Windows-only and live-network tests,
  revert harness, lint; actions pinned by SHA.
- CLI: `drift`, `sync`, `recreate --python`.

### Changed
- `packaging>=25` (lock-file marker evaluation).

## 4.1.0 — 2026-10-23

### Added — project-local venv management
- **Workspaces:** folders such as `C:\dev` are scanned (depth-limited, heavy folders pruned, never inside a
  venv) for projects and the venvs inside them. Found venvs are registered in place and linked to their
  project; vanished ones are pruned on rescan (manually adopted entries are always kept).
- **PROJECTS tab** and `PROJECTS W/O VENV` metric: every project with its venv, health and Python, or
  "— none". Auto-rescan on start-up.
- **Create venv in project** (`<project>/.venv`) — refused when the project already has a venv (P3).
- **Sync project deps:** `requirements.txt`, else editable install of `pyproject.toml`/`setup.py`.
- **Recreate in place:** rebuild a moved/copied/broken venv at its own path with the same Python and pins
  (falls back to the newest snapshot when the interpreter is dead).
- **Delete venv folder** for project/external envs, guarded: must contain `pyvenv.cfg`, must be
  registered, must not be a project root, home, workspace, drive root or the app home.
- Environment *kind* is now `managed` / `project` / `external`; adopting a `.venv` links its project.
- CLI: `workspace add|remove|list`, `discover`, `projects [--missing]`, `init`, `recreate`.

### Fixed
- Registry writes replaced the whole file; other keys are now preserved (P7).

## 4.0.0 — 2026-10-23

Rewrite of the earlier single-file venv manager (v3) as a `src/` package under the EnvWarden name.

### Fixed (each covered by a revert-proven regression test)
- **R1** Manage tab never appeared — its builder returned `None` and Qt silently dropped it.
- **R2** Every background action crashed — `set_busy()` was called but never defined.
- **R3** Clone used `copytree`; the clone's launchers kept pointing at the source, so installs into the
  clone landed in the original. Clone now rebuilds from frozen pins.
- **R4** Rename/import-move used `os.rename`/`shutil.move`, breaking the env. Managed renames rebuild;
  adopted renames only relabel.
- **R5** Fallback "security check" flagged packages regardless of version (e.g. pip 26.2.2 reported for a
  `<23.3` CVE). Replaced by OSV.dev exact-version matching; network failures are reported, never "clean".
- **R6** PyPI versions sorted as strings (2.9.2 shown as newest). PEP 440 ordering; yanked excluded.
- **R7** Package box passed anything to pip (`--index-url`, `-r`, URLs). Now deny-first PEP 508 only.
- **R8** Delete called `rmtree` on any registered path. Confined to the managed root; adopted envs are
  only unregistered.
- **R9** Wipe had no safety net. Wipe and upgrade-all auto-snapshot first.
- **R10** Audit log was plain appends. Now SHA-256 hash-chained with verification.
- **R11** Names such as `CON`, `nul.txt` or trailing dots were accepted.
- UI freeze: refresh ran three subprocesses per env on the GUI thread; now one isolated probe per env,
  on a worker. `shell=True` activation replaced with argv lists.
- Upgrading pip via `pip.exe` (fails on Windows) — all pip work now goes through the env's interpreter.

### Changed / added
- uv backend with automatic Python download; stdlib venv + pip fallback; Python discovery via uv,
  `py -0p` or PATH.
- Real dependency-conflict check (`pip check` / `uv pip check`) replaces the static conflict table.
- Scanner resolves via `packages_distributions()`, reads PEP 621 / PEP 735 declarations, prunes venvs,
  reports undeclared/unused deps; JSON project config (`envwarden.json`).
- Moved/copied venv detection in health checks.
- Snapshot store with restore, delete and preview; unpinned templates; temp-env purge.
- Hash-chained audit log viewer with chain verification; headless CLI.
- Design system: Obsidian/Panel/Teal palette, JetBrains Mono, flat zero-radius controls.
- Removed: PyPI HTML scraping (blocked by PyPI and unsupported), hard-coded conflict/CVE tables.
