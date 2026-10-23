# EnvWarden

**Governed virtual-environment console for Python** — create, adopt, inspect, scan, audit and snapshot
virtualenvs from one PyQt6 desktop app, with a tamper-evident audit trail of every change.

Author: Leon Priest · GitHub [7h3v01d](https://github.com/7h3v01d) · Apache-2.0

## Highlights

- **Project-local venvs are first-class.** Add workspace folders (e.g. `C:\dev`) and EnvWarden finds every
  project and the venv living inside it (`.venv`, `venv`, `env`, `venv311`, …), registers it *in place*,
  and lists the projects that have **no** venv yet. It never builds a second venv for a project that
  already has one. From the PROJECTS tab you can create `.venv` inside a project, sync its dependencies
  (`requirements.txt`, else editable `pyproject.toml`/`setup.py`), recreate a broken one in place, or
  delete just the venv folder (project files are never touched).

- **Lock files and drift.** Each project's DRIFT column compares what the project declares against what
  its venv actually has — from `uv.lock`, `pylock.toml` (PEP 751), `requirements.txt` or `pyproject.toml`,
  in that order — evaluating markers such as `sys_platform == 'win32'` against *that* venv. Sync installs
  exactly from the lock (`uv sync --frozen` into that venv / `uv pip sync pylock.toml`), takes a safety
  snapshot first, and refuses when the venv's Python doesn't satisfy `requires-python` (uv would otherwise
  silently rebuild the venv on another interpreter). Poetry and Pipenv locks are left to their tools.
- **Safe removal on Windows.** Delete and recreate first move the venv folder aside; if anything has files
  open in it, that move fails and *nothing* changes. Recreate keeps the old folder until the new venv is
  built and restores it if anything fails. Recreate can also switch to another Python version.
- **uv-first.** Uses [uv](https://docs.astral.sh/uv/) when it's on PATH (fast installs, and a missing Python
  version is fetched automatically). Falls back to stdlib `venv` + `python -m pip`.
- **Correct clone / rename / restore.** Venvs hard-code their own absolute path, so copying one leaves its
  launchers driving the original. EnvWarden rebuilds a fresh environment and reinstalls the exact pins.
- **Moved-venv detection.** Health checks flag environments whose `pip` launcher or activate script points
  at a different directory.
- **Adopt in place.** Register any existing `.venv` without moving or copying it. Deleting an adopted env
  only unregisters it.
- **Real dependency checks.** `pip check` / `uv pip check` instead of a hand-maintained conflict table.
- **Vulnerability audit via OSV.dev.** Exact installed versions are matched server-side; shows CVE/GHSA id,
  severity and fixed-in versions, with one-click "upgrade to fix". Only names + versions are sent.
- **Accurate project scan.** Imports resolved through the target env's
  `importlib.metadata.packages_distributions()`, compared against `pyproject.toml` (PEP 621 + PEP 735
  dependency groups) and `requirements*.txt` — reports missing, undeclared and unused dependencies.
- **PyPI lookup** via the JSON API with PEP 440 ordering, yanked releases excluded.
- **Safety nets that fail closed.** Wipe, upgrade-all, exact sync and recreate take a snapshot first — and
  are refused, with nothing changed, if that snapshot can't be written. Snapshots restore into a new env.
- **Deny-first governance.**
  - One mutating operation at a time *across processes*: two GUI windows, the CLI and scripts share an OS
    file lock (released automatically if a process dies). A second change gets "busy — nothing changed".
  - Destructive actions require typing the env name; the package box refuses pip options, URLs and paths.
  - Deletes: managed envs only inside the managed store; project/external venvs only when explicitly asked,
    and only if the folder is a real venv that is not a project root, home, workspace or drive root.
    Leftovers from interrupted deletes are only purged when their recorded provenance and contents prove
    they are EnvWarden's own — anything doubtful is left on disk and reported.
  - The first dependency sync of each project asks you to trust it (installing can run its build code).
- **Hash-chained audit log** (`audit.jsonl`) with a *Verify chain* button. It is **tamper-evident**: it
  detects accidental damage, truncation, partial edits and concurrent-writer corruption. It is **not**
  tamper-resistant — there is no secret key, so someone with write access to your user profile could rewrite
  the whole chain consistently.
- **Never blocks the UI** — all inspection and pip/uv work runs on QObject workers.

## Quick start (Windows)

```bat
setup.bat     :: creates .venv and installs from the hash-locked set (uv if available)
run.bat       :: launches the GUI
test.bat      :: test-suite, revert-proof harness, then a pip-backend pass
relock.bat    :: after editing pyproject.toml: re-resolve, regenerate lock + SBOM (commit all three)
```

Installs are reproducible: `requirements-lock.txt` pins every dependency — including the setuptools build
backend — with SHA-256 hashes for all platforms, and the editable install runs with `--no-build-isolation`,
so nothing unverified is downloaded. `uv.lock` is the source; `sbom.cdx.json` is a CycloneDX 1.5 SBOM of the
runtime set. CI fails if any of them is stale.

Without the .bat files:

```bat
python -m pip install --require-hashes -r requirements-lock.txt
python -m pip install --no-deps --no-build-isolation -e .
python -m envwarden
```

### Project venvs

1. PROJECTS tab → **ADD FOLDER…** → pick the folder that holds your projects. A scan runs immediately and
   on every start-up (set `"auto_discover": false` in `settings.json` to turn that off).
2. Projects with a venv show it and its health; projects without one show **— none** (tick
   *Only projects without a venv* to list just those).
3. **CREATE VENV IN PROJECT** makes `<project>\.venv` (optionally installing the project's deps).
   **RECREATE IN PLACE** (Lifecycle tab) fixes a venv that was copied/moved or whose base Python was
   upgraded: it snapshots the pins, rebuilds at the same path with the same Python, and reinstalls.

4. **DRIFT** shows *in sync*, *N drifted*, *lock stale* (pyproject changed since `uv lock`) or
   *in sync (+N extra)* — packages an exact sync would remove. Select a project to see exactly what's
   missing or at the wrong version; **SYNC DEPS** fixes it.

Scan depth defaults to 4 folders below each workspace (`"scan_depth"` in `settings.json`); heavy folders
such as `node_modules`, `.git`, `build` and `dist` are skipped, and the walk never enters a venv.

### CLI

```bat
python -m envwarden list [--json]
python -m envwarden create myenv --python 3.12
python -m envwarden scan myenv C:\dev\myproject
python -m envwarden vulns myenv
python -m envwarden snapshot myenv
python -m envwarden verify-audit
python -m envwarden workspace add C:\dev
python -m envwarden discover
python -m envwarden projects --missing
python -m envwarden init C:\dev\newtool --python 3.12 --sync
python -m envwarden recreate newtool --python 3.13
python -m envwarden drift            :: exit code 1 when any project venv has drifted
python -m envwarden sync newtool --trust   :: --trust needed on a project's first sync (exit 3 without)
```

## Where things live

| | |
|---|---|
| App home | `%LOCALAPPDATA%\EnvWarden` (Linux: `~/.local/share/envwarden`; override with `ENVWARDEN_HOME`) |
| Managed envs | `<home>\environments\<name>` |
| Metadata & history | `<home>\meta\<name>.json` (kept outside the env so envs stay pristine) |
| Adopted envs | `<home>\registry.json` |
| Snapshots | `<home>\snapshots\<env>\<stamp>\{requirements.txt,snapshot.json}` |
| Templates | `<home>\templates\<name>.txt` |
| Audit log | `<home>\audit.jsonl` |
| Settings | `<home>\settings.json` — e.g. `{"backend": "pip"}` to force the pip backend |
| Locks | `<home>\locks\mutation.lock` (+ `.holder.json`: who holds it). `"lock_timeout"` in settings (default 3 s) |
| Trusted projects | `"trusted_projects"` in `settings.json` |

Per-project scan overrides go in `envwarden.json` at the project root:

```json
{ "exclude": ["legacy", "scratch"], "package_mappings": { "cv2": "opencv-python-headless" } }
```

## Tests and CI

`.github/workflows/ci.yml` runs on every push: Windows + Linux × Python 3.11 / 3.13 × uv / pip backends,
plus lint (ruff, SPDX headers). One cell per OS also runs the live OSV.dev/PyPI checks and the revert
harness. Windows-only tests cover a venv locked by a running `python.exe`, `py`-launcher recreate and
copied-venv `.exe` launcher detection. Actions are pinned to commit SHAs.

Locally: `test.bat` (set `ENVWARDEN_NETWORK_TESTS=1` to include the live checks).


`tests/test_regressions.py` holds one test per defect fixed from the previous version (R1–R11);
`tests/test_projects.py` covers project-local venv management (P1–P8), `tests/test_safety.py`
delete/recreate safety (S1–S7), `tests/test_locks.py` lock files, drift and sync (L1–L10) and
`tests/test_hardening.py` the fixes from the 4.2.0 adversarial review (S8–S13, R12–R13, T1, N3–N4).
`tests/revert_check.py` re-introduces each defect in a temp copy and requires its test to fail —
currently 45/45 caught (R1–R13, P1–P8, S1–S13, L1–L10, T1, N3–N4). Suite runs on both uv and pip backends and on Python 3.11+.
