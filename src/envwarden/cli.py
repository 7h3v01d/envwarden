# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
r"""Headless CLI over the same core (handy for scripts, CI and TerminalX panes).

    python -m envwarden list
    python -m envwarden create NAME [--python 3.12] [--template T]
    python -m envwarden scan NAME PROJECT_DIR
    python -m envwarden vulns NAME
    python -m envwarden snapshot NAME
    python -m envwarden verify-audit
    python -m envwarden workspace add C:\dev      (also: workspace list / workspace remove PATH)
    python -m envwarden discover                  find project venvs, register them in place
    python -m envwarden projects [--missing]      projects and their venvs
    python -m envwarden init PROJECT_DIR [--python 3.12] [--sync]   create PROJECT/.venv unless one exists
    python -m envwarden recreate NAME [--python 3.13]   rebuild at its own path (optionally on another Python)
    python -m envwarden drift [NAME]              lock/requirements vs installed; exit 1 when drifted
    python -m envwarden sync NAME                 sync a project venv from its lock / requirements
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import EnvManager


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="envwarden", description="Governed virtual-environment manager")
    ap.add_argument("--version", action="version", version=f"EnvWarden {__version__}")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    c = sub.add_parser("create")
    c.add_argument("name")
    c.add_argument("--python", default="")
    c.add_argument("--template", default="")
    c.add_argument("--project", default="")
    s = sub.add_parser("scan")
    s.add_argument("name")
    s.add_argument("project_dir")
    v = sub.add_parser("vulns")
    v.add_argument("name")
    sn = sub.add_parser("snapshot")
    sn.add_argument("name")
    sub.add_parser("verify-audit")
    w = sub.add_parser("workspace")
    w.add_argument("action", choices=["add", "remove", "list"])
    w.add_argument("path", nargs="?", default="")
    sub.add_parser("discover")
    pr = sub.add_parser("projects")
    pr.add_argument("--missing", action="store_true", help="only projects without a venv")
    ini = sub.add_parser("init")
    ini.add_argument("project_dir")
    ini.add_argument("--python", default="")
    ini.add_argument("--venv-dir", default=".venv")
    ini.add_argument("--sync", action="store_true")
    ini.add_argument("--trust", action="store_true", help="trust the project's build code (needed on first sync)")
    rc = sub.add_parser("recreate")
    rc.add_argument("name")
    rc.add_argument("--python", default="")
    dr = sub.add_parser("drift")
    dr.add_argument("name", nargs="?", default="")
    sy = sub.add_parser("sync")
    sy.add_argument("name")
    sy.add_argument("--trust", action="store_true", help="trust the project's build code (needed on first sync)")
    args = ap.parse_args(argv)

    mgr = EnvManager()
    if args.cmd == "list":
        envs = mgr.inventory(with_size=False)
        if args.json:
            print(json.dumps([{"name": e.name, "path": e.path, "python": e.python_version, "health": e.health,
                               "packages": len(e.packages), "managed": e.managed} for e in envs], indent=2))
        else:
            for e in envs:
                print(f"{e.health.upper():<5} {e.name:<28} py{e.python_version:<9} {len(e.packages):>4} pkgs  {e.path}")
        return 0
    if args.cmd == "workspace":
        if args.action == "list":
            print("\n".join(mgr.workspaces()) or "(no workspaces)")
            return 0
        if not args.path:
            ap.error("workspace add/remove needs a PATH")
        res = mgr.add_workspace(args.path) if args.action == "add" else mgr.remove_workspace(args.path)
    elif args.cmd == "discover":
        res = mgr.discover()
    elif args.cmd == "projects":
        snap = mgr.projects()
        rows = [p for p in snap.get("projects", []) if not args.missing or not p.get("venvs")]
        if args.json:
            print(json.dumps(rows, indent=2))
        else:
            for p in rows:
                venvs = ", ".join(f"{v['path']}" + (f" [{v['env']}]" if v.get("env") else "") for v in p["venvs"])
                print(f"{'NO VENV' if not p['venvs'] else 'VENV':<8} {p['name']:<28} {venvs or p['path']}")
            print(f"\n{len(rows)} project(s) · last scan {snap.get('scanned', 'never')}")
        return 0
    elif args.cmd == "init":
        res = mgr.create_in_project(args.project_dir, args.python, args.venv_dir, sync=args.sync, trust=args.trust)
    elif args.cmd == "recreate":
        res = mgr.recreate(args.name, args.python)
    elif args.cmd == "sync":
        res = mgr.sync_project(args.name, trust=args.trust)
        if not res.ok and (res.data or {}).get("needs_trust"):
            print(res.message + "\n\nRe-run with --trust to continue.")
            return 3
    elif args.cmd == "drift":
        infos = mgr.inventory(with_size=False)
        if args.name:
            infos = [i for i in infos if i.name == args.name]
            if not infos:
                print(f"No environment named '{args.name}'.")
                return 2
        drifts = mgr.drift_all(infos)
        bad = {n: d for n, d in drifts.items() if d.drifted or d.stale}
        if args.json:
            print(json.dumps({n: {"status": d.status, "source": d.source.kind if d.source else None,
                                  "missing": d.missing, "mismatched": d.mismatched, "extra": d.extra,
                                  "stale": d.stale} for n, d in drifts.items()}, indent=2))
        elif args.name and args.name in drifts:
            print(drifts[args.name].describe())
        else:
            for n, d in sorted(drifts.items()):
                print(f"{d.status:<24} {n:<28} {d.source.kind if d.source else '-'}")
            print(f"\n{len(bad)} of {len(drifts)} project env(s) drifted.")
        return 1 if bad else 0
    elif args.cmd == "create":
        res = mgr.create(args.name, args.python, args.template, args.project)
    elif args.cmd == "scan":
        res = mgr.scan(args.name, args.project_dir)
    elif args.cmd == "vulns":
        res = mgr.security_audit(args.name)
        if res.ok and res.data:
            for f in res.data.findings:
                print(f"{f.package}=={f.version}  {f.headline_id}  {f.severity or '-'}  fixed: {', '.join(f.fixed_in) or 'none'}")
    elif args.cmd == "snapshot":
        res = mgr.snapshot(args.name)
    else:
        vr = mgr.audit.verify()
        print(f"{'INTACT' if vr.ok else 'BROKEN'}  records={vr.records}  {vr.reason}")
        return 0 if vr.ok else 2
    print(res.message)
    return 0 if res.ok else 1


def _entry() -> None:
    sys.exit(main(sys.argv[1:]))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
