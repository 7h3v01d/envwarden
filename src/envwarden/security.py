# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Vulnerability audit against the OSV.dev database (no extra dependencies).

OSV matches the *exact installed version* server-side, so a package is only
reported when that version is actually affected — unlike the old hard-coded
table, which flagged every installed copy of e.g. pip regardless of version.
Only package names and versions are sent; nothing else leaves the machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import netio
from .versions import normalize

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
BATCH_SIZE = 500


@dataclass
class Finding:
    package: str
    version: str
    vuln_id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    severity: str = ""
    fixed_in: list[str] = field(default_factory=list)

    @property
    def headline_id(self) -> str:
        cves = [a for a in self.aliases if a.startswith("CVE-")]
        return cves[0] if cves else self.vuln_id


@dataclass
class AuditReport:
    queried: int
    findings: list[Finding]
    errors: list[str]

    @property
    def vulnerable_packages(self) -> list[str]:
        return sorted({f.package for f in self.findings}, key=str.lower)


def _first_line(text: str, limit: int = 240) -> str:
    lines = [ln.strip() for ln in str(text).strip().splitlines() if ln.strip()]
    return lines[0][:limit] if lines else ""


def _severity(vuln: dict[str, Any]) -> str:
    sev = (vuln.get("database_specific") or {}).get("severity")
    if sev:
        return str(sev).upper()
    for item in vuln.get("severity") or []:
        if item.get("score"):
            return f"{item.get('type', '')} {item['score']}".strip()
    return ""


def _fixed_versions(vuln: dict[str, Any], package: str) -> list[str]:
    fixed: list[str] = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != "PyPI" or normalize(pkg.get("name", "")) != normalize(package):
            continue
        for rng in aff.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event and event["fixed"] not in fixed:
                    fixed.append(event["fixed"])
    return fixed


def audit(packages: dict[str, str], detail_limit: int = 100) -> AuditReport:
    items = sorted(packages.items(), key=lambda kv: kv[0].lower())
    hits: list[tuple[str, str, str]] = []
    errors: list[str] = []
    for start in range(0, len(items), BATCH_SIZE):
        chunk = items[start:start + BATCH_SIZE]
        payload = {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in chunk]}
        try:
            resp = netio.http_json(OSV_BATCH, payload)
        except netio.NetError as exc:
            errors.append(str(exc))
            continue
        results = resp.get("results", []) if isinstance(resp, dict) else []
        if len(results) != len(chunk):
            errors.append(f"OSV returned {len(results)} results for {len(chunk)} queries; audit incomplete")
        for (name, version), result in zip(chunk, results, strict=False):
            for vuln in (result or {}).get("vulns") or []:
                if vuln.get("id"):
                    hits.append((name, version, vuln["id"]))

    findings: list[Finding] = []
    cache: dict[str, dict[str, Any]] = {}
    for idx, (name, version, vid) in enumerate(hits):
        detail: dict[str, Any] = {}
        if idx < detail_limit:
            if vid not in cache:
                try:
                    cache[vid] = netio.http_json(OSV_VULN.format(vid))
                except netio.NetError as exc:
                    errors.append(f"{vid}: {exc}")
                    cache[vid] = {}
            detail = cache[vid]
        findings.append(Finding(
            package=name,
            version=version,
            vuln_id=vid,
            aliases=list(detail.get("aliases") or []),
            summary=_first_line(detail.get("summary") or detail.get("details") or ""),
            severity=_severity(detail),
            fixed_in=_fixed_versions(detail, name),
        ))
    return AuditReport(queried=len(items), findings=findings, errors=errors)
