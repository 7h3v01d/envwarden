# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""PyPI JSON API lookup.

PyPI's HTML search is behind bot protection and its XML-RPC search was
retired, so scraping is gone. Exact-name lookup via the JSON API is the
supported path. Versions are ordered by PEP 440, not string order.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import netio
from .versions import is_prerelease, version_key

NAME_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


@dataclass
class PackageInfo:
    name: str
    latest: str
    summary: str
    requires_python: str
    license: str
    urls: dict[str, str] = field(default_factory=dict)
    versions: list[str] = field(default_factory=list)  # newest first, yanked excluded
    yanked: list[str] = field(default_factory=list)

    def describe(self) -> str:
        lines = [f"Package:   {self.name}", f"Latest:    {self.latest}"]
        if self.summary:
            lines.append(f"Summary:   {self.summary}")
        if self.requires_python:
            lines.append(f"Python:    {self.requires_python}")
        if self.license:
            lines.append(f"License:   {self.license}")
        for label, url in list(self.urls.items())[:5]:
            lines.append(f"{label[:9]:<9}  {url}")
        if self.versions:
            lines.append(f"Releases:  {', '.join(self.versions[:15])}")
        if self.yanked:
            lines.append(f"Yanked:    {', '.join(self.yanked[:10])}")
        return "\n".join(lines)


def sort_versions(versions: list[str]) -> list[str]:
    return sorted(versions, key=version_key, reverse=True)


def lookup(name: str, include_pre: bool = False) -> PackageInfo:
    name = name.strip()
    if not NAME_OK.match(name):
        raise ValueError("Not a valid PyPI project name.")
    try:
        data = netio.http_json(f"https://pypi.org/pypi/{name}/json")
    except netio.NetError as exc:
        if "HTTP 404" in str(exc):
            raise LookupError(f"No project named '{name}' on PyPI.") from exc
        raise
    info = data.get("info") or {}
    releases: dict[str, list[dict]] = data.get("releases") or {}
    live, yanked = [], []
    for ver, files in releases.items():
        if files and all(f.get("yanked") for f in files):
            yanked.append(ver)
        elif files and (include_pre or not is_prerelease(ver)):
            live.append(ver)
    license_text = info.get("license_expression") or ""  # PEP 639
    if not license_text:
        raw = (info.get("license") or "").strip()
        license_text = raw.splitlines()[0][:80] if raw else ""
    urls = {k: v for k, v in (info.get("project_urls") or {}).items() if isinstance(v, str) and v.startswith("https://")}
    return PackageInfo(
        name=info.get("name") or name,
        latest=info.get("version") or "",
        summary=info.get("summary") or "",
        requires_python=info.get("requires_python") or "",
        license=license_text or "",
        urls=urls,
        versions=sort_versions(live),
        yanked=sort_versions(yanked),
    )
