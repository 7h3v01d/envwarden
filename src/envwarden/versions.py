# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Version and package-name helpers (PEP 440 / PEP 503 / PEP 508)."""

from __future__ import annotations

import re
from typing import Any

try:  # packaging is a declared dependency, but stay functional without it
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.version import InvalidVersion, Version
except ImportError:  # pragma: no cover
    Requirement = None  # type: ignore[assignment,misc]
    Version = None  # type: ignore[assignment,misc]

_NORMALIZE = re.compile(r"[-_.]+")
_PRE = re.compile(r"(a|b|rc|alpha|beta|c|pre|preview|dev)", re.I)
_SIMPLE_REQ = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,\s-]+\])?\s*((===|==|!=|~=|<=|>=|<|>)\s*[A-Za-z0-9.*+!_-]+\s*,?\s*)*$"
)


def normalize(name: str) -> str:
    return _NORMALIZE.sub("-", name).lower().strip()


def version_key(v: str) -> Any:
    """Sort key giving PEP 440 order. Unparseable versions sort lowest."""
    if Version is not None:
        try:
            return (1, Version(v))
        except InvalidVersion:
            return (0, v)
    nums = tuple(int(x) for x in re.findall(r"\d+", v.split("+")[0])[:6])
    is_final = 0 if _PRE.search(v) else 1
    return (1, nums, is_final)


def is_prerelease(v: str) -> bool:
    if Version is not None:
        try:
            return Version(v).is_prerelease
        except InvalidVersion:
            return True
    return bool(_PRE.search(v))


def requirement_name(spec: str) -> str | None:
    """Return the project name of a PEP 508 requirement, or None if it is not one.

    Anything starting with '-' (pip options such as --index-url, -r, -e) or
    looking like a path/URL is rejected: the single-package box is deny-first.
    """
    spec = spec.strip()
    if not spec or spec.startswith("-") or any(t in spec for t in ("://", "/", "\\", "@", ";")):
        return None
    if Requirement is not None:
        try:
            req = Requirement(spec)
        except InvalidRequirement:
            return None
        if req.url:
            return None
        return req.name
    return spec.split("[")[0].split("=")[0].split("<")[0].split(">")[0].split("!")[0].split("~")[0].strip() if _SIMPLE_REQ.match(spec) else None
