# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Tiny JSON-over-HTTPS client (stdlib only). Tests monkeypatch :func:`http_json`.

* HTTPS only — including every redirect hop (urllib's default handler would
  happily follow https -> http or ftp).
* Responses are read in chunks and capped, so a misbehaving endpoint can't
  exhaust memory. PyPI's JSON for very large projects is the biggest legitimate
  payload, hence the generous default.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from . import __version__

USER_AGENT = f"EnvWarden/{__version__} (+https://github.com/7h3v01d)"
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_REDIRECTS = 5


class NetError(RuntimeError):
    pass


class HttpsOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 (stdlib signature)
        if not str(newurl).lower().startswith("https://"):
            raise NetError(f"Refused redirect away from HTTPS: {req.full_url} -> {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(HttpsOnlyRedirectHandler())


def read_capped(resp: Any, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    declared = resp.headers.get("Content-Length") if getattr(resp, "headers", None) else None
    if declared and declared.isdigit() and int(declared) > limit:
        raise NetError(f"Response too large ({int(declared):,} bytes > {limit:,})")
    chunks, total = [], 0
    while True:
        chunk = resp.read(256 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise NetError(f"Response exceeded {limit:,} bytes; aborted")
        chunks.append(chunk)
    return b"".join(chunks)


def http_json(url: str, payload: Any = None, timeout: float = 20, limit: int = MAX_RESPONSE_BYTES) -> Any:
    if not url.startswith("https://"):
        raise NetError("Only HTTPS endpoints are allowed.")
    data = None
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data else "GET")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            if not resp.geturl().lower().startswith("https://"):
                raise NetError(f"Final URL is not HTTPS: {resp.geturl()}")
            return json.loads(read_capped(resp, limit).decode("utf-8"))
    except NetError:
        raise
    except urllib.error.HTTPError as exc:
        raise NetError(f"HTTP {exc.code} from {url.split('?')[0]}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NetError(f"Network error: {getattr(exc, 'reason', exc)}") from exc
    except ValueError as exc:
        raise NetError(f"Invalid JSON from {url}") from exc
