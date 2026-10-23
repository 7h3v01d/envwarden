# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Leon Priest (GitHub: 7h3v01d)
"""Append-only, hash-chained audit log (JSON Lines).

Each record carries ``seq``, ``prev`` (hash of the previous record) and
``hash`` (SHA-256 of the record's canonical JSON without ``hash``).
Editing, deleting or reordering a line without recomputing the rest of the
chain is detected by :meth:`AuditLog.verify`.

Threat model: this is TAMPER-EVIDENT, not tamper-resistant. There is no secret
key, so anyone with write access to this user's files can rewrite the whole
chain consistently. It reliably catches accidental damage, partial edits,
truncation and concurrent-writer corruption — not a deliberate local attacker.

Writers in different processes (GUI + CLI, two GUIs) are serialised with an
inter-process file lock, and the chain tail is re-read under that lock before
every append, so concurrent writers cannot fork the chain.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .filelock import InterProcessLock

GENESIS = "0" * 64


def _digest(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records: int
    first_bad_seq: int | None = None
    reason: str = ""


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._iplock = InterProcessLock(path.with_name(path.name + ".lock"))
        self._seq, self._last = self._load_tail()

    def _load_tail(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last_line = ""
        with open(self.path, "rb") as fh:  # scan backwards from the end: cost independent of log size
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            buf = b""
            while pos > 0:
                step = min(64 * 1024, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
                body = buf.rstrip(b"\r\n \t")
                nl = body.rfind(b"\n")
                if nl != -1 or pos == 0:
                    last_line = body[nl + 1:].decode("utf-8", "replace")
                    break
        if not last_line:
            return 0, GENESIS
        try:
            rec = json.loads(last_line)
            return int(rec["seq"]), str(rec["hash"])
        except (ValueError, KeyError, TypeError):
            # A corrupt tail is reported by verify(); keep appending after it
            # so new events are not lost, but chain from a sentinel.
            return -1, "corrupt-tail"

    def record(self, event: str, status: str, detail: str = "", **context: Any) -> dict[str, Any]:
        with self._lock, self._iplock:
            # another process may have appended since we last looked: always chain from the real tail
            self._seq, self._last = self._load_tail()
            seq = self._seq + 1 if self._seq >= 0 else 1
            rec: dict[str, Any] = {
                "seq": seq,
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "event": event,
                "status": status,
                "detail": detail,
                "context": context,
                "prev": self._last,
            }
            rec["hash"] = _digest(rec)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._seq, self._last = seq, rec["hash"]
            return rec

    def tail(self, limit: int = 400) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except ValueError:
                out.append({"event": "UNPARSEABLE", "status": "corrupt", "detail": line[:200]})
        return out

    def verify(self) -> VerifyResult:
        if not self.path.exists():
            return VerifyResult(True, 0)
        prev = GENESIS
        expected_seq = 1
        count = 0
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    return VerifyResult(False, count, expected_seq, "unparseable line")
                if rec.get("seq") != expected_seq:
                    return VerifyResult(False, count, expected_seq, "sequence gap or reorder")
                if rec.get("prev") != prev:
                    return VerifyResult(False, count, expected_seq, "previous-hash mismatch")
                if rec.get("hash") != _digest(rec):
                    return VerifyResult(False, count, expected_seq, "record hash mismatch (edited)")
                prev = rec["hash"]
                expected_seq += 1
                count += 1
        return VerifyResult(True, count)
