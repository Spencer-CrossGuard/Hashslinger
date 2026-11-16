"""Append-only JSONL audit log. Every run writes start and end, including failures."""
from __future__ import annotations

import getpass
import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _append(self, entry: dict) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def next_run_id(self, today: str | None = None) -> str:
        today = today or datetime.now().strftime("%Y-%m-%d")
        n = 0
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("event") == "start" and e.get("run_id", "").startswith(today + "-"):
                    n += 1
        return f"{today}-{n + 1:03d}"

    def start(self, run_id: str, trigger: str, scope: list[str], requested_by: str | None = None,
              edipi: str | None = None, reason: str | None = None) -> None:
        self._append({
            "event": "start", "run_id": run_id, "time": _now(), "trigger": trigger,
            "run_as": getpass.getuser(), "host": socket.gethostname(),
            "requested_by": requested_by, "edipi": edipi, "reason": reason, "scope": scope,
        })

    def rejected(self, why: str, edipi: str | None, reason: str | None, requested_by: str | None) -> None:
        self._append({
            "event": "rejected", "time": _now(), "run_as": getpass.getuser(),
            "host": socket.gethostname(), "why": why, "edipi": edipi, "reason": reason,
            "requested_by": requested_by,
        })

    def end(self, run_id: str, status: str, accounts_processed: int, output: str | None,
            wipe_confirmed: bool, error: str | None = None) -> None:
        self._append({
            "event": "end", "run_id": run_id, "time": _now(), "status": status,
            "accounts_processed": accounts_processed, "output": output,
            "wipe_confirmed": wipe_confirmed, "error": error,
        })
