"""Append-only log of what shellbouncer blocked or flagged."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path


def log_path() -> Path:
    base = os.environ.get("SHELLBOUNCER_LOG") or os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    path = Path(base)
    return path if path.suffix == ".jsonl" else path / "shellbouncer" / "audit.jsonl"


def record(agent: str, tool: str, action: str, decision: str, reason: str, project: str) -> None:
    try:
        path = log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "agent": agent, "tool": tool, "decision": decision,
            "action": action[:500], "reason": reason[:500], "project": project,
        }
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # never break the agent because the log isn't writable


def read(limit: int = 20, include_allowed: bool = False) -> list[dict]:
    path = log_path()
    if not path.exists():
        return []
    entries = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if include_allowed or entry.get("decision") != "allow":
                entries.append(entry)
    return entries[-limit:]
