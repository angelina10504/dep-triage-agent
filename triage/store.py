"""Durable record of human-approved actions, so a retry never runs an action twice.

One row per (dependency_id, target_version). The row is written the moment a
human approves, and updated once the PR exists. A later run that finds a row with
a PR URL reports that PR instead of calling GitHub again.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

_SCHEMA = """
CREATE TABLE IF NOT EXISTS actions (
    dependency_id  TEXT NOT NULL,
    target_version TEXT NOT NULL,
    repo           TEXT NOT NULL,
    branch         TEXT NOT NULL,
    status         TEXT NOT NULL,      -- approved | pr_opened
    approved_by    TEXT NOT NULL,
    approved_at    TEXT NOT NULL,
    pr_number      INTEGER,
    pr_url         TEXT,
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (dependency_id, target_version)
)
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class ActionRecord:
    dependency_id: str
    target_version: str
    repo: str
    branch: str
    status: str
    approved_by: str
    approved_at: str
    pr_number: int | None
    pr_url: str | None
    updated_at: str


class ActionStore:
    def __init__(self, path: str = "triage.db"):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute(_SCHEMA)
        self.db.commit()

    def get(self, dependency_id: str, target_version: str) -> ActionRecord | None:
        row = self.db.execute(
            "SELECT * FROM actions WHERE dependency_id = ? AND target_version = ?",
            (dependency_id, target_version),
        ).fetchone()
        return ActionRecord(**dict(row)) if row else None

    def record_approval(self, dependency_id: str, target_version: str, repo: str,
                        branch: str, approved_by: str) -> ActionRecord:
        """Insert the approval once; an existing row (earlier approval) is kept as is."""
        now = _now()
        self.db.execute(
            "INSERT OR IGNORE INTO actions (dependency_id, target_version, repo, branch, status,"
            " approved_by, approved_at, updated_at) VALUES (?, ?, ?, ?, 'approved', ?, ?, ?)",
            (dependency_id, target_version, repo, branch, approved_by, now, now),
        )
        self.db.commit()
        return self.get(dependency_id, target_version)

    def record_pr(self, dependency_id: str, target_version: str, pr_number: int, pr_url: str) -> ActionRecord:
        self.db.execute(
            "UPDATE actions SET status = 'pr_opened', pr_number = ?, pr_url = ?, updated_at = ?"
            " WHERE dependency_id = ? AND target_version = ?",
            (pr_number, pr_url, _now(), dependency_id, target_version),
        )
        self.db.commit()
        return self.get(dependency_id, target_version)
