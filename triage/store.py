"""Durable record of human-approved actions, so a retry never runs an action twice.

One row per (dependency_id, target_version). The row is written the moment a
human approves, and updated once the PR exists. A later run that finds a row with
a PR URL reports that PR instead of calling GitHub again.

ci_observations is append-only history from the CI watcher: every look at a PR
adds a row (intended vs observed state), nothing is overwritten.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
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
    package        TEXT,
    advisories     TEXT,               -- JSON [{"id": ..., "aliases": [...]}]
    PRIMARY KEY (dependency_id, target_version)
);
CREATE TABLE IF NOT EXISTS ci_observations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    dependency_id  TEXT NOT NULL,
    target_version TEXT NOT NULL,
    repo           TEXT NOT NULL,
    pr_number      INTEGER NOT NULL,
    pr_state       TEXT NOT NULL,      -- open | closed | merged
    merged_at      TEXT,
    head_sha       TEXT NOT NULL,
    intended_state TEXT NOT NULL,      -- what the action is meant to achieve: ci_passing
    ci_status      TEXT NOT NULL,      -- observed: passing | failing | pending | unknown
    outcome        TEXT NOT NULL,
    checks         TEXT NOT NULL,      -- JSON evidence [{"name", "kind", "state", "url"}]
    observed_at    TEXT NOT NULL
);
"""
# Columns added after the first release of the actions table.
_MIGRATIONS = {"package": "TEXT", "advisories": "TEXT"}


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
    package: str | None = None
    advisories: list[dict] = field(default_factory=list)


def _record(row: sqlite3.Row) -> ActionRecord:
    d = dict(row)
    d["advisories"] = json.loads(d["advisories"]) if d.get("advisories") else []
    return ActionRecord(**d)


class ActionStore:
    def __init__(self, path: str = "triage.db"):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(_SCHEMA)
        have = {r["name"] for r in self.db.execute("PRAGMA table_info(actions)")}
        for col, typ in _MIGRATIONS.items():
            if col not in have:
                self.db.execute(f"ALTER TABLE actions ADD COLUMN {col} {typ}")
        self.db.commit()

    def get(self, dependency_id: str, target_version: str) -> ActionRecord | None:
        row = self.db.execute(
            "SELECT * FROM actions WHERE dependency_id = ? AND target_version = ?",
            (dependency_id, target_version),
        ).fetchone()
        return _record(row) if row else None

    def with_prs(self, repo: str | None = None) -> list[ActionRecord]:
        q = "SELECT * FROM actions WHERE pr_number IS NOT NULL"
        rows = self.db.execute(q + " AND repo = ? ORDER BY pr_number" if repo else q + " ORDER BY pr_number",
                               (repo,) if repo else ())
        return [_record(r) for r in rows]

    def record_approval(self, dependency_id: str, target_version: str, repo: str,
                        branch: str, approved_by: str, package: str | None = None,
                        advisories: list[dict] | None = None) -> ActionRecord:
        """Insert the approval once; an existing row (earlier approval) is kept as is."""
        now = _now()
        self.db.execute(
            "INSERT OR IGNORE INTO actions (dependency_id, target_version, repo, branch, status,"
            " approved_by, approved_at, updated_at, package, advisories)"
            " VALUES (?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?)",
            (dependency_id, target_version, repo, branch, approved_by, now, now, package,
             json.dumps(advisories) if advisories else None),
        )
        self.db.commit()
        if advisories:
            self.fill_advisories(dependency_id, target_version, package, advisories)
        return self.get(dependency_id, target_version)

    def fill_advisories(self, dependency_id: str, target_version: str, package: str | None,
                        advisories: list[dict]) -> None:
        """Backfill advisory evidence on rows written before it was stored; never overwrite it."""
        self.db.execute(
            "UPDATE actions SET package = COALESCE(package, ?), advisories = COALESCE(advisories, ?)"
            " WHERE dependency_id = ? AND target_version = ?",
            (package, json.dumps(advisories), dependency_id, target_version),
        )
        self.db.commit()

    def record_pr(self, dependency_id: str, target_version: str, pr_number: int, pr_url: str) -> ActionRecord:
        self.db.execute(
            "UPDATE actions SET status = 'pr_opened', pr_number = ?, pr_url = ?, updated_at = ?"
            " WHERE dependency_id = ? AND target_version = ?",
            (pr_number, pr_url, _now(), dependency_id, target_version),
        )
        self.db.commit()
        return self.get(dependency_id, target_version)

    def add_observation(self, *, dependency_id: str, target_version: str, repo: str, pr_number: int,
                        pr_state: str, merged_at: str | None, head_sha: str, ci_status: str,
                        outcome: str, checks: list[dict], observed_at: str,
                        intended_state: str = "ci_passing") -> None:
        self.db.execute(
            "INSERT INTO ci_observations (dependency_id, target_version, repo, pr_number, pr_state,"
            " merged_at, head_sha, intended_state, ci_status, outcome, checks, observed_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (dependency_id, target_version, repo, pr_number, pr_state, merged_at, head_sha,
             intended_state, ci_status, outcome, json.dumps(checks), observed_at),
        )
        self.db.commit()

    def observations(self, dependency_id: str, target_version: str) -> list[dict]:
        rows = self.db.execute(
            "SELECT * FROM ci_observations WHERE dependency_id = ? AND target_version = ? ORDER BY id",
            (dependency_id, target_version),
        )
        return [{**dict(r), "checks": json.loads(r["checks"])} for r in rows]
