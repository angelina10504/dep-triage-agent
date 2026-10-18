"""Web side state in triage.db: graph runs, background jobs (with live progress lines),
approval decisions (who / when / after seeing the risk) and CI failure diagnoses.

Jobs run one at a time in a background thread. Every call opens its own connection
(SQLite file or Postgres URL), so nothing is shared between threads.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from typing import Callable

from ..db import Database, Row, connect

_SCHEMA = """
CREATE TABLE IF NOT EXISTS web_runs (
    thread_id   TEXT PRIMARY KEY,
    repo        TEXT NOT NULL,
    path        TEXT NOT NULL,
    dry_run     INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL,          -- running | awaiting_approval | done | error | interrupted
    started_by  TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    snapshot    TEXT,                   -- JSON: plans, matches, risks, prs, ci, diagnoses...
    interrupt   TEXT,                   -- JSON: the pending human_approval payload
    error       TEXT
);
CREATE TABLE IF NOT EXISTS web_jobs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,          -- scan | resume | refresh
    thread_id   TEXT,
    status      TEXT NOT NULL,          -- running | done | error | interrupted
    started_by  TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    error       TEXT
);
CREATE TABLE IF NOT EXISTS web_job_lines (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id  INTEGER NOT NULL,
    at      TEXT NOT NULL,
    line    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS web_decisions (
    thread_id     TEXT NOT NULL,
    key           TEXT NOT NULL,
    package       TEXT NOT NULL,
    decision      TEXT NOT NULL,        -- approved | rejected
    decided_by    TEXT NOT NULL,
    decided_at    TEXT NOT NULL,
    risk_shown_at TEXT,
    PRIMARY KEY (thread_id, key)
);
CREATE TABLE IF NOT EXISTS web_diagnoses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    repo        TEXT NOT NULL,
    pr_number   INTEGER NOT NULL,
    data        TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
"""


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Busy(RuntimeError):
    """Another job is still running."""


class RunStore:
    def __init__(self, path: str):
        self.path = path
        db = self._db()
        try:
            db.script(_SCHEMA)
        finally:
            db.close()

    def _db(self) -> Database:
        return connect(self.path)

    def _q(self, sql: str, args: tuple = ()) -> list[Row]:
        db = self._db()
        try:
            rows = db.execute(sql, args).fetchall()
            db.commit()
            return rows
        finally:
            db.close()

    def _x(self, sql: str, args: tuple = ()) -> int:
        """Run one write; returns the row count (or the id, for INSERT ... RETURNING id)."""
        db = self._db()
        try:
            cur = db.execute(sql, args)
            out = cur.fetchone()[0] if " RETURNING " in sql else cur.rowcount
            db.commit()
            return out
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    # ---------- runs ----------
    def new_run(self, thread_id: str, repo: str, path: str, dry_run: bool, by: str) -> None:
        t = now()
        self._x("INSERT INTO web_runs (thread_id, repo, path, dry_run, status, started_by, started_at, updated_at)"
                " VALUES (?, ?, ?, ?, 'running', ?, ?, ?)", (thread_id, repo, path, int(dry_run), by, t, t))

    def set_run(self, thread_id: str, status: str, snapshot: dict | None = None,
                interrupt: dict | None = None, error: str | None = None) -> None:
        self._x("UPDATE web_runs SET status = ?, updated_at = ?, snapshot = COALESCE(?, snapshot),"
                " interrupt = ?, error = ? WHERE thread_id = ?",
                (status, now(), json.dumps(snapshot) if snapshot is not None else None,
                 json.dumps(interrupt) if interrupt is not None else None, error, thread_id))

    def run(self, thread_id: str) -> dict | None:
        rows = self._q("SELECT * FROM web_runs WHERE thread_id = ?", (thread_id,))
        return _run(rows[0]) if rows else None

    def runs(self, limit: int = 20) -> list[dict]:
        return [_run(r) for r in self._q("SELECT * FROM web_runs ORDER BY started_at DESC, thread_id DESC LIMIT ?", (limit,))]

    def awaiting(self) -> list[dict]:
        return [_run(r) for r in self._q("SELECT * FROM web_runs WHERE status = 'awaiting_approval' ORDER BY started_at")]

    # ---------- jobs ----------
    def new_job(self, kind: str, thread_id: str | None, by: str) -> int:
        return self._x("INSERT INTO web_jobs (kind, thread_id, status, started_by, started_at)"
                       " VALUES (?, ?, 'running', ?, ?) RETURNING id",
                       (kind, thread_id, by, now()))

    def finish_job(self, job_id: int, status: str, error: str | None = None) -> None:
        self._x("UPDATE web_jobs SET status = ?, finished_at = ?, error = ? WHERE id = ?", (status, now(), error, job_id))

    def add_line(self, job_id: int, line: str) -> None:
        self._x("INSERT INTO web_job_lines (job_id, at, line) VALUES (?, ?, ?)", (job_id, now(), line))

    def job(self, job_id: int) -> dict | None:
        rows = self._q("SELECT * FROM web_jobs WHERE id = ?", (job_id,))
        if not rows:
            return None
        lines = self._q("SELECT at, line FROM web_job_lines WHERE job_id = ? ORDER BY id", (job_id,))
        return {**dict(rows[0]), "lines": [dict(r) for r in lines]}

    def jobs(self, limit: int = 10) -> list[dict]:
        return [dict(r) for r in self._q("SELECT * FROM web_jobs ORDER BY id DESC LIMIT ?", (limit,))]

    def mark_stale(self) -> None:
        """At startup: nothing can still be running in a fresh process."""
        self._x("UPDATE web_jobs SET status = 'interrupted', finished_at = ?, error = 'server restarted'"
                " WHERE status = 'running'", (now(),))
        self._x("UPDATE web_runs SET status = 'interrupted', error = 'server restarted' WHERE status = 'running'")

    # ---------- approvals ----------
    def decide(self, thread_id: str, key: str, package: str, decision: str, by: str,
               risk_shown_at: str | None) -> bool:
        """First decision wins; returns False if this proposal was already decided."""
        return self._x("INSERT INTO web_decisions VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                       (thread_id, key, package, decision, by, now(), risk_shown_at)) == 1

    def decisions(self, thread_id: str | None = None) -> list[dict]:
        if thread_id:
            rows = self._q("SELECT * FROM web_decisions WHERE thread_id = ? ORDER BY decided_at", (thread_id,))
        else:
            rows = self._q("SELECT * FROM web_decisions ORDER BY decided_at DESC")
        return [dict(r) for r in rows]

    # ---------- diagnoses ----------
    def save_diagnosis(self, repo: str, pr_number: int, data: dict) -> None:
        self._x("INSERT INTO web_diagnoses (repo, pr_number, data, created_at) VALUES (?, ?, ?, ?)",
                (repo, pr_number, json.dumps(data), now()))

    def latest_diagnoses(self, repo: str) -> dict[int, dict]:
        out: dict[int, dict] = {}
        for r in self._q("SELECT * FROM web_diagnoses WHERE repo = ? ORDER BY id", (repo,)):
            out[r["pr_number"]] = {**json.loads(r["data"]), "created_at": r["created_at"]}
        return out


def _run(row: Row) -> dict:
    d = dict(row)
    d["snapshot"] = json.loads(d["snapshot"]) if d.get("snapshot") else {}
    d["interrupt"] = json.loads(d["interrupt"]) if d.get("interrupt") else None
    return d


class JobRunner:
    """One job at a time. background=False runs jobs inline (tests)."""

    def __init__(self, store: RunStore, background: bool = True):
        self.store = store
        self.background = background
        self._lock = threading.Lock()

    @property
    def busy(self) -> bool:
        return self._lock.locked()

    def submit(self, kind: str, thread_id: str | None, by: str, fn: Callable[[Callable[[str], None]], None]) -> int:
        if not self._lock.acquire(blocking=False):
            raise Busy("another job is still running; wait for it to finish")
        try:
            job_id = self.store.new_job(kind, thread_id, by)
        except Exception:
            self._lock.release()
            raise

        def log(line: str) -> None:
            self.store.add_line(job_id, line)

        def work() -> None:
            try:
                fn(log)
                self.store.finish_job(job_id, "done")
            except Exception as e:                       # shown on the job page, never swallowed
                log(f"error: {type(e).__name__}: {str(e)[:300]}")
                self.store.finish_job(job_id, "error", f"{type(e).__name__}: {str(e)[:300]}")
            finally:
                self._lock.release()

        if self.background:
            threading.Thread(target=work, name=f"triage-job-{job_id}", daemon=True).start()
        else:
            work()
        return job_id
