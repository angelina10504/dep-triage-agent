"""Copy the agent's records from one database to another, e.g. the local triage.db to the
deployed Neon Postgres, so the deployed UI starts with the real PR / CI history.

Idempotent: rows already in the target are skipped (ON CONFLICT DO NOTHING), nothing in
the target is updated or deleted. Local web job logs and LangGraph checkpoints are not
copied (they belong to the local process).
"""
from __future__ import annotations

from .db import connect
from .llm import LLMCache
from .store import ActionStore
from .web.runs import RunStore

TABLES = ("actions", "ci_observations", "scan_runs", "llm_cache", "llm_events", "web_decisions", "web_diagnoses")
_ID_TABLES = ("ci_observations", "llm_events", "web_diagnoses")


def _ensure_schema(target: str) -> None:
    ActionStore(target).db.close()
    LLMCache(target).db.close()
    RunStore(target)


def copy(src: str, dst: str, log=print) -> dict[str, int]:
    _ensure_schema(src)                     # also migrates an old source DB (adds missing columns)
    _ensure_schema(dst)
    a, b = connect(src), connect(dst)
    counts: dict[str, int] = {}
    try:
        for table in TABLES:
            cols = sorted(a.columns(table) & b.columns(table))
            rows = a.execute(f"SELECT {', '.join(cols)} FROM {table}").fetchall()
            n = 0
            for r in rows:
                cur = b.execute(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})"
                                " ON CONFLICT DO NOTHING", [r[c] for c in cols])
                n += max(cur.rowcount, 0)
            if b.postgres and table in _ID_TABLES:    # explicit ids were inserted: move the id sequence past them
                b.execute(f"SELECT setval(pg_get_serial_sequence('{table}', 'id'),"
                          f" GREATEST((SELECT COALESCE(MAX(id), 0) FROM {table}), 1))")
            b.commit()
            counts[table] = n
            log(f"{table}: {n} new of {len(rows)}")
    finally:
        a.close()
        b.close()
    return counts
