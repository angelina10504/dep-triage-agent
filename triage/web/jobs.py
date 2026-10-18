"""What the web buttons run in the background: a graph run, a resume after approval,
and a CI refresh. All three reuse the same graph / watcher / diagnosis code as the CLI.
"""
from __future__ import annotations

import time
from typing import Callable

from langgraph.types import Command

from ..ci_watch import watch
from ..diagnose import diagnose_failure
from ..graph import Runtime, build_graph, checkpointer, pending_interrupt, progress
from ..llm import llm_budget
from .runs import RunStore

SNAPSHOT_KEYS = ("dependencies", "plans", "matches", "warnings", "risks", "explanations", "resolutions",
                 "prs", "ci", "ci_timed_out", "diagnoses", "repo_summary", "notice", "base", "approvals")

Log = Callable[[str], None]


def _logging_sleep(log: Log, sleep: Callable[[float], None] | None) -> Callable[[float], None]:
    def s(seconds: float) -> None:
        log(f"watch_ci: CI still pending, checking again in {seconds:.0f}s")
        (sleep or time.sleep)(seconds)
    return s


def _drive(rt: Runtime, checkpoints: str, store: RunStore, thread: str, repo: str, inp, log: Log) -> None:
    rt.sleep = _logging_sleep(log, rt.sleep)
    cp = checkpointer(checkpoints)
    try:
        graph = build_graph(rt, cp)
        config = {"configurable": {"thread_id": thread}}
        t0 = time.monotonic()
        for update in graph.stream(inp, config, stream_mode="updates"):
            for node, value in update.items():
                line = "waiting for approval in the web UI" if node == "__interrupt__" else progress(node, value)
                label = "human_approval" if node == "__interrupt__" else node
                log(f"[{time.monotonic() - t0:5.1f}s] {label}: {line}")
        values = graph.get_state(config).values
        payload = pending_interrupt(graph, config)
        snapshot = {k: values.get(k) for k in SNAPSHOT_KEYS}
        store.set_run(thread, "awaiting_approval" if payload else "done", snapshot, payload)
        for n, d in (values.get("diagnoses") or {}).items():
            store.save_diagnosis(repo, int(n), d)
        log("paused: approval needed" if payload else "run finished")
    except Exception as e:
        store.set_run(thread, "error", error=f"{type(e).__name__}: {str(e)[:300]}")
        raise
    finally:
        cp.conn.close()


def scan_job(make_runtime: Callable[[], Runtime], checkpoints: str, store: RunStore, thread: str,
             repo: str, path: str, dry_run: bool) -> Callable[[Log], None]:
    """No local checkout: the graph reads the dependency file, workflows and .py files from GitHub."""
    def job(log: Log) -> None:
        _drive(make_runtime(), checkpoints, store, thread, repo,
               {"repo": repo, "path": path, "dry_run": dry_run}, log)
    return job


def resume_job(make_runtime: Callable[[], Runtime], checkpoints: str, store: RunStore, thread: str,
               repo: str, answers: dict[str, bool], approved_by: str) -> Callable[[Log], None]:
    def job(log: Log) -> None:
        rt = make_runtime()
        rt.approved_by = approved_by
        n = sum(answers.values())
        log(f"resuming {thread}: {n} approved, {len(answers) - n} rejected (by {approved_by})")
        store.set_run(thread, "running", interrupt=None)
        _drive(rt, checkpoints, store, thread, repo, Command(resume=answers), log)
    return job


def refresh_job(make_runtime: Callable[[], Runtime], store: RunStore, repo: str) -> Callable[[Log], None]:
    def job(log: Log) -> None:
        rt = make_runtime()
        if not rt.store.with_prs(repo):
            log(f"no upgrade PRs recorded for {repo}")
            return
        statuses, _ = watch(repo, rt.client(), rt.store, wait=False)
        for st in statuses:
            log(f"PR #{st.pr_number} {st.record.package}: {st.pr_state}, CI {st.ci_status} -> {st.outcome}")
        failing = [st for st in statuses if st.pr_state == "open" and st.ci_status == "failing"]
        with llm_budget(rt.llm_budget):
            for st in failing:
                r = st.record
                current = r.dependency_id.split("@", 1)[1].split("#", 1)[0]
                d = diagnose_failure(repo, r.pr_number, r.package or r.dependency_id, current, r.target_version,
                                     [c.__dict__ for c in st.checks], rt.client(), rt.cache, rt.llm)
                store.save_diagnosis(repo, r.pr_number, d)
                log(f"PR #{r.pr_number} diagnosis ({d['status']}): {d['root_cause'][:140]}")
        log("refresh finished")
    return job
