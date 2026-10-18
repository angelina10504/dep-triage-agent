"""Command line:
  python -m triage path/to/requirements.txt [--json] [--explain]     scan only, no GitHub writes
  python -m triage run path/to/requirements.txt --repo owner/name    full LangGraph run (asks y/N)
  python -m triage path/to/requirements.txt --repo owner/name --open-prs   (same as run)
  python -m triage resume --thread <id>                              answer a paused approval
  python -m triage status --repo owner/name [--wait]                 PR + CI table (+ diagnosis)
  python -m triage graph [docs/graph.md]                             write the graph as Mermaid
  python -m triage web [--host 127.0.0.1] [--port 8000]              web UI (FastAPI + HTMX)
  python -m triage db-copy triage.db "$DATABASE_URL"                 copy records to another DB (e.g. Neon)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .models import PlanStatus
from .report import format_scan
from .scanner import scan


def _load_dotenv(path: str = ".env") -> None:
    """Tiny .env reader (KEY=value lines); real environment variables win."""
    f = Path(path)
    if not f.is_file():
        return
    for line in f.read_text().splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key and not key.startswith("#"):
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def _explanations(args, result) -> dict:
    """Optional LLM explanations per upgrade plan; failures are recorded, never raised."""
    from .explain import explain
    from .llm import LLMCache

    _load_dotenv()
    cache = LLMCache(args.db)
    out = {p.dependency_id: explain(p, result.matches, cache)
           for p in result.plans if p.status == PlanStatus.UPGRADE}
    print("\nExplanations (LLM - advisory text only, not used for any decision):")
    for p in result.plans:
        if p.dependency_id in out:
            e = out[p.dependency_id]
            print(f"  {p.package} -> {p.target_version} [{e.detail or e.status}]")
            for line in e.render().splitlines():
                print(f"    {line}")
    if not out:
        print("  no upgrade plans to explain")
    return out


def _runtime(args, wait: bool):
    from . import osv
    from .github_pr import GitHubClient
    from .graph import Runtime
    from .llm import LLMCache
    from .release_notes import fetch_release_notes
    from .store import ActionStore

    _load_dotenv()
    token = os.environ.get("GITHUB_TOKEN")
    return Runtime(
        store=ActionStore(args.db), cache=LLMCache(args.db),
        github=(lambda: GitHubClient(token)) if token else None,
        fetch=osv.fetch_advisories,
        notes=lambda name, cur, tgt: fetch_release_notes(name, cur, tgt, github_token=token),
        wait=wait, timeout=args.timeout, interval=args.interval)


def _ask(payload: dict) -> dict | None:
    """The human gate: y/N per proposal. None = no answer yet (run stays paused)."""
    print(f"\n{payload['question']}")
    answers = {}
    for prop in payload["proposals"]:
        print("\n--- Proposed upgrade PR ---")
        if prop["attempt"] > 1 and prop.get("previous_pr"):
            prev = prop["previous_pr"]
            print(f"(re-run: previous PR #{prev['number']} was {'merged' if prev.get('merged_at') else prev['state']}, "
                  f"but the file on the base branch still pins the vulnerable version -> new action, "
                  f"attempt {prop['attempt']})")
        print(prop["render"])
        if prop.get("risk"):
            print("Risk:   " + "\n        ".join(prop["risk"]))
        try:
            answer = input("Open this PR? [y/N] ")
        except EOFError:
            return None
        answers[prop["key"]] = answer.strip().lower() in {"y", "yes"}
    return answers


def _stream(graph, inp, config) -> None:
    """Run until the next pause/end, printing one progress line per finished node."""
    import time

    from .graph import progress
    t0 = time.monotonic()
    for update in graph.stream(inp, config, stream_mode="updates"):
        for node, value in update.items():
            line = "waiting for your y/N" if node == "__interrupt__" else progress(node, value)
            label = "human_approval" if node == "__interrupt__" else node
            print(f"  [{time.monotonic() - t0:5.1f}s] {label}: {line}", flush=True)


def _drive(graph, config, first_input, verbose: bool = False) -> int:
    """Run (or resume) until the graph finishes or waits for a human who is not there."""
    from langgraph.types import Command

    from .graph import pending_interrupt
    thread = config["configurable"]["thread_id"]
    if first_input is not None:
        print(f"thread {thread}")
        _stream(graph, first_input, config)
    while (payload := pending_interrupt(graph, config)) is not None:
        answers = _ask(payload)
        if answers is None:
            print(f"\nPaused at human_approval. Resume with: python -m triage resume --thread {thread}")
            return 0
        _stream(graph, Command(resume=answers), config)
    values = graph.get_state(config).values
    if "report_text" not in values:
        print(f"error: no run found for thread {thread}", file=sys.stderr)
        return 1
    print(values["report_verbose" if verbose and "report_verbose" in values else "report_text"])
    print(f"\n(thread {thread})")
    return 0


def _run(argv: list[str], resume: bool = False) -> int:
    from datetime import datetime, timezone

    from .graph import build_graph, sqlite_checkpointer

    ap = argparse.ArgumentParser(prog=f"python -m triage {'resume' if resume else 'run'}",
                                 description="Full agent run as a LangGraph graph (pauses for y/N approval).")
    if not resume:
        ap.add_argument("requirements", nargs="?",
                        help="local requirements.txt (optional with --repo: default is the file on the repo's base branch)")
        ap.add_argument("--repo", help="GitHub repo owner/name (without it: scan + risk only)")
        ap.add_argument("--path", default="requirements.txt", help="dependency file path inside the repo")
        ap.add_argument("--base", help="base branch (default: the repo's default branch)")
    ap.add_argument("--thread", required=resume, help="thread id (resume a paused run with the same id)")
    ap.add_argument("--db", default="triage.db",
                    help="SQLite file or postgres:// URL: approved actions, CI history, runs, LLM cache")
    ap.add_argument("--checkpoints", default="checkpoints.db",
                    help="SQLite file or postgres:// URL for LangGraph checkpoints")
    ap.add_argument("--no-wait", action="store_true", help="observe CI once instead of waiting for a result")
    ap.add_argument("--timeout", type=float, default=600, help="seconds to wait for CI at most")
    ap.add_argument("--interval", type=float, default=15, help="seconds between CI polls")
    ap.add_argument("--verbose", action="store_true", help="full report: every advisory decision, all evidence")
    if not resume:
        ap.add_argument("--dry-run", action="store_true",
                        help="read the repo for repo-aware risk, but propose and open nothing")
    args = ap.parse_args(argv)
    if not resume and not args.requirements and not args.repo:
        ap.error("give a local requirements file, or --repo owner/name to read it from GitHub")

    thread = args.thread or f"triage-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}"
    graph = build_graph(_runtime(args, wait=not args.no_wait), sqlite_checkpointer(args.checkpoints))
    config = {"configurable": {"thread_id": thread}}
    first = None if resume else {"requirements_path": args.requirements or None, "repo": args.repo,
                                 "base": args.base, "path": args.path, "dry_run": args.dry_run}
    return _drive(graph, config, first, verbose=args.verbose)


def _graph_doc(argv: list[str]) -> int:
    from .graph import Runtime, build_graph, mermaid

    out = Path(argv[0] if argv else "docs/graph.md")
    g = build_graph(Runtime(store=None, cache=None))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "# Agent graph (LangGraph)\n\n"
        "Generated by `python -m triage graph`. `human_approval` pauses the run (interrupt) until a "
        "human answers y/N; state is checkpointed in SQLite, so a paused run resumes by thread id. "
        "`diagnose_failure` only runs when an upgrade PR's CI is failing.\n\n"
        f"```mermaid\n{mermaid(g).strip()}\n```\n")
    print(f"wrote {out}")
    return 0


def _status(argv: list[str]) -> int:
    from .ci_watch import render_table, watch
    from .github_pr import GitHubClient, GitHubError
    from .store import ActionStore

    ap = argparse.ArgumentParser(prog="python -m triage status",
                                 description="Show PR and CI status for every recorded upgrade PR.")
    ap.add_argument("--repo", required=True, help="GitHub repo owner/name")
    ap.add_argument("--db", default="triage.db", help="SQLite file or postgres:// URL recording approved actions")
    ap.add_argument("--wait", action="store_true", help="poll until no PR has pending CI")
    ap.add_argument("--timeout", type=float, default=600, help="seconds to wait at most (with --wait)")
    ap.add_argument("--interval", type=float, default=15, help="seconds between polls (with --wait)")
    ap.add_argument("--no-diagnose", action="store_true", help="skip the CI failure diagnosis")
    ap.add_argument("--verbose", action="store_true", help="also list every advisory ID per PR")
    args = ap.parse_args(argv)

    _load_dotenv()
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN is not set (put it in .env).", file=sys.stderr)
        return 2
    store = ActionStore(args.db)
    if not store.with_prs(args.repo):
        print(f"No upgrade PRs recorded for {args.repo} in {args.db}.")
        return 0
    client = GitHubClient(token)
    try:
        statuses, timed_out = watch(args.repo, client, store, wait=args.wait,
                                    timeout=args.timeout, interval=args.interval)
    except GitHubError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    extra = {}
    if not args.no_diagnose:
        from .diagnose import diagnose_failure, render_diagnosis
        from .llm import LLMCache, llm_budget
        cache = LLMCache(args.db)
        failing = [st for st in statuses if st.pr_state == "open" and st.ci_status == "failing"]
        with llm_budget(30):
            for st in failing:
                r = st.record
                current = r.dependency_id.split("@", 1)[1].split("#", 1)[0]
                extra[r.pr_number] = render_diagnosis(diagnose_failure(
                    args.repo, r.pr_number, r.package or r.dependency_id, current, r.target_version,
                    [c.__dict__ for c in st.checks], client, cache))
    print(render_table(statuses, extra, verbose=args.verbose))
    if timed_out:
        print(f"\nTimed out after {args.timeout:.0f}s; pending CI is still pending (not passing).")
    return 0


def _web(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m triage web",
                                 description="Web triage table with approve buttons. Viewing is public; "
                                             "Run scan / Approve / Refresh need APP_PASSWORD from .env.")
    ap.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"),
                    help="bind address (0.0.0.0 to serve other machines)")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    args = ap.parse_args(argv)
    _load_dotenv()
    import uvicorn

    from .web.app import WebConfig, create_app
    cfg = WebConfig.from_env()
    if not cfg.password:
        print("warning: APP_PASSWORD is not set; the UI is read-only (nobody can scan, approve or refresh).",
              file=sys.stderr)
    if not cfg.secret:
        print("note: APP_SECRET is not set; logins are lost when the server restarts.", file=sys.stderr)
    from .db import is_postgres
    if not is_postgres(cfg.db):
        print(f"note: DATABASE_URL is not set; state is in the local SQLite file {cfg.db} "
              "(lost on hosts that wipe the disk on restart).", file=sys.stderr)
    print(f"Triage web UI for {cfg.repo}: http://{'localhost' if args.host in ('127.0.0.1', '0.0.0.0') else args.host}:{args.port}/")
    # Behind the host's proxy (Render): trust X-Forwarded-For/-Proto so the login rate limit sees the
    # real client IP. Locally only 127.0.0.1 is trusted.
    uvicorn.run(create_app(cfg), host=args.host, port=args.port, proxy_headers=True,
                forwarded_allow_ips=os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1"), log_level="info")
    return 0


def _db_copy(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="python -m triage db-copy",
                                 description="Copy PR/CI/run records between databases (skips rows already there).")
    ap.add_argument("source", help="SQLite file or postgres:// URL")
    ap.add_argument("target", help="SQLite file or postgres:// URL")
    args = ap.parse_args(argv)
    from .dbcopy import copy
    copy(args.source, args.target)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["db-copy"]:
        return _db_copy(argv[1:])
    if argv[:1] == ["web"]:
        return _web(argv[1:])
    if argv[:1] == ["status"]:
        return _status(argv[1:])
    if argv[:1] == ["run"]:
        return _run(argv[1:])
    if argv[:1] == ["resume"]:
        return _run(argv[1:], resume=True)
    if argv[:1] == ["graph"]:
        return _graph_doc(argv[1:])
    ap = argparse.ArgumentParser(description="Scan a requirements.txt against OSV advisories.")
    ap.add_argument("requirements", help="path to requirements.txt")
    ap.add_argument("--json", action="store_true", help="print the full result as JSON (all evidence)")
    ap.add_argument("--repo", help="GitHub repo owner/name to open upgrade PRs against")
    ap.add_argument("--path", default="requirements.txt", help="dependency file path inside the repo")
    ap.add_argument("--base", help="base branch (default: the repo's default branch)")
    ap.add_argument("--db", default="triage.db", help="SQLite file or postgres:// URL recording approved actions")
    ap.add_argument("--open-prs", action="store_true",
                    help="full agent run (same as 'run'): risk, y/N approval, PRs, CI, diagnosis")
    ap.add_argument("--thread", help="with --open-prs: thread id for the run")
    ap.add_argument("--no-wait", action="store_true", help="with --open-prs: observe CI once")
    ap.add_argument("--verbose", action="store_true", help="every per-advisory decision and TC2 detail")
    ap.add_argument("--dry-run", action="store_true", help="with --open-prs: propose and open nothing")
    ap.add_argument("--explain", action="store_true",
                    help="add LLM explanations (LLM_PROVIDER, default groq); never affects decisions")
    args = ap.parse_args(argv)
    if args.open_prs and not args.repo:
        ap.error("--open-prs needs --repo owner/name")
    if args.open_prs:
        rest = [args.requirements, "--repo", args.repo, "--path", args.path, "--db", args.db]
        rest += (["--base", args.base] if args.base else []) + (["--thread", args.thread] if args.thread else [])
        rest += ["--no-wait"] if args.no_wait else []
        rest += (["--verbose"] if args.verbose else []) + (["--dry-run"] if args.dry_run else [])
        return _run(rest)

    with open(args.requirements) as f:
        result = scan(f.read())

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return 0

    print(format_scan(result.plans, result.matches, result.warnings, verbose=args.verbose))
    if args.explain:
        _explanations(args, result)
    return 0


def cli() -> int:
    """Entry point: expected failures become one line on stderr, not a traceback."""
    import requests

    from .github_pr import GitHubError, StaleProposal
    from .osv import AdvisorySourceError
    try:
        return main()
    except (OSError, AdvisorySourceError, GitHubError, StaleProposal, requests.RequestException) as e:
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(cli())
