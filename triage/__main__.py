"""Command line:
  python -m triage path/to/requirements.txt [--json]
  python -m triage path/to/requirements.txt --repo owner/name --open-prs   (asks y/N per PR)
  python -m triage status --repo owner/name [--wait --timeout 600 --interval 15]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .models import PlanStatus
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


def _open_prs(args, result) -> int:
    from .github_pr import GitHubClient, ask_approval, build_proposal, open_pr, resolve
    from .store import ActionStore

    upgrades = [p for p in result.plans if p.status == PlanStatus.UPGRADE]
    if not upgrades:            # uncertain / no_action plans never become PRs
        print("\nNo upgrade plans - no PRs proposed.")
        return 0
    _load_dotenv()
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN is not set (put it in .env). No PRs opened.", file=sys.stderr)
        return 2
    client = GitHubClient(token)
    store = ActionStore(args.db)
    base = args.base or client.default_branch(args.repo)
    deps = {d.id: d for d in result.dependencies}

    for plan in upgrades:
        p = build_proposal(plan, deps[plan.dependency_id], result.matches, args.repo, base, args.path)
        store.fill_advisories(p.dependency_id, p.target_version, p.package, p.advisories)
        res = resolve(p, client, store)
        if res.action == "reuse":
            print(f"\n{p.package}: already handled, {res.reason}: {res.pr['html_url']} (not opening another)")
            continue
        if res.action == "no_action":
            print(f"\n{p.package}: no action - {res.reason}")
            continue
        p = res.proposal
        if p.attempt > 1:
            print(f"\n{p.package}: previous PR #{res.pr['number']} was merged/closed but {p.path} on "
                  f"{p.base} still pins {p.old_line!r} -> new action, attempt {p.attempt}")
        if not ask_approval(p):
            print(f"{p.package}: not approved, nothing done.")
            continue
        r = open_pr(p, client, store)
        print(f"{p.package}: {r.outcome} -> {r.pr_url}")
    return 0


def _status(argv: list[str]) -> int:
    from .ci_watch import render_table, watch
    from .github_pr import GitHubClient, GitHubError
    from .store import ActionStore

    ap = argparse.ArgumentParser(prog="python -m triage status",
                                 description="Show PR and CI status for every recorded upgrade PR.")
    ap.add_argument("--repo", required=True, help="GitHub repo owner/name")
    ap.add_argument("--db", default="triage.db", help="SQLite file recording approved actions")
    ap.add_argument("--wait", action="store_true", help="poll until no PR has pending CI")
    ap.add_argument("--timeout", type=float, default=600, help="seconds to wait at most (with --wait)")
    ap.add_argument("--interval", type=float, default=15, help="seconds between polls (with --wait)")
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
    try:
        statuses, timed_out = watch(args.repo, GitHubClient(token), store, wait=args.wait,
                                    timeout=args.timeout, interval=args.interval)
    except GitHubError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(render_table(statuses))
    if timed_out:
        print(f"\nTimed out after {args.timeout:.0f}s; pending CI is still pending (not passing).")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["status"]:
        return _status(argv[1:])
    ap = argparse.ArgumentParser(description="Scan a requirements.txt against OSV advisories.")
    ap.add_argument("requirements", help="path to requirements.txt")
    ap.add_argument("--json", action="store_true", help="print the full result as JSON (all evidence)")
    ap.add_argument("--repo", help="GitHub repo owner/name to open upgrade PRs against")
    ap.add_argument("--path", default="requirements.txt", help="dependency file path inside the repo")
    ap.add_argument("--base", help="base branch (default: the repo's default branch)")
    ap.add_argument("--db", default="triage.db", help="SQLite file recording approved actions")
    ap.add_argument("--open-prs", action="store_true", help="propose upgrade PRs, each needs y/N approval")
    args = ap.parse_args(argv)
    if args.open_prs and not args.repo:
        ap.error("--open-prs needs --repo owner/name")

    with open(args.requirements) as f:
        result = scan(f.read())

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return 0

    print(f"\n{'PACKAGE':<14}{'CURRENT':<10}{'TARGET':<10}{'STATUS':<11}REASON")
    for p in result.plans:
        print(f"{p.package:<14}{p.current_version or '-':<10}{p.target_version or '-':<10}"
              f"{p.status.value:<11}{p.reason}")
    print("\nPer-advisory decisions (PyPI):")
    for m in result.matches:
        if m.queried_ecosystem == "PyPI":
            print(f"  [{m.decision.value:<12}] {m.dependency_id:<28} {m.advisory_id:<22} {m.reason}")
    collisions = [m for m in result.matches if m.queried_ecosystem != "PyPI"]
    print("\nSame name in other ecosystems (TC2 - not this package, never upgraded):")
    for m in collisions:
        print(f"  {m.dependency_id:<28} {m.advisory_id:<22} {m.decision.value}: {m.reason}")
    if not collisions:
        print("  none found")
    for w in result.warnings:
        print(f"  warning: {w}")
    if args.open_prs:
        return _open_prs(args, result)
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
