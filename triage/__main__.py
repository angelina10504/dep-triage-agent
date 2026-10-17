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
    from .github_pr import GitHubClient, ask_approval, build_proposal, open_pr
    from .store import ActionStore

    _load_dotenv()
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("GITHUB_TOKEN is not set (put it in .env). No PRs opened.", file=sys.stderr)
        return 2
    client = GitHubClient(token)
    store = ActionStore(args.db)
    base = args.base or client.default_branch(args.repo)
    deps = {d.id: d for d in result.dependencies}

    for plan in result.plans:
        if plan.status != PlanStatus.UPGRADE:
            continue
        p = build_proposal(plan, deps[plan.dependency_id], result.matches, args.repo, base, args.path)
        done = store.get(p.dependency_id, p.target_version)
        if done and done.pr_url:
            store.fill_advisories(p.dependency_id, p.target_version, p.package, p.advisories)
            print(f"\n{p.package}: already handled, PR {done.pr_url} (approved {done.approved_at})")
            continue
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
    print("\nPer-advisory decisions:")
    for m in result.matches:
        print(f"  [{m.decision.value:<12}] {m.dependency_id:<28} {m.advisory_id:<22} {m.reason}")
    if args.open_prs:
        return _open_prs(args, result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
