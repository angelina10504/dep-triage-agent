"""Step 05 - Verify: read the CI result on each upgrade PR, separately from the action.

The PR action only says "a PR exists". Whether the upgrade is safe is decided here,
from GitHub's check runs AND commit statuses for the PR's head commit. The watcher
never claims "fixed" or "deployed": a merged PR is reported as merged, not deployed,
because nothing here observes a deployment.

Every look is appended to ci_observations (intended: ci_passing vs observed), so the
history of pending -> passing/failing stays visible.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from .github_pr import GitHubClient
from .scanner import count_unique
from .store import ActionRecord, ActionStore

_OK = {"success", "neutral", "skipped"}
_FAIL = {"failure", "cancelled", "timed_out", "error"}               # "error" = commit-status failure
_PENDING = {"queued", "in_progress", "pending", "waiting", "requested"}

OUTCOME_PASSING = "PR open, CI passing (awaiting human merge)"
OUTCOME_FAILING = "PR failing, NOT fixed"
OUTCOME_PENDING = "waiting for CI"
OUTCOME_UNKNOWN = "PR open, no CI checks found (cannot verify)"
OUTCOME_MERGED = "merged, NOT deployed (deployment not verified)"
OUTCOME_CLOSED = "closed without merge"


@dataclass
class Check:
    name: str
    kind: str        # check_run | status
    state: str       # conclusion if completed, else the run status (queued, in_progress, pending...)
    url: str | None


@dataclass
class PrStatus:
    record: ActionRecord
    pr_state: str    # open | closed | merged
    merged_at: str | None
    head_sha: str
    ci_status: str   # passing | failing | pending | unknown
    outcome: str
    checks: list[Check] = field(default_factory=list)
    observed_at: str = ""

    @property
    def unique_vulnerabilities(self) -> int:
        return count_unique([{a["id"], *a.get("aliases", [])} for a in self.record.advisories])


def ci_status(checks: list[Check]) -> str:
    """failing beats pending beats passing; anything not clearly OK keeps it from 'passing'."""
    if not checks:
        return "unknown"
    states = {c.state for c in checks}
    if states & _FAIL:
        return "failing"
    if states & _PENDING:
        return "pending"
    if states <= _OK:
        return "passing"
    return "unknown"    # e.g. action_required / stale: not evidence of success


def outcome(pr_state: str, ci: str) -> str:
    if pr_state == "merged":
        return OUTCOME_MERGED
    if pr_state == "closed":
        return OUTCOME_CLOSED
    return {"passing": OUTCOME_PASSING, "failing": OUTCOME_FAILING,
            "pending": OUTCOME_PENDING}.get(ci, OUTCOME_UNKNOWN)


def _checks(client: GitHubClient, repo: str, sha: str) -> list[Check]:
    runs = client.get(f"/repos/{repo}/commits/{sha}/check-runs", per_page=100)
    combined = client.get(f"/repos/{repo}/commits/{sha}/status", per_page=100)
    out = [Check(r["name"], "check_run",
                 r["conclusion"] if r.get("status") == "completed" and r.get("conclusion") else r["status"],
                 r.get("html_url"))
           for r in runs.get("check_runs", [])]
    out += [Check(s["context"], "status", s["state"], s.get("target_url"))
            for s in combined.get("statuses", [])]
    return out


def observe(record: ActionRecord, client: GitHubClient, store: ActionStore) -> PrStatus:
    pr = client.get(f"/repos/{record.repo}/pulls/{record.pr_number}")
    pr_state = "merged" if pr.get("merged") else pr["state"]
    sha = pr["head"]["sha"]
    checks = _checks(client, record.repo, sha)
    ci = ci_status(checks)
    st = PrStatus(record, pr_state, pr.get("merged_at"), sha, ci, outcome(pr_state, ci), checks,
                  datetime.now(timezone.utc).isoformat(timespec="seconds"))
    store.add_observation(
        dependency_id=record.dependency_id, target_version=record.target_version, repo=record.repo,
        pr_number=record.pr_number, pr_state=pr_state, merged_at=st.merged_at, head_sha=sha,
        ci_status=ci, outcome=st.outcome, checks=[c.__dict__ for c in checks], observed_at=st.observed_at)
    return st


def watch(repo: str, client: GitHubClient, store: ActionStore, wait: bool = False,
          timeout: float = 600, interval: float = 15,
          sleep: Callable[[float], None] = time.sleep,
          clock: Callable[[], float] = time.monotonic) -> tuple[list[PrStatus], bool]:
    """Observe every recorded PR. With wait, poll until none is pending or timeout.

    Returns (statuses, timed_out). Only PRs still open with pending CI are re-polled.
    """
    records = store.with_prs(repo)
    latest = {r.pr_number: observe(r, client, store) for r in records}
    deadline = clock() + timeout
    while wait:
        pending = [s for s in latest.values() if s.pr_state == "open" and s.ci_status == "pending"]
        if not pending:
            break
        if clock() + interval > deadline:
            return list(latest.values()), True
        sleep(interval)
        for s in pending:
            latest[s.record.pr_number] = observe(s.record, client, store)
    return list(latest.values()), False


def render_table(statuses: list[PrStatus]) -> str:
    rows = [("PACKAGE", "ADVISORIES", "PR", "PR STATE", "CI", "OUTCOME")]
    for s in statuses:
        r = s.record
        adv = (f"{s.unique_vulnerabilities} vulns ({len(r.advisories)} records)"
               if r.advisories else "not recorded")
        rows.append((f"{r.package or r.dependency_id} -> {r.target_version}", adv, r.pr_url or "-",
                     s.pr_state, s.ci_status, s.outcome))
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]) - 1)]
    lines = ["  ".join(c.ljust(w) for c, w in zip(row[:-1], widths)) + "  " + row[-1] for row in rows]

    lines.append("\nEvidence:")
    for s in statuses:
        r = s.record
        lines.append(f"  {r.package or r.dependency_id} PR #{r.pr_number} @ {s.head_sha[:7]} "
                     f"(observed {s.observed_at}; intended: CI passing, observed: {s.ci_status})")
        if r.advisories:
            lines.append(f"    advisories: {', '.join(a['id'] for a in r.advisories)}")
        for c in s.checks or []:
            lines.append(f"    [{c.state}] {c.kind} {c.name}: {c.url or '-'}")
        if not s.checks:
            lines.append("    no check runs or commit statuses on this commit")
        if s.merged_at:
            lines.append(f"    merged_at {s.merged_at}; no deployment was observed")
    return "\n".join(lines)
