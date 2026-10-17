"""Step 04 - Take the action: open an upgrade PR, only after explicit human approval.

Flow for one UPGRADE plan:
  build_proposal()  pure: the exact one-line change, branch name and PR text
  resolve()         reuse an open PR / no action if base is already fixed / pick a new attempt
  ask_approval()    human gate: only "y"/"yes" approves, anything else is a no
  open_pr()         idempotent: store -> existing PR -> existing branch -> create

Re-runs: an OPEN PR for the branch is always reused. If the earlier PR was merged or
closed but the file on the base branch still pins the vulnerable version (e.g. after
scripts/reset_demo.sh), that is a new action: attempt n+1 on triage/<pkg>-<target>-<n+1>,
again behind the y/N approval.

Opening a PR is the irreversible step, so open_pr() checks three places before it
creates anything: the local SQLite store, GitHub's PR list for the head branch, and
the branch itself (a crash between "commit" and "open PR" must not commit twice).
"""
from __future__ import annotations

import base64
import getpass
import re
from dataclasses import dataclass, field, replace
from typing import Callable

import requests

from .models import AdvisoryMatch, Decision, Dependency, PlanStatus, UpgradePlan
from .store import ActionStore

API = "https://api.github.com"


class GitHubError(RuntimeError):
    pass


class StaleProposal(RuntimeError):
    """The file on GitHub no longer has the line we planned to change."""


@dataclass
class Proposal:
    dependency_id: str
    package: str
    current_version: str
    target_version: str
    repo: str                # "owner/name"
    base: str                # base branch, e.g. "main"
    branch: str              # head branch, e.g. "triage/requests-2.33.0"
    path: str                # dependency file path inside the repo
    line: int                # 1-based line number
    old_line: str
    new_line: str
    title: str
    body: str
    advisory_ids: list[str] = field(default_factory=list)
    advisories: list[dict] = field(default_factory=list)   # [{"id", "aliases"}] for unique counting
    attempt: int = 1

    def render(self) -> str:
        return (
            f"Repo:    {self.repo}\n"
            f"Base:    {self.base}\n"
            f"Branch:  {self.branch}" + (f"  (attempt {self.attempt})" if self.attempt > 1 else "") + "\n"
            f"File:    {self.path} line {self.line}\n"
            f"  - {self.old_line}\n"
            f"  + {self.new_line}\n"
            f"PR:      {self.title}\n"
            f"Fixes:   {', '.join(self.advisory_ids)}"
        )


@dataclass
class PrResult:
    outcome: str             # created | existing_in_store | existing_on_github | declined
    pr_number: int | None = None
    pr_url: str | None = None


def branch_name(package: str, target: str, attempt: int = 1) -> str:
    base = f"triage/{re.sub(r'[^a-z0-9._-]+', '-', package.lower())}-{target}"
    return base if attempt == 1 else f"{base}-{attempt}"


def bump_line(line: str, current: str, target: str) -> str:
    """Change only the pinned version, keep extras, markers, comments and spacing."""
    new, n = re.subn(rf"(==\s*){re.escape(current)}(?![\w.])", rf"\g<1>{target}", line, count=1)
    if n != 1:
        raise StaleProposal(f"line {line!r} does not pin =={current}")
    return new


def _pr_body(p: UpgradePlan, dep: Dependency, matches: list[AdvisoryMatch], path: str) -> str:
    rows = [m for m in matches if m.dependency_id == dep.id and m.decision == Decision.VULNERABLE]
    lines = [
        f"Upgrades **{p.package}** from `{p.current_version}` to `{p.target_version}` in `{path}` "
        f"(line {dep.line}).",
        "",
        f"`{p.target_version}` is the lowest version that clears every advisory below; it was "
        "re-checked against all advisories for this package. Version matching is deterministic "
        "code, not an LLM.",
        "",
        "| Advisory | Affected range | Fixed in | Source | Retrieved at |",
        "|---|---|---|---|---|",
    ]
    lines += [
        f"| [{m.advisory_id}]({m.url}) | `{m.affected_range}` | `{m.fixed_version or '-'}` "
        f"| {m.source} | {m.retrieved_at} |"
        for m in rows
    ]
    lines += [
        "",
        f"Dependency ID: `{dep.id}`",
        "",
        "Opened after explicit human approval by the dependency advisory triage agent. "
        "CI on this PR decides whether the upgrade is safe; this PR does not mean the issue is fixed "
        "until CI passes and it is merged.",
    ]
    return "\n".join(lines)


def build_proposal(plan: UpgradePlan, dep: Dependency, matches: list[AdvisoryMatch],
                   repo: str, base: str, path: str) -> Proposal:
    if plan.status != PlanStatus.UPGRADE or not plan.target_version or not dep.version:
        raise ValueError(f"{plan.dependency_id} is not an upgrade plan")
    return Proposal(
        dependency_id=dep.id,
        package=plan.package,
        current_version=dep.version,
        target_version=plan.target_version,
        repo=repo,
        base=base,
        branch=branch_name(dep.name, plan.target_version),
        path=path,
        line=dep.line,
        old_line=dep.spec,
        new_line=bump_line(dep.spec, dep.version, plan.target_version),
        title=f"Upgrade {plan.package} {dep.version} -> {plan.target_version} (security advisories)",
        body=_pr_body(plan, dep, matches, path),
        advisory_ids=list(plan.advisory_ids),
        advisories=[{"id": m.advisory_id, "aliases": list(m.aliases)} for m in matches
                    if m.dependency_id == dep.id and m.decision == Decision.VULNERABLE],
    )


@dataclass
class Resolution:
    action: str              # new | reuse | no_action
    proposal: Proposal       # for "new": the attempt and branch to use
    reason: str
    pr: dict | None = None   # the open PR (reuse) or the earlier merged/closed PR


def _pr_state(pr: dict) -> str:
    return "merged" if pr.get("merged") or pr.get("merged_at") else pr["state"]


def with_attempt(p: Proposal, n: int, previous: dict | None = None) -> Proposal:
    if n == 1:
        return p
    name = p.dependency_id.split(":", 1)[1].split("@", 1)[0]
    note = (f"\n\nRe-run (attempt {n}): previous PR #{previous['number']} was {_pr_state(previous)}, "
            f"but `{p.path}` on `{p.base}` still pins `{p.old_line}`.") if previous else ""
    return replace(p, attempt=n, branch=branch_name(name, p.target_version, n), body=p.body + note)


def resolve(p: Proposal, client: GitHubClient, store: ActionStore, max_attempts: int = 20) -> Resolution:
    """Decide what an approved run WOULD do, before asking for approval. Read-only on GitHub."""
    base_line: str | None = None
    previous: dict | None = None
    for n in range(1, max_attempts + 1):
        q = with_attempt(p, n, previous)
        rec = store.get(p.dependency_id, p.target_version, n)
        pr = (client.get(f"/repos/{p.repo}/pulls/{rec.pr_number}") if rec and rec.pr_number
              else client.find_pr(p.repo, q.branch))
        if pr is None:
            return Resolution("new", q, f"attempt {n}: no PR yet for {q.branch}", previous)
        state = _pr_state(pr)
        if state == "open":
            if not (rec and rec.pr_url):     # found on GitHub only: remember it
                store.record_approval(p.dependency_id, p.target_version, p.repo, q.branch,
                                      "(existing PR on GitHub)", p.package, p.advisories, n)
                store.record_pr(p.dependency_id, p.target_version, pr["number"], pr["html_url"], n)
            return Resolution("reuse", q, f"PR #{pr['number']} is still open", pr)
        if base_line is None:
            text, _ = client.get_file(p.repo, p.path, p.base)
            lines = text.splitlines()
            base_line = lines[p.line - 1].strip() if p.line <= len(lines) else ""
        if base_line != p.old_line.strip():
            return Resolution("no_action", q,
                              f"PR #{pr['number']} was {state}; {p.path} line {p.line} on {p.base} is now "
                              f"{base_line!r}, no longer {p.old_line!r}", pr)
        previous = pr                        # merged/closed, base still vulnerable -> next attempt
    raise GitHubError(f"more than {max_attempts} attempts for {p.dependency_id}")


def ask_approval(proposal: Proposal, input_fn: Callable[[str], str] | None = None,
                 print_fn: Callable[[str], None] = print) -> bool:
    print_fn("\n--- Proposed upgrade PR ---\n" + proposal.render())
    try:
        answer = (input_fn or input)("Open this PR? [y/N] ")
    except EOFError:            # no terminal (e.g. piped input) -> never approve by default
        return False
    return answer.strip().lower() in {"y", "yes"}


class GitHubClient:
    """Minimal GitHub REST client: only the calls this action needs."""

    def __init__(self, token: str, session: requests.Session | None = None, api: str = API):
        self.api = api
        self.s = session or requests.Session()
        self.s.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })

    def _call(self, method: str, path: str, ok=(200,), **kw):
        r = self.s.request(method, f"{self.api}{path}", timeout=20, **kw)
        if r.status_code == 404 and 404 in ok:
            return None
        if r.status_code not in ok:
            raise GitHubError(f"{method} {path} -> {r.status_code}: {r.text[:300]}")
        return r.json()

    def get(self, path: str, **params):
        return self._call("GET", path, params=params or None)

    def default_branch(self, repo: str) -> str:
        return self._call("GET", f"/repos/{repo}")["default_branch"]

    def branch_sha(self, repo: str, branch: str) -> str | None:
        ref = self._call("GET", f"/repos/{repo}/git/ref/heads/{branch}", ok=(200, 404))
        return ref["object"]["sha"] if ref else None

    def create_branch(self, repo: str, branch: str, sha: str) -> None:
        self._call("POST", f"/repos/{repo}/git/refs", ok=(201,),
                   json={"ref": f"refs/heads/{branch}", "sha": sha})

    def get_file(self, repo: str, path: str, ref: str) -> tuple[str, str]:
        """Return (text, blob_sha)."""
        f = self._call("GET", f"/repos/{repo}/contents/{path}", params={"ref": ref})
        return base64.b64decode(f["content"]).decode(), f["sha"]

    def put_file(self, repo: str, path: str, branch: str, text: str, sha: str, message: str) -> None:
        self._call("PUT", f"/repos/{repo}/contents/{path}", ok=(200, 201), json={
            "message": message,
            "content": base64.b64encode(text.encode()).decode(),
            "sha": sha,
            "branch": branch,
        })

    def find_pr(self, repo: str, branch: str) -> dict | None:
        """Any PR (open, closed or merged) whose head is this branch."""
        owner = repo.split("/")[0]
        prs = self._call("GET", f"/repos/{repo}/pulls",
                         params={"head": f"{owner}:{branch}", "state": "all"})
        return prs[0] if prs else None

    def create_pr(self, repo: str, branch: str, base: str, title: str, body: str) -> dict:
        return self._call("POST", f"/repos/{repo}/pulls", ok=(201,),
                          json={"title": title, "head": branch, "base": base, "body": body})


def _replace_line(text: str, line_no: int, old: str, new: str) -> str:
    lines = text.splitlines(keepends=True)
    if line_no > len(lines) or lines[line_no - 1].strip() != old.strip():
        raise StaleProposal(f"line {line_no} on GitHub is not {old!r}; re-scan before upgrading")
    current = lines[line_no - 1]
    ending = current[len(current.rstrip("\r\n")):]
    indent = current[: len(current) - len(current.lstrip())]
    lines[line_no - 1] = indent + new.strip() + ending
    return "".join(lines)


def open_pr(p: Proposal, client: GitHubClient, store: ActionStore,
            approved_by: str | None = None) -> PrResult:
    """Run an APPROVED proposal. Safe to call again after a crash or retry."""
    done = store.get(p.dependency_id, p.target_version, p.attempt)
    if done and done.pr_url:
        store.fill_advisories(p.dependency_id, p.target_version, p.package, p.advisories)
        return PrResult("existing_in_store", done.pr_number, done.pr_url)

    store.record_approval(p.dependency_id, p.target_version, p.repo, p.branch,
                          approved_by or getpass.getuser(), p.package, p.advisories, p.attempt)

    existing = client.find_pr(p.repo, p.branch)
    if existing:
        store.record_pr(p.dependency_id, p.target_version, existing["number"], existing["html_url"], p.attempt)
        return PrResult("existing_on_github", existing["number"], existing["html_url"])

    if client.branch_sha(p.repo, p.branch) is None:
        base_sha = client.branch_sha(p.repo, p.base)
        if base_sha is None:
            raise GitHubError(f"base branch {p.base!r} not found in {p.repo}")
        client.create_branch(p.repo, p.branch, base_sha)

    text, blob_sha = client.get_file(p.repo, p.path, p.branch)
    lines = text.splitlines()
    already = p.line <= len(lines) and lines[p.line - 1].strip() == p.new_line.strip()
    if not already:     # skip the commit if an earlier, interrupted run already made it
        client.put_file(p.repo, p.path, p.branch, _replace_line(text, p.line, p.old_line, p.new_line),
                        blob_sha, f"Upgrade {p.package} to {p.target_version} (security advisories)")

    pr = client.create_pr(p.repo, p.branch, p.base, p.title, p.body)
    store.record_pr(p.dependency_id, p.target_version, pr["number"], pr["html_url"], p.attempt)
    return PrResult("created", pr["number"], pr["html_url"])
