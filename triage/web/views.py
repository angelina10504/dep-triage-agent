"""Read-only data for the pages: the triage table rows and the TC1-TC4 results.

Everything is computed from triage.db at request time: recorded actions (PRs), the
latest CI observation per PR, web runs (plans, matches, risk) and diagnoses.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field

from ..ci_watch import OUTCOME_FAILING, OUTCOME_MERGED
from ..scanner import count_unique
from ..store import ActionStore
from .runs import RunStore

OSV = "https://osv.dev/vulnerability/"


def status_class(pr_state: str | None, ci: str | None) -> str:
    """Colour key: failing red, passing green, pending amber, merged blue."""
    if pr_state == "merged":
        return "merged"
    if pr_state == "closed":
        return "closed"
    return {"failing": "failing", "passing": "passing", "pending": "pending"}.get(ci or "", "unknown")


@dataclass
class Row:
    key: str
    package: str
    current: str | None
    target: str | None
    plan_status: str
    plan_reason: str
    vulnerable: list[dict] = field(default_factory=list)      # matches that make it vulnerable
    other: list[dict] = field(default_factory=list)           # not_affected / excluded / uncertain
    advisory_ids: list[dict] = field(default_factory=list)    # from the action row (no run snapshot)
    risk: dict | None = None
    pr: dict | None = None             # actions row
    obs: dict | None = None            # latest CI observation
    history: list[dict] = field(default_factory=list)
    diagnosis: dict | None = None
    decision: dict | None = None       # web approval record

    @property
    def advisory_summary(self) -> str:
        groups = [{m["advisory_id"], *m["aliases"]} for m in self.vulnerable] or \
                 [{a["id"], *a.get("aliases", [])} for a in self.advisory_ids]
        if not groups:
            return "none affecting this version"
        return f"{count_unique(groups)} vulns ({len(groups)} records)"

    @property
    def css(self) -> str:
        return status_class(self.obs and self.obs["pr_state"], self.obs and self.obs["ci_status"])

    @property
    def outcome(self) -> str:
        if self.obs:
            return self.obs["outcome"]
        if self.pr:
            return "PR opened, CI not observed yet (Refresh CI)"
        if self.plan_status == "upgrade":
            return "upgrade proposed, no PR yet (needs approval)"
        return self.plan_reason or "no action"

    @property
    def excluded_other_ecosystem(self) -> list[dict]:
        return [m for m in self.other if m.get("queried_ecosystem", "PyPI") != "PyPI"]


def _observations(db_path: str, repo: str) -> dict[int, list[dict]]:
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    try:
        out: dict[int, list[dict]] = {}
        for r in db.execute("SELECT * FROM ci_observations WHERE repo = ? ORDER BY id", (repo,)):
            out.setdefault(r["pr_number"], []).append({**dict(r), "checks": json.loads(r["checks"])})
        return out
    finally:
        db.close()


def _decision_for(decisions: list[dict], branch: str) -> dict | None:
    for d in decisions:
        if d["key"].endswith("|" + branch) and d["decision"] == "approved":
            return d
    return None


def build_rows(db_path: str, repo: str) -> tuple[list[Row], dict | None]:
    store = ActionStore(db_path)
    runs = RunStore(db_path)
    try:
        actions = store.with_prs(repo)
    finally:
        store.db.close()
    obs = _observations(db_path, repo)
    diags = runs.latest_diagnoses(repo)
    decisions = runs.decisions()
    latest = runs.latest_snapshot()
    snap = (latest or {}).get("snapshot") or {}
    risks = snap.get("risks") or {}
    matches = snap.get("matches") or []

    rows: list[Row] = []
    used: set[tuple] = set()

    def with_pr(row: Row, a) -> Row:
        row.pr = {"number": a.pr_number, "url": a.pr_url, "attempt": a.attempt, "branch": a.branch,
                  "approved_by": a.approved_by, "approved_at": a.approved_at, "status": a.status}
        hist = obs.get(a.pr_number, [])
        row.history = hist
        row.obs = hist[-1] if hist else None
        if row.obs and row.obs["ci_status"] == "failing" and row.obs["pr_state"] == "open":
            row.diagnosis = diags.get(a.pr_number)
        row.decision = _decision_for(decisions, a.branch)
        row.advisory_ids = a.advisories
        used.add((a.dependency_id, a.target_version, a.attempt))
        return row

    for p in snap.get("plans") or []:
        dep = p["dependency_id"]
        mine = [m for m in matches if m["dependency_id"] == dep]
        base = dict(package=p["package"], current=p["current_version"], target=p["target_version"],
                    plan_status=p["status"], plan_reason=p["reason"],
                    vulnerable=[m for m in mine if m["decision"] == "vulnerable"],
                    other=[m for m in mine if m["decision"] != "vulnerable"], risk=risks.get(dep))
        prs = sorted((a for a in actions if a.dependency_id == dep and a.target_version == p["target_version"]),
                     key=lambda a: -a.attempt)
        if not prs:
            rows.append(Row(key=f"{dep}|{p['target_version']}", **base))
        for a in prs:
            rows.append(with_pr(Row(key=f"{dep}|{a.target_version}|{a.attempt}", **base), a))

    for a in actions:                    # PRs from earlier runs (e.g. merged attempt 1)
        if (a.dependency_id, a.target_version, a.attempt) in used:
            continue
        current = a.dependency_id.split("@", 1)[1].split("#", 1)[0]
        row = Row(key=f"{a.dependency_id}|{a.target_version}|{a.attempt}", package=a.package or a.dependency_id,
                  current=current, target=a.target_version, plan_status="upgrade",
                  plan_reason="recorded upgrade PR (earlier run)")
        rows.append(with_pr(row, a))
    return rows, latest


# ---------------------------------------------------------------- test cases

@dataclass
class TestCase:
    id: str
    title: str
    input: str
    expected: str
    actual: str
    result: str                       # PASS | FAIL | PENDING
    evidence: list[tuple[str, str]] = field(default_factory=list)   # (label, url)


def _pr_links(row: Row) -> list[tuple[str, str]]:
    out = []
    if row.pr and row.pr.get("url"):
        out.append((f"PR #{row.pr['number']}", row.pr["url"]))
    for c in (row.obs or {}).get("checks", []):
        if c.get("url"):
            out.append((f"check {c['name']}: {c['state']}", c["url"]))
    return out


def _adv_links(ms: list[dict], n: int = 3) -> list[tuple[str, str]]:
    return [(m["advisory_id"], m["url"]) for m in ms[:n] if m.get("url")]


def test_cases(rows: list[Row], latest: dict | None, evidence_files: list[str]) -> list[TestCase]:
    def files(*names):
        return [(f"evidence/{n}", f"/evidence/{n}") for n in names if n in evidence_files]

    snap = (latest or {}).get("snapshot") or {}
    out = []

    # TC1: installed version inside an advisory range -> upgrade PR opened
    tc1 = TestCase("TC1", "Installed version inside advisory range", "", "upgrade PR opened", "", "PENDING",
                   files("tc1_tc3_before_merge.txt"))
    affected = [r for r in rows if r.vulnerable or (r.pr and r.advisory_ids)]
    with_pr = [r for r in affected if r.pr]
    pick = next((r for r in with_pr if r.css in ("passing", "merged")), None) or (with_pr[0] if with_pr else None)
    if pick:
        m = pick.vulnerable[0] if pick.vulnerable else None
        tc1.input = f"{pick.package}=={pick.current}" + (f" (advisory {m['advisory_id']}, range {m['affected_range']})" if m else "")
        tc1.actual = (f"plan: upgrade to {pick.target}; PR #{pick.pr['number']} opened (attempt {pick.pr['attempt']}), "
                      f"CI {pick.obs['ci_status'] if pick.obs else 'not observed yet'}")
        tc1.result = "PASS"
        tc1.evidence = _pr_links(pick) + _adv_links(pick.vulnerable) + tc1.evidence
    elif affected:
        r = affected[0]
        tc1.input = f"{r.package}=={r.current}"
        if r.plan_status == "upgrade":
            tc1.actual = f"upgrade to {r.target} planned; no PR opened yet (waiting for human approval)"
        else:
            tc1.actual, tc1.result = f"vulnerable but plan is '{r.plan_status}': {r.plan_reason}", "FAIL"
        tc1.evidence = _adv_links(r.vulnerable) + tc1.evidence
    else:
        tc1.input, tc1.actual = "-", "no run yet with a vulnerable dependency"
    out.append(tc1)

    # TC2: unrelated package with the same name -> excluded
    tc2 = TestCase("TC2", "Unrelated package with the same name", "", "advisory excluded, no PR", "", "PENDING",
                   files("tc2_excluded.txt"))
    collided = [r for r in rows if r.excluded_other_ecosystem]
    if collided:
        bad = [r for r in collided if any(m["decision"] != "excluded" for m in r.excluded_other_ecosystem)
               or (r.pr and not r.vulnerable)]
        parts = []
        for r in collided:
            ecos = sorted({m["queried_ecosystem"] for m in r.excluded_other_ecosystem})
            ids = ", ".join(m["advisory_id"] for m in r.excluded_other_ecosystem[:3])
            parts.append(f"{r.package}=={r.current}: {len(r.excluded_other_ecosystem)} {'/'.join(ecos)} advisory "
                         f"record(s) ({ids}) -> {', '.join(sorted({m['decision'] for m in r.excluded_other_ecosystem}))}; "
                         f"plan {r.plan_status}" + (f", PR #{r.pr['number']}" if r.pr else ", no PR"))
        tc2.input = "; ".join(f"PyPI {r.package}=={r.current}" for r in collided)
        tc2.actual = " | ".join(parts)
        tc2.result = "FAIL" if bad else "PASS"
        for r in collided:
            tc2.evidence += _adv_links(r.excluded_other_ecosystem)
    else:
        tc2.input = "-"
        tc2.actual = "no same-name advisory from another ecosystem in the latest run" if snap else "no run yet"
    out.append(tc2)

    # TC3: tests fail after upgrade -> PR marked failing, NOT "fixed"
    tc3 = TestCase("TC3", "Tests fail after upgrade", "", f'outcome "{OUTCOME_FAILING}"', "", "PENDING",
                   files("tc1_tc3_before_merge.txt", "step5_diagnosis_pr2.txt"))
    failing = [r for r in rows if r.obs and r.obs["ci_status"] == "failing" and r.obs["pr_state"] == "open"]
    if failing:
        r = failing[0]
        tc3.input = f"PR #{r.pr['number']} {r.package} {r.current} -> {r.target}, CI failing"
        tc3.actual = f'outcome "{r.obs["outcome"]}" (observed {r.obs["observed_at"]})'
        if r.diagnosis:
            tc3.actual += f"; diagnosis: {r.diagnosis['root_cause'][:160]}"
        claims_fixed = "fixed" in r.obs["outcome"].lower() and "not fixed" not in r.obs["outcome"].lower()
        tc3.result = "PASS" if r.obs["outcome"] == OUTCOME_FAILING and not claims_fixed else "FAIL"
        tc3.evidence = _pr_links(r) + ([("CI job log", r.diagnosis["job_url"])] if r.diagnosis and r.diagnosis.get("job_url") else []) + tc3.evidence
    else:
        tc3.input, tc3.actual = "-", "no open PR with failing CI observed yet"
    out.append(tc3)

    # TC4: PR merged -> reported "merged", NOT "deployed"
    tc4 = TestCase("TC4", "PR merged", "", f'outcome "{OUTCOME_MERGED}"', "", "PENDING", files("tc4_merged.txt"))
    merged = [r for r in rows if r.obs and r.obs["pr_state"] == "merged"]
    if merged:
        r = merged[0]
        tc4.input = f"PR #{r.pr['number']} {r.package} -> {r.target} merged at {r.obs['merged_at']}"
        tc4.actual = f'outcome "{r.obs["outcome"]}" (observed {r.obs["observed_at"]})'
        low = r.obs["outcome"].lower()
        tc4.result = "PASS" if "merged" in low and ("deployed" not in low or "not deployed" in low) else "FAIL"
        tc4.evidence = _pr_links(r) + tc4.evidence
    else:
        tc4.input, tc4.actual = "-", "no merged upgrade PR observed yet (merge one, then Refresh CI)"
    out.append(tc4)
    return out
