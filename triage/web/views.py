"""Read-only data for the pages: the triage table rows and the TC1-TC4 results.

Everything is computed from triage.db at request time: the latest stored scan run
(scan_runs: plans, every per-advisory decision, risk with citations), recorded PRs
(actions, with the risk shown at approval), CI observations, web decisions and
diagnoses. One row per package; its latest PR attempt is the row, earlier attempts
are its history.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..db import connect
from ..ci_watch import OUTCOME_FAILING, OUTCOME_MERGED
from ..scanner import count_unique
from ..store import ActionRecord, ActionStore
from .runs import RunStore


def status_class(pr_state: str | None, ci: str | None) -> str:
    """Colour key: failing red, passing green, pending amber, merged blue."""
    if pr_state == "merged":
        return "merged"
    if pr_state == "closed":
        return "closed"
    return {"failing": "failing", "passing": "passing", "pending": "pending"}.get(ci or "", "unknown")


@dataclass
class Attempt:
    """One recorded upgrade PR (one attempt) and what was observed on it."""
    number: int
    url: str | None
    attempt: int
    branch: str
    target: str
    current: str
    approved_by: str
    approved_at: str
    risk: dict | None = None           # stored with the PR at approval time
    obs: dict | None = None            # latest CI observation
    history: list[dict] = field(default_factory=list)
    diagnosis: dict | None = None
    decision: dict | None = None       # web approval record (name, time, risk shown at)

    @property
    def css(self) -> str:
        return status_class(self.obs and self.obs["pr_state"], self.obs and self.obs["ci_status"])

    @property
    def outcome(self) -> str:
        return self.obs["outcome"] if self.obs else "PR opened, CI not observed yet (Refresh CI)"

    @property
    def merged(self) -> bool:
        return bool(self.obs and self.obs["pr_state"] == "merged")

    @property
    def failing(self) -> bool:
        return bool(self.obs and self.obs["pr_state"] == "open" and self.obs["ci_status"] == "failing")


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
    advisory_ids: list[dict] = field(default_factory=list)    # from the PR record (no stored scan)
    run_risk: dict | None = None                              # from the latest stored run
    attempts: list[Attempt] = field(default_factory=list)     # newest first

    @property
    def latest(self) -> Attempt | None:
        return self.attempts[0] if self.attempts else None

    @property
    def earlier(self) -> list[Attempt]:
        return self.attempts[1:]

    # the row shows the latest attempt
    @property
    def pr(self) -> Attempt | None:
        return self.latest

    @property
    def obs(self) -> dict | None:
        return self.latest.obs if self.latest else None

    @property
    def diagnosis(self) -> dict | None:
        return self.latest.diagnosis if self.latest else None

    @property
    def risk(self) -> dict | None:
        return self.run_risk or (self.latest.risk if self.latest else None)

    @property
    def risk_source(self) -> str:
        if self.run_risk:
            return "latest stored scan run"
        if self.latest and self.latest.risk:
            return f"stored with PR #{self.latest.number} at approval"
        return ""

    @property
    def advisory_summary(self) -> str:
        groups = [{m["advisory_id"], *m["aliases"]} for m in self.vulnerable] or \
                 [{a["id"], *a.get("aliases", [])} for a in self.advisory_ids]
        if not groups:
            return "none affecting this version"
        return f"{count_unique(groups)} vulns ({len(groups)} records)"

    @property
    def css(self) -> str:
        return self.latest.css if self.latest else "unknown"

    @property
    def outcome(self) -> str:
        if self.latest:
            return self.latest.outcome
        if self.plan_status == "upgrade":
            return "upgrade proposed, no PR yet (needs approval)"
        return self.plan_reason or "no action"

    @property
    def excluded_other_ecosystem(self) -> list[dict]:
        return [m for m in self.other if m.get("queried_ecosystem", "PyPI") != "PyPI"]


def _observations(db_path: str, repo: str) -> dict[int, list[dict]]:
    db = connect(db_path)
    try:
        out: dict[int, list[dict]] = {}
        for r in db.execute("SELECT * FROM ci_observations WHERE repo = ? ORDER BY id", (repo,)):
            out.setdefault(r["pr_number"], []).append({**dict(r), "checks": json.loads(r["checks"])})
        return out
    finally:
        db.close()


def _decision_for(decisions: list[dict], branch: str) -> dict | None:
    return next((d for d in decisions if d["key"].endswith("|" + branch) and d["decision"] == "approved"), None)


def _current(dependency_id: str) -> str:
    return dependency_id.split("@", 1)[1].split("#", 1)[0]


def build_rows(db_path: str, repo: str) -> tuple[list[Row], dict | None]:
    """Rows (one per package) and the latest stored scan run (or None)."""
    store = ActionStore(db_path)
    try:
        actions = store.with_prs(repo)
        latest = store.latest_run(repo)
    finally:
        store.db.close()
    runs = RunStore(db_path)
    obs = _observations(db_path, repo)
    diags = runs.latest_diagnoses(repo)
    decisions = runs.decisions()
    data = (latest or {}).get("data") or {}
    risks = data.get("risks") or {}
    matches = data.get("matches") or []

    def attempt(a: ActionRecord) -> Attempt:
        hist = obs.get(a.pr_number, [])
        at = Attempt(number=a.pr_number, url=a.pr_url, attempt=a.attempt, branch=a.branch, target=a.target_version,
                     current=_current(a.dependency_id), approved_by=a.approved_by, approved_at=a.approved_at,
                     risk=a.risk, obs=hist[-1] if hist else None, history=hist,
                     decision=_decision_for(decisions, a.branch))
        if at.failing:
            at.diagnosis = diags.get(a.pr_number)
        return at

    rows: dict[str, Row] = {}
    for p in data.get("plans") or []:
        dep = p["dependency_id"]
        mine = [m for m in matches if m["dependency_id"] == dep]
        rows[p["package"].lower()] = Row(
            key=dep, package=p["package"], current=p["current_version"], target=p["target_version"],
            plan_status=p["status"], plan_reason=p["reason"],
            vulnerable=[m for m in mine if m["decision"] == "vulnerable"],
            other=[m for m in mine if m["decision"] != "vulnerable"], run_risk=risks.get(dep))

    for a in actions:                    # every PR attempt joins its package's row
        name = (a.package or a.dependency_id).lower()
        if name not in rows:
            rows[name] = Row(key=a.dependency_id, package=a.package or a.dependency_id, current=_current(a.dependency_id),
                             target=a.target_version, plan_status="upgrade",
                             plan_reason="recorded upgrade PR (no stored scan run includes this package)")
        row = rows[name]
        row.attempts.append(attempt(a))
        if not row.advisory_ids:
            row.advisory_ids = a.advisories
    for row in rows.values():
        row.attempts.sort(key=lambda t: (t.approved_at, t.attempt), reverse=True)
    return list(rows.values()), latest


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


def _pr_links(at: Attempt) -> list[tuple[str, str]]:
    out = [(f"PR #{at.number}", at.url)] if at.url else []
    for c in (at.obs or {}).get("checks", []):
        if c.get("url"):
            out.append((f"PR #{at.number} check {c['name']}: {c['state']}", c["url"]))
    return out


def _adv_links(ms: list[dict], n: int = 3) -> list[tuple[str, str]]:
    return [(m["advisory_id"], m["url"]) for m in ms[:n] if m.get("url")]


def _run_label(latest: dict | None) -> str:
    return f"stored run {latest['thread_id']} ({latest['updated_at']})" if latest else "no stored run"


def _for_package(m: dict, row: Row) -> str:
    """'npm/markdown' from the matcher's reason, else '<ecosystem>/<name>'."""
    found = re.search(r"advisory is for (\S+?),", m.get("reason", ""))
    return found.group(1) if found else f"{m.get('queried_ecosystem')}/{row.package.lower()}"


def test_cases(rows: list[Row], latest: dict | None, evidence_files: list[str]) -> list[TestCase]:
    def files(*names):
        return [(f"evidence/{n}", f"/evidence/{n}") for n in names if n in evidence_files]

    out = []

    # TC1: installed version inside an advisory range -> upgrade PR opened (latest attempt is the live example)
    tc1 = TestCase("TC1", "Installed version inside advisory range", "", "upgrade PR opened", "", "PENDING",
                   files("tc1_tc3_before_merge.txt"))
    affected = [r for r in rows if r.vulnerable or r.attempts]
    with_pr = [r for r in affected if r.latest]
    pick = next((r for r in with_pr if not r.latest.failing), None) or (with_pr[0] if with_pr else None)
    if pick:
        at = pick.latest
        m = pick.vulnerable[0] if pick.vulnerable else None
        tc1.input = f"{pick.package}=={at.current}" + (f" (advisory {m['advisory_id']}, affected range {m['affected_range']})" if m else "")
        tc1.actual = (f"upgrade to {at.target} planned; PR #{at.number} opened (attempt {at.attempt}), "
                      f"CI {at.obs['ci_status'] if at.obs else 'not observed yet'}")
        for e in pick.earlier:
            tc1.actual += (f". Earlier attempt: PR #{e.number} (attempt {e.attempt}), "
                           + ("merged, see TC4" if e.merged else e.outcome))
        tc1.result = "PASS"
        tc1.evidence = _pr_links(at) + _adv_links(pick.vulnerable) + tc1.evidence
    elif affected:
        r = affected[0]
        tc1.input = f"{r.package}=={r.current}"
        if r.plan_status == "upgrade":
            tc1.actual = f"upgrade to {r.target} planned; no PR opened yet (waiting for human approval)"
        else:
            tc1.actual, tc1.result = f"vulnerable but plan is '{r.plan_status}': {r.plan_reason}", "FAIL"
        tc1.evidence = _adv_links(r.vulnerable) + tc1.evidence
    else:
        tc1.input, tc1.actual = "-", f"no vulnerable dependency in the {_run_label(latest)}"
    out.append(tc1)

    # TC2: unrelated package with the same name -> excluded
    tc2 = TestCase("TC2", "Unrelated package with the same name", "", "advisory excluded, no upgrade, no PR",
                   "", "PENDING", files("tc2_excluded.txt"))
    collided = [r for r in rows if r.excluded_other_ecosystem]
    if collided:
        inputs, actuals, bad = [], [], False
        for r in collided:
            ms = r.excluded_other_ecosystem
            inputs.append(f"{r.package}=={r.current} (PyPI); " + "; ".join(
                f"advisory {m['advisory_id']} is for {_for_package(m, r)}" for m in ms))
            decisions = sorted({m["decision"] for m in ms})
            prs = [a for a in r.attempts if not r.vulnerable]
            actuals.append(f"{r.package}: {', '.join(decisions)} ({ms[0]['reason']}); plan {r.plan_status}"
                           + (f"; PR #{prs[0].number} exists" if prs else "; no PR"))
            bad |= decisions != ["excluded"] or bool(prs) or (r.plan_status == "upgrade" and not r.vulnerable)
            tc2.evidence = _adv_links(ms) + tc2.evidence
        tc2.input = " | ".join(inputs)
        tc2.actual = " | ".join(actuals) + f". From {_run_label(latest)}."
        tc2.result = "FAIL" if bad else "PASS"
    else:
        tc2.input = "-"
        tc2.actual = (f"no same-name advisory from another ecosystem in the {_run_label(latest)}" if latest
                      else "no stored run yet (run a scan once)")
    out.append(tc2)

    # TC3: tests fail after upgrade -> PR marked failing, NOT "fixed"
    tc3 = TestCase("TC3", "Tests fail after upgrade", "", f'outcome "{OUTCOME_FAILING}"', "", "PENDING",
                   files("tc1_tc3_before_merge.txt", "step5_diagnosis_pr2.txt"))
    failing = [(r, a) for r in rows for a in r.attempts if a.failing]
    if failing:
        r, at = failing[0]
        tc3.input = f"PR #{at.number} {r.package} {at.current} -> {at.target}, CI failing"
        tc3.actual = f'outcome "{at.obs["outcome"]}" (observed {at.obs["observed_at"]})'
        if at.diagnosis:
            tc3.actual += f"; diagnosis: {at.diagnosis['root_cause'][:160]}"
        low = at.obs["outcome"].lower()
        tc3.result = "PASS" if at.obs["outcome"] == OUTCOME_FAILING and ("fixed" not in low or "not fixed" in low) else "FAIL"
        tc3.evidence = _pr_links(at) + ([("CI job log", at.diagnosis["job_url"])]
                                        if at.diagnosis and at.diagnosis.get("job_url") else []) + tc3.evidence
    else:
        tc3.input, tc3.actual = "-", "no open PR with failing CI observed yet"
    out.append(tc3)

    # TC4: PR merged -> reported "merged", NOT "deployed" (latest or an earlier attempt)
    tc4 = TestCase("TC4", "PR merged", "", f'outcome "{OUTCOME_MERGED}"', "", "PENDING", files("tc4_merged.txt"))
    merged = [(r, a) for r in rows for a in r.attempts if a.merged]
    if merged:
        r, at = merged[0]
        tc4.input = f"PR #{at.number} {r.package} {at.current} -> {at.target} (attempt {at.attempt}) merged at {at.obs['merged_at']}"
        tc4.actual = f'outcome "{at.obs["outcome"]}" (observed {at.obs["observed_at"]})'
        low = at.obs["outcome"].lower()
        tc4.result = "PASS" if "merged" in low and ("deployed" not in low or "not deployed" in low) else "FAIL"
        tc4.evidence = _pr_links(at) + tc4.evidence
    else:
        tc4.input, tc4.actual = "-", "no merged upgrade PR observed yet (merge one, then Refresh CI)"
    out.append(tc4)
    return out
