"""Step 5 orchestration: the whole workflow as a LangGraph state machine.

collect -> fetch_advisories -> match -> plan -> assess_upgrade_risk -> human_approval
  -> open_pr -> watch_ci -> (diagnose_failure, only if a PR is failing) -> report

Every node wraps an existing module; no decision logic lives here. human_approval
pauses the run with interrupt(); the SQLite checkpointer keeps the paused state, so the
run can be resumed later - even from a new process - with the same thread id. The resume
value is the human's y/N per proposal; only an explicit True approves.

State holds plain JSON-able data (dicts/lists), so checkpoints stay readable.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, TypedDict

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from . import osv, release_notes
from .ci_watch import PrStatus, render_table, watch
from .diagnose import diagnose_failure, render_diagnosis
from .explain import Explanation, explain, with_explanation
from .github_pr import GitHubClient, Proposal, build_proposal, open_pr, resolve
from .llm import LLMCache, llm_budget
from .models import AdvisoryMatch, Decision, Dependency, PlanStatus, UpgradePlan
from .parser import parse_requirements
from .repo_context import fetch_repo_context
from .report import format_scan
from .risk import assess_upgrade_risk, render_risk
from .scanner import OTHER_ECOSYSTEMS, fetch_all, match_all, plan_all
from .store import ActionStore

NODES = ("collect", "fetch_advisories", "match", "plan", "assess_upgrade_risk", "human_approval",
         "open_pr", "watch_ci", "diagnose_failure", "report")


class TriageState(TypedDict, total=False):
    requirements_path: str
    requirements_text: str
    requirements_source: str
    repo: str | None
    base: str | None
    path: str
    dry_run: bool
    repo_summary: dict
    dependencies: list[dict]
    fetched: dict
    warnings: list[str]
    matches: list[dict]
    plans: list[dict]
    risks: dict[str, dict]
    explanations: dict[str, dict]
    resolutions: list[dict]
    approvals: dict[str, bool]
    notice: str
    prs: list[dict]
    ci: list[dict]
    ci_timed_out: bool
    diagnoses: dict[str, dict]
    report_text: str
    report_verbose: str


@dataclass
class Runtime:
    """Things nodes need that are not state: clients, stores, policies. Injected for tests."""
    store: ActionStore
    cache: LLMCache
    github: Callable[[], GitHubClient] | None = None     # lazy: only called when GitHub is needed
    fetch: Callable | None = None                        # default osv.fetch_advisories (looked up late)
    other_ecosystems: tuple[str, ...] = OTHER_ECOSYSTEMS
    notes: Callable[[str, str, str], release_notes.ReleaseNotes] | None = None
    llm: Any = "env"
    wait: bool = True
    timeout: float = 600
    interval: float = 15
    sleep: Callable[[float], None] | None = None
    clock: Callable[[], float] | None = None
    approved_by: str | None = None
    llm_budget: float | None = 30            # max seconds of LLM time per node (then deterministic only)
    _client: GitHubClient | None = field(default=None, repr=False)

    def client(self) -> GitHubClient:
        if self._client is None:
            if self.github is None:
                raise RuntimeError("GitHub is needed for this step but GITHUB_TOKEN is not set")
            self._client = self.github()
        return self._client


# ---------- (de)serialising the dataclasses kept in state ----------

def _plain(obj) -> dict:
    return json.loads(json.dumps(asdict(obj), default=str))


def _deps(s) -> list[Dependency]:
    return [Dependency(**d) for d in s["dependencies"]]


def _matches(s) -> list[AdvisoryMatch]:
    return [AdvisoryMatch(**{**m, "decision": Decision(m["decision"])}) for m in s["matches"]]


def _plans(s) -> list[UpgradePlan]:
    return [UpgradePlan(**{**p, "status": PlanStatus(p["status"])}) for p in s["plans"]]


def _key(proposal: dict) -> str:
    """Approval key: a 'y' only counts for this exact dependency AND branch (attempt)."""
    return f"{proposal['dependency_id']}|{proposal['branch']}"


# What a stored scan run keeps (scan_runs.data): enough to show the table and TC1-TC4 after a restart.
RUN_KEYS = ("requirements_source", "dependencies", "plans", "matches", "warnings", "risks", "explanations", "repo_summary", "base",
            "prs", "ci", "ci_timed_out", "diagnoses", "notice")


def _persist(rt: Runtime, s: dict, config: RunnableConfig | None, stage: str) -> None:
    thread = ((config or {}).get("configurable") or {}).get("thread_id")
    if rt.store is None or not thread:
        return
    rt.store.save_run(thread, {k: s.get(k) for k in RUN_KEYS if s.get(k) is not None}, repo=s.get("repo"),
                      source=s.get("path") or s.get("requirements_path") or "requirements.txt",
                      dry_run=bool(s.get("dry_run")), stage=stage)


def build_graph(rt: Runtime, checkpointer=None):
    def collect(s: TriageState):
        """Dependency file: given text, a local path (CLI option), or - deployed - read from
        the repo's base branch via the GitHub API (no checkout needed)."""
        out = {}
        if s.get("requirements_text"):
            text, source = s["requirements_text"], s.get("requirements_source") or "given text"
        elif s.get("requirements_path"):
            text, source = Path(s["requirements_path"]).read_text(), f"local file {s['requirements_path']}"
        elif s.get("repo"):
            client = rt.client()
            base = s.get("base") or client.default_branch(s["repo"])
            path = s.get("path") or "requirements.txt"
            text, _ = client.get_file(s["repo"], path, base)
            source, out["base"] = f"{s['repo']}@{base}:{path} (GitHub API)", base
        else:
            raise ValueError("no dependency file: give a local path or a repo")
        return {**out, "requirements_text": text, "requirements_source": source,
                "dependencies": [_plain(d) for d in parse_requirements(text)]}

    def fetch_advisories(s: TriageState):
        fetched, warnings = fetch_all(_deps(s), rt.fetch or osv.fetch_advisories, rt.other_ecosystems)
        return {"fetched": fetched, "warnings": warnings}

    def match(s: TriageState):
        return {"matches": [_plain(m) for m in match_all(_deps(s), s["fetched"])]}

    def plan(s: TriageState):
        return {"plans": [_plain(p) for p in plan_all(_deps(s), s["fetched"], _matches(s))]}

    def assess(s: TriageState, config: RunnableConfig):
        out = _assess(s)
        _persist(rt, {**s, **out}, config, "assessed")      # stored before the run pauses for approval
        return out

    def _assess(s: TriageState):
        deps = {d.id: d for d in _deps(s)}
        upgrades = [p for p in _plans(s) if p.status == PlanStatus.UPGRADE]
        risks, explanations, out = {}, {}, {}
        ctx = None
        if upgrades and s.get("repo"):                 # repo-aware risk: Python version + API usage
            try:
                client = rt.client()
                base = s.get("base") or client.default_branch(s["repo"])
                ctx = fetch_repo_context(client, s["repo"], base)
                out = {"base": base, "repo_summary": {"python": ctx.python_label, "python_source": ctx.python_source,
                                                      "py_files": len(ctx.files), "ref": base, "note": ctx.note}}
            except Exception as e:                     # can't read the repo: risk stays repo-unaware, say so
                out = {"repo_summary": {"error": f"{type(e).__name__}: {str(e)[:120]}"}}
        notes = {}
        for p in upgrades:
            name = deps[p.dependency_id].name
            try:
                notes[p.dependency_id] = (rt.notes or release_notes.fetch_release_notes)(
                    name, p.current_version, p.target_version)
            except Exception as e:                    # network etc.: say so, don't guess
                notes[p.dependency_id] = release_notes.ReleaseNotes(None, note=f"no release notes found ({type(e).__name__})")
        with llm_budget(rt.llm_budget):               # risk for every package first, explanations last
            for p in upgrades:
                risks[p.dependency_id] = assess_upgrade_risk(
                    p.package, p.current_version, p.target_version, notes[p.dependency_id], rt.cache, rt.llm,
                    repo=ctx, import_name=deps[p.dependency_id].name.replace("-", "_"))
            for p in upgrades:
                explanations[p.dependency_id] = asdict(explain(p, _matches(s), rt.cache, rt.llm,
                                                               risk=risks[p.dependency_id]))
        return {**out, "risks": risks, "explanations": explanations}

    def human_approval(s: TriageState):
        upgrades = [p for p in _plans(s) if p.status == PlanStatus.UPGRADE]
        if not s.get("repo"):
            return {"resolutions": [], "approvals": {}, "notice": "scan only (no --repo): no PRs proposed"}
        if not upgrades:
            return {"resolutions": [], "approvals": {}, "notice": "No upgrade plans - no PRs proposed."}
        client = rt.client()
        base = s.get("base") or client.default_branch(s["repo"])
        deps = {d.id: d for d in _deps(s)}
        resolutions = []
        for p in upgrades:
            prop = build_proposal(p, deps[p.dependency_id], _matches(s), s["repo"], base, s.get("path") or "requirements.txt")
            e = s.get("explanations", {}).get(p.dependency_id)
            prop.body = with_explanation(prop.body, Explanation(**e) if e else None)
            if (risk := s.get("risks", {}).get(p.dependency_id)):
                prop.body += "\n\n### Upgrade risk (LLM, cited release notes)\n" + "\n".join(
                    f"- {line.strip(' -')}" for line in render_risk(risk))
            rt.store.fill_advisories(prop.dependency_id, prop.target_version, prop.package, prop.advisories)
            res = resolve(prop, client, rt.store)
            resolutions.append({"dependency_id": p.dependency_id, "package": p.package, "action": res.action,
                                "reason": res.reason, "proposal": asdict(res.proposal),
                                "pr": {k: res.pr.get(k) for k in ("number", "html_url", "state", "merged_at")}
                                if res.pr else None})
        for r in resolutions:
            if (risk := s.get("risks", {}).get(r["dependency_id"])):
                r["risk_lines"] = render_risk(risk)
        pending = [r for r in resolutions if r["action"] == "new"]
        approvals: dict[str, bool] = {}
        if s.get("dry_run"):
            return {"resolutions": resolutions, "approvals": {}, "notice": "dry run: nothing proposed for approval, no PRs opened"}
        if pending:
            answers = interrupt({
                "question": "Open these upgrade PRs? (each needs an explicit yes)",
                "proposals": [{"key": _key(r["proposal"]), "package": r["package"],
                               "attempt": r["proposal"]["attempt"], "reason": r["reason"],
                               "render": Proposal(**r["proposal"]).render(),
                               "risk": r.get("risk_lines", []),
                               "previous_pr": r["pr"],
                               "dependency_id": r["dependency_id"],        # structured copy for the web UI
                               "proposal": {k: r["proposal"][k] for k in (
                                   "repo", "base", "branch", "path", "line", "old_line", "new_line", "title",
                                   "current_version", "target_version", "advisory_ids")}} for r in pending],
            })
            answers = answers if isinstance(answers, dict) else {}
            approvals = {_key(r["proposal"]): answers.get(_key(r["proposal"])) is True for r in pending}
        return {"resolutions": resolutions, "approvals": approvals, "notice": ""}

    def open_pr_node(s: TriageState):
        prs = []
        for r in s.get("resolutions", []):
            row = {"package": r["package"], "dependency_id": r["dependency_id"],
                   "attempt": r["proposal"]["attempt"], "branch": r["proposal"]["branch"]}
            if r["action"] == "reuse":
                prs.append({**row, "outcome": "reused (PR still open)", "pr_number": r["pr"]["number"],
                            "pr_url": r["pr"]["html_url"]})
            elif r["action"] == "no_action":
                prs.append({**row, "outcome": "no action", "reason": r["reason"]})
            elif s.get("dry_run"):
                prs.append({**row, "outcome": "dry run - would propose a new PR"})
            elif s.get("approvals", {}).get(_key(r["proposal"])) is True:
                res = open_pr(Proposal(**r["proposal"]), rt.client(), rt.store, rt.approved_by)
                if (risk := s.get("risks", {}).get(r["dependency_id"])):    # the risk the approver saw
                    rt.store.set_risk(r["dependency_id"], r["proposal"]["target_version"],
                                      r["proposal"]["attempt"], risk)
                prs.append({**row, "outcome": res.outcome, "pr_number": res.pr_number, "pr_url": res.pr_url})
            else:
                prs.append({**row, "outcome": "not approved - nothing done"})
        return {"prs": prs}

    def watch_ci(s: TriageState):
        if s.get("dry_run") or not s.get("repo") or not rt.store.with_prs(s["repo"]):
            return {"ci": [], "ci_timed_out": False, "diagnoses": {}}
        just_opened = frozenset(p["pr_number"] for p in s.get("prs", []) if p["outcome"] == "created")
        kw = {k: v for k, v in (("sleep", rt.sleep), ("clock", rt.clock)) if v is not None}
        statuses, timed_out = watch(s["repo"], rt.client(), rt.store, wait=rt.wait, timeout=rt.timeout,
                                    interval=rt.interval, just_opened=just_opened, **kw)
        return {"ci": [st.to_dict() for st in statuses], "ci_timed_out": timed_out, "diagnoses": {}}

    def after_watch(s: TriageState) -> str:
        failing = any(c["pr_state"] == "open" and c["ci_status"] == "failing" for c in s.get("ci", []))
        return "diagnose_failure" if failing else "report"

    def diagnose(s: TriageState):
        with llm_budget(rt.llm_budget):
            return _diagnose(s)

    def _diagnose(s: TriageState):
        out = {}
        for c in s["ci"]:
            if c["pr_state"] == "open" and c["ci_status"] == "failing":
                rec = c["record"]
                current = rec["dependency_id"].split("@", 1)[1].split("#", 1)[0]
                out[str(rec["pr_number"])] = diagnose_failure(
                    s["repo"], rec["pr_number"], rec["package"] or rec["dependency_id"], current,
                    rec["target_version"], c["checks"], rt.client(), rt.cache, rt.llm)
        return {"diagnoses": out}

    def report(s: TriageState, config: RunnableConfig):
        _persist(rt, s, config, "complete")
        return {"report_text": _report(s, verbose=False), "report_verbose": _report(s, verbose=True)}

    def _report(s: TriageState, verbose: bool) -> str:
        plans = _plans(s)
        out = ["== PLAN ==", format_scan(plans, _matches(s), s.get("warnings", []), verbose=verbose)]
        rs = s.get("repo_summary") or {}
        if rs:
            out.append("repo: " + (f"Python {rs['python']} ({rs['python_source'] or 'not found'}), "
                                   f"{rs['py_files']} .py files searched at {rs['ref']}" + (f"; {rs['note']}" if rs.get("note") else "")
                                   if "error" not in rs else f"could not be read ({rs['error']}); risk is not repo-aware"))
        if s.get("risks"):
            out.append("\n== UPGRADE RISK (computed from release notes + repo code) ==")
            for p in plans:
                if (risk := s["risks"].get(p.dependency_id)):
                    out.append(f"{p.package} {p.current_version} -> {p.target_version}")
                    out += [f"  {line}" for line in render_risk(risk, verbose=verbose)]
        if verbose and s.get("explanations"):
            out.append("\n== EXPLANATION (LLM, advisory only) ==")
            for p in plans:
                if (e := s["explanations"].get(p.dependency_id)):
                    out.append(f"{p.package} -> {p.target_version} [{e['detail'] or e['status']}]")
                    out += [f"  {line}" for line in Explanation(**e).render().splitlines()]
        out.append("\n== ACTIONS ==")
        if s.get("notice"):
            out.append(s["notice"])
        for pr in s.get("prs", []):
            where = f" -> PR #{pr['pr_number']} {pr['pr_url']}" if pr.get("pr_number") else ""
            why = f" ({pr['reason']})" if pr.get("reason") else ""
            out.append(f"{pr['package']} (attempt {pr['attempt']}, {pr['branch']}): {pr['outcome']}{where}{why}")
        if s.get("ci"):
            out.append("\n== TRIAGE TABLE (PR + CI) ==")
            extra = {int(n): render_diagnosis(d) for n, d in s.get("diagnoses", {}).items()}
            out.append(render_table([PrStatus.from_dict(c) for c in s["ci"]], extra, verbose=verbose))
            if s.get("ci_timed_out"):
                out.append("\nTimed out waiting for CI; pending CI is still pending (not passing).")
        return "\n".join(out)

    g = StateGraph(TriageState)
    for name, fn in [("collect", collect), ("fetch_advisories", fetch_advisories), ("match", match),
                     ("plan", plan), ("assess_upgrade_risk", assess), ("human_approval", human_approval),
                     ("open_pr", open_pr_node), ("watch_ci", watch_ci), ("diagnose_failure", diagnose),
                     ("report", report)]:
        g.add_node(name, fn)
    g.add_edge(START, "collect")
    for a, b in zip(NODES[:7], NODES[1:8]):            # collect ... -> watch_ci
        g.add_edge(a, b)
    g.add_conditional_edges("watch_ci", after_watch, {"diagnose_failure": "diagnose_failure", "report": "report"})
    g.add_edge("diagnose_failure", "report")
    g.add_edge("report", END)
    return g.compile(checkpointer=checkpointer)


def checkpointer(target: str = "checkpoints.db"):
    """LangGraph checkpoints: a SQLite file locally, Postgres when target is a postgres:// URL
    (deployed: paused approvals survive restarts and redeploys). Close with cp.conn.close()."""
    from .db import is_postgres
    if is_postgres(target):
        import psycopg
        from langgraph.checkpoint.postgres import PostgresSaver
        from psycopg.rows import dict_row
        conn = psycopg.connect(target, autocommit=True, prepare_threshold=0, row_factory=dict_row, connect_timeout=15)
        cp = PostgresSaver(conn)
        cp.setup()                                   # idempotent: creates/migrates its tables
        return cp
    return SqliteSaver(sqlite3.connect(target, check_same_thread=False))


sqlite_checkpointer = checkpointer                   # old name, still used by tests/CLI


def pending_interrupt(graph, config) -> dict | None:
    snap = graph.get_state(config)
    for task in snap.tasks:
        for i in task.interrupts:
            return i.value
    return None


def mermaid(graph) -> str:
    return graph.get_graph().draw_mermaid()


def progress(node: str, update: dict) -> str:
    """One short line per finished node, for the CLI."""
    u = update or {}
    if node == "collect":
        src = u.get("requirements_source")
        return f"{len(u.get('dependencies', []))} dependencies" + (f" from {src}" if src else "")
    if node == "fetch_advisories":
        f = u.get("fetched", {})
        n = sum(len(v["advisories"]) + sum(len(o["advisories"]) for o in v["other"]) for v in f.values())
        errors = [k for k, v in f.items() if v["error"]]
        return f"{n} advisory records from osv.dev" + (f", {len(errors)} unavailable" if errors else "")
    if node == "match":
        return f"{len(u.get('matches', []))} decisions"
    if node == "plan":
        ps = u.get("plans", [])
        return ", ".join(f"{p['package']} {p['status']}" for p in ps)
    if node == "assess_upgrade_risk":
        return ", ".join(f"{r['package']} {r['breaking_risk']}" for r in u.get("risks", {}).values()) or "no upgrades"
    if node == "human_approval":
        return u.get("notice") or ", ".join(f"{r['package']}: {r['action']}" for r in u.get("resolutions", []))
    if node == "open_pr":
        return ", ".join(f"{p['package']}: {p['outcome']}" for p in u.get("prs", [])) or "nothing to do"
    if node == "watch_ci":
        return ", ".join(f"PR #{c['record']['pr_number']} {c['ci_status']}" for c in u.get("ci", [])) or "no PRs to watch"
    if node == "diagnose_failure":
        return ", ".join(f"PR #{n} {d['status']}" for n, d in u.get("diagnoses", {}).items())
    return "done"
