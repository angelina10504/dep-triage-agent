"""Offline tests for the LangGraph orchestration: interrupt/resume, checkpoints, routing, report."""
import json

import pytest
from langgraph.types import Command

from tests.test_github_pr import REPO, REQS, FakeGitHub, Resp, fake_fetch
from triage import __main__ as cli
from triage.github_pr import GitHubClient
from triage.graph import NODES, Runtime, build_graph, mermaid, pending_interrupt, sqlite_checkpointer
from triage.llm import LLMCache
from triage.release_notes import NoteItem, ReleaseNotes
from triage.store import ActionStore

URL = "https://github.com/o/r/blob/9.9/CHANGES.rst#L10"
ERR = "E   ImportError: cannot import name 'url_quote' from 'werkzeug.urls'"
LOG = f"collecting\n{ERR}\n##[error]Process completed with exit code 2.\nCleaning up"


class Text:
    def __init__(self, text):
        self.status_code, self.text = 200, text


class World(FakeGitHub):
    """FakeGitHub + check runs per branch and job logs."""

    def __init__(self, ci="failure"):
        super().__init__({"requirements.txt": REQS})
        self.ci = ci

    def request(self, method, url, params=None, json=None, timeout=None):
        path = url.split("api.github.com", 1)[-1]
        if path.endswith("/check-runs"):
            self.calls.append((method, path))
            return Resp(200, {"check_runs": [{
                "name": "test", "status": "completed", "conclusion": self.ci,
                "html_url": f"https://github.com/{REPO}/actions/runs/1/job/77"}]})
        if path.endswith("/actions/jobs/77/logs"):
            self.calls.append((method, path))
            return Text(LOG)
        return super().request(method, url, params=params, json=json, timeout=timeout)


class FakeLLM:
    name, model = "fake", "m"

    def __init__(self):
        self.calls = []

    def complete_json(self, system, user, schema, schema_name):
        self.calls.append(schema_name)
        return {
            "upgrade_explanation": {"summary": "s", "upgrade_risk": "r", "reviewer_checklist": "c"},
            "upgrade_risk": {"breaking_risk": "high", "reasons": "removals",
                             "breaking_changes": [{"change": "removed url_quote", "source_url": URL}]},
            "ci_failure_diagnosis": {"root_cause": "url_quote was removed", "evidence_lines": [ERR],
                                     "suggested_next_step": "use urllib.parse.quote"},
        }[schema_name]


def notes(name, cur, tgt):
    return ReleaseNotes("o/r", [NoteItem("9.0", "Remove previously deprecated code.", URL, "changelog")])


@pytest.fixture
def env(tmp_path):
    gh = World()
    db = str(tmp_path / "t.db")
    rt = Runtime(store=ActionStore(db), cache=LLMCache(db), github=lambda: GitHubClient("t", session=gh),
                 fetch=fake_fetch, other_ecosystems=(), notes=notes, llm=FakeLLM(), wait=False)
    return gh, rt, tmp_path


def start(rt, cp_path, thread="t1", text=REQS, repo=REPO):
    g = build_graph(rt, sqlite_checkpointer(str(cp_path)))
    cfg = {"configurable": {"thread_id": thread}}
    g.invoke({"requirements_text": text, "repo": repo, "path": "requirements.txt"}, cfg)
    return g, cfg


def keys(payload):
    return {p["package"]: p["key"] for p in payload["proposals"]}


def visited(g, cfg, resume):
    nodes = []
    for update in g.stream(Command(resume=resume), cfg, stream_mode="updates"):
        nodes += list(update)
    return nodes


def test_run_pauses_at_human_approval_before_any_write(env):
    gh, rt, tmp = env
    g, cfg = start(rt, tmp / "cp.db")
    payload = pending_interrupt(g, cfg)
    assert set(keys(payload)) == {"requests", "Jinja2"}
    assert "requests==2.32.4" in payload["proposals"][0]["render"]
    assert gh.writes() == [] and gh.pulls == []                  # nothing irreversible yet
    assert g.get_state(cfg).next == ("human_approval",)


def test_approve_one_then_ci_failing_routes_to_diagnosis(env):
    gh, rt, tmp = env
    g, cfg = start(rt, tmp / "cp.db")
    k = keys(pending_interrupt(g, cfg))
    nodes = visited(g, cfg, {k["requests"]: True})              # Jinja2 not answered -> not approved
    assert nodes[-4:] == ["open_pr", "watch_ci", "diagnose_failure", "report"]
    assert [p["head"] for p in gh.pulls] == ["triage/requests-2.32.4"]
    report = g.get_state(cfg).values["report_text"]
    assert "PR failing, NOT fixed" in report and f"evidence: {ERR}" in report
    assert "outcome unchanged: PR failing, NOT fixed" in report
    assert "Jinja2 (attempt 1, triage/jinja2-3.1.6): not approved - nothing done" in report
    assert "breaking risk: high" in report and URL in report


def test_passing_ci_skips_diagnosis(env):
    gh, rt, tmp = env
    gh.ci = "success"
    g, cfg = start(rt, tmp / "cp.db")
    nodes = visited(g, cfg, {keys(pending_interrupt(g, cfg))["requests"]: True})
    assert "diagnose_failure" not in nodes and nodes[-1] == "report"
    assert "PR open, CI passing (awaiting human merge)" in g.get_state(cfg).values["report_text"]
    assert "ci_failure_diagnosis" not in rt.llm.calls


def test_pr_body_has_cited_risk_and_labelled_explanation(env):
    gh, rt, tmp = env
    g, cfg = start(rt, tmp / "cp.db")
    g.invoke(Command(resume={keys(pending_interrupt(g, cfg))["requests"]: True}), cfg)
    body = gh.pulls[0]["body"]
    assert "### Upgrade risk (LLM, cited release notes)" in body and URL in body
    assert "### Explanation (LLM, advisory only)" in body


@pytest.mark.parametrize("answer", ["yes", 1, "True", None])
def test_only_literal_true_approves(env, answer):
    gh, rt, tmp = env
    g, cfg = start(rt, tmp / "cp.db")
    g.invoke(Command(resume={keys(pending_interrupt(g, cfg))["requests"]: answer}), cfg)
    assert gh.pulls == []


def test_resume_from_a_new_process_by_thread_id(env, tmp_path):
    gh, rt, tmp = env
    cp = tmp / "cp.db"
    g1, cfg = start(rt, cp, thread="demo-1")
    k = keys(pending_interrupt(g1, cfg))["requests"]
    del g1                                                     # "process" ends while paused

    db = str(tmp / "t.db")
    rt2 = Runtime(store=ActionStore(db), cache=LLMCache(db), github=lambda: GitHubClient("t", session=gh),
                  fetch=fake_fetch, other_ecosystems=(), notes=notes, llm=FakeLLM(), wait=False)
    g2 = build_graph(rt2, sqlite_checkpointer(str(cp)))        # new graph, same checkpoint file
    assert pending_interrupt(g2, cfg) is not None
    g2.invoke(Command(resume={k: True}), cfg)
    assert [p["head"] for p in gh.pulls] == ["triage/requests-2.32.4"]
    assert pending_interrupt(g2, {"configurable": {"thread_id": "other"}}) is None


def test_no_upgrade_plans_never_contacts_github(env):
    _, rt, tmp = env

    def explode():
        raise AssertionError("GitHub must not be contacted")
    rt.github = explode
    g, cfg = start(rt, tmp / "cp.db", text="MarkupSafe==2.0.1\n")
    values = g.get_state(cfg).values
    assert pending_interrupt(g, cfg) is None
    assert "No upgrade plans - no PRs proposed." in values["report_text"]


def test_scan_only_without_repo_has_no_interrupt(env):
    gh, rt, tmp = env
    g, cfg = start(rt, tmp / "cp.db", repo=None)
    assert pending_interrupt(g, cfg) is None and gh.calls == []
    assert "scan only" in g.get_state(cfg).values["report_text"]


def test_mermaid_shows_every_node_and_the_conditional_edge():
    m = mermaid(build_graph(Runtime(store=None, cache=None)))
    for node in NODES:
        assert node in m
    assert "watch_ci -.-> diagnose_failure" in m and "watch_ci -.-> report" in m


def test_cli_pause_then_resume_by_thread(env, monkeypatch, capsys):
    gh, rt, tmp = env
    reqs = tmp / "requirements.txt"
    reqs.write_text(REQS)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("LLM_PROVIDER", "none")
    monkeypatch.setattr("triage.github_pr.GitHubClient", lambda token: GitHubClient("t", session=gh))
    monkeypatch.setattr("triage.osv.fetch_advisories", fake_fetch)
    monkeypatch.setattr("triage.release_notes.fetch_release_notes", lambda *a, **k: ReleaseNotes(None))
    common = ["--db", str(tmp / "c.db"), "--checkpoints", str(tmp / "c-cp.db"), "--no-wait"]

    def no_terminal(_):
        raise EOFError
    monkeypatch.setattr("builtins.input", no_terminal)
    assert cli.main(["run", str(reqs), "--repo", REPO, "--thread", "th-9"] + common) == 0
    assert "Paused at human_approval. Resume with: python -m triage resume --thread th-9" in capsys.readouterr().out
    assert gh.pulls == []

    answers = iter(["y", "n"])
    monkeypatch.setattr("builtins.input", lambda _: next(answers))
    assert cli.main(["resume", "--thread", "th-9"] + common) == 0
    out = capsys.readouterr().out
    assert [p["head"] for p in gh.pulls] == ["triage/requests-2.32.4"] and "== TRIAGE TABLE" in out
