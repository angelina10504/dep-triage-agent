"""Offline tests for the upgrade-PR action: approval gate, PR content, idempotency.

GitHub is replaced by FakeGitHub, an in-memory stand-in for the few REST calls
we use. No test touches the network.
"""
import base64
import json
from urllib.parse import urlparse

import pytest

from triage import __main__ as cli
from triage.github_pr import (GitHubClient, StaleProposal, ask_approval, branch_name,
                              build_proposal, bump_line, open_pr, resolve)
from triage.models import PlanStatus
from triage.scanner import scan
from triage.store import ActionStore

REPO = "acme/demo"
REQS = "requests==2.19.0\nJinja2==2.10  # templating\nMarkupSafe==2.0.1\n"
T = "2026-10-17T00:00:00+00:00"


class Resp:
    def __init__(self, status, body):
        self.status_code, self._body, self.text = status, body, json.dumps(body)

    def json(self):
        return self._body


class FakeGitHub:
    """Just enough of the GitHub REST API, with a call log."""

    def __init__(self, files):
        self.headers = {}
        self.branches = {"main": "sha-main"}
        self.files = {"main": dict(files)}
        self.pulls = []
        self.calls = []

    def request(self, method, url, params=None, json=None, timeout=None):
        path = urlparse(url).path
        self.calls.append((method, path))
        if path == f"/repos/{REPO}" and method == "GET":
            return Resp(200, {"default_branch": "main"})
        if path.startswith(f"/repos/{REPO}/git/ref/heads/"):
            b = path.rsplit("/heads/", 1)[1]
            return Resp(200, {"object": {"sha": self.branches[b]}}) if b in self.branches else Resp(404, {})
        if path == f"/repos/{REPO}/git/refs" and method == "POST":
            b = json["ref"].removeprefix("refs/heads/")
            self.branches[b] = json["sha"]
            self.files[b] = dict(self.files["main"])
            return Resp(201, {})
        if path.startswith(f"/repos/{REPO}/contents/"):
            fp = path.split("/contents/", 1)[1]
            if method == "GET":
                text = self.files[params["ref"]][fp]
                return Resp(200, {"content": base64.b64encode(text.encode()).decode(), "sha": f"blob-{hash(text)}"})
            self.files[json["branch"]][fp] = base64.b64decode(json["content"]).decode()
            return Resp(200, {"commit": {"sha": "c1"}})
        if path == f"/repos/{REPO}/pulls" and method == "GET":
            head = params["head"].split(":", 1)[1]
            return Resp(200, [p for p in self.pulls if p["head"] == head])
        if path == f"/repos/{REPO}/pulls" and method == "POST":
            n = len(self.pulls) + 1
            pr = {"number": n, "html_url": f"https://github.com/{REPO}/pull/{n}",
                  "state": "open", "merged": False, "merged_at": None, **json}
            self.pulls.append(pr)
            return Resp(201, pr)
        if "/commits/" in path and path.endswith("/check-runs"):
            return Resp(200, {"check_runs": []})
        if "/commits/" in path and path.endswith("/status"):
            return Resp(200, {"statuses": []})
        if path.startswith(f"/repos/{REPO}/pulls/") and method == "GET":
            n = int(path.rsplit("/", 1)[1])
            pr = self.pulls[n - 1]            # real GitHub: head is an object with the commit sha
            return Resp(200, {**pr, "head": {"ref": pr["head"], "sha": f"sha-{pr['head']}"}})
        raise AssertionError(f"unexpected call {method} {path}")

    def merge(self, n):
        """Simulate a human merging PR n: base gets the branch's file."""
        pr = self.pulls[n - 1]
        pr.update(state="closed", merged=True, merged_at="2026-10-18T10:00:00Z")
        self.files["main"] = dict(self.files[pr["head"]])

    def writes(self):
        return [c for c in self.calls if c[0] in ("POST", "PUT")]


def fake_fetch(name, ecosystem):
    advisories = {
        "requests": [{
            "id": "GHSA-TEST-REQ", "summary": "test",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.4"}]}]}],
        }],
        "jinja2": [{
            "id": "GHSA-TEST-JIN", "summary": "test",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "jinja2"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.6"}]}]}],
        }],
    }
    return (advisories.get(name, []) if ecosystem == "PyPI" else []), T


@pytest.fixture
def setup(tmp_path):
    result = scan(REQS, fetch=fake_fetch)
    deps = {d.id: d for d in result.dependencies}
    upgrades = [p for p in result.plans if p.status == PlanStatus.UPGRADE]
    proposals = [build_proposal(p, deps[p.dependency_id], result.matches, REPO, "main", "requirements.txt")
                 for p in upgrades]
    gh = FakeGitHub({"requirements.txt": REQS})
    client = GitHubClient("t0ken", session=gh)
    store = ActionStore(str(tmp_path / "t.db"))
    return proposals, gh, client, store


# ---------- proposal ----------

def test_proposal_has_exact_line_change_branch_and_evidence(setup):
    proposals, *_ = setup
    req, jin = proposals
    assert (req.branch, req.line, req.old_line, req.new_line) == (
        "triage/requests-2.32.4", 1, "requests==2.19.0", "requests==2.32.4")
    assert jin.new_line == "Jinja2==3.1.6  # templating"       # comment kept
    assert jin.branch == "triage/jinja2-3.1.6"
    for text in ("GHSA-TEST-REQ", "https://osv.dev/vulnerability/GHSA-TEST-REQ",
                 ">=0, <2.32.4", "osv.dev", T, "human approval"):
        assert text in req.body


def test_bump_line_only_touches_the_version():
    assert bump_line("uvicorn[standard] == 0.30.0 ; python_version>'3.8'", "0.30.0", "0.31.0") == \
        "uvicorn[standard] == 0.31.0 ; python_version>'3.8'"
    with pytest.raises(StaleProposal):
        bump_line("requests==2.19.01", "2.19.0", "2.32.4")     # 2.19.0 is a prefix, not the pin


def test_branch_name_is_safe():
    assert branch_name("zope.interface", "6.0") == "triage/zope.interface-6.0"


# ---------- approval gate ----------

@pytest.mark.parametrize("answer, approved", [
    ("y", True), ("YES", True), (" y ", True), ("", False), ("n", False), ("sure", False)])
def test_only_explicit_yes_approves(setup, answer, approved):
    proposals, *_ = setup
    assert ask_approval(proposals[0], input_fn=lambda _: answer, print_fn=lambda _: None) is approved


def test_no_terminal_means_no_approval(setup):
    def eof(_):
        raise EOFError
    proposals, *_ = setup
    assert ask_approval(proposals[0], input_fn=eof, print_fn=lambda _: None) is False


# ---------- action + idempotency ----------

def test_open_pr_creates_branch_commits_one_line_and_opens_pr(setup):
    proposals, gh, client, store = setup
    r = open_pr(proposals[0], client, store, approved_by="tester")
    assert (r.outcome, r.pr_number) == ("created", 1)
    assert gh.files["triage/requests-2.32.4"]["requirements.txt"] == REQS.replace("2.19.0", "2.32.4")
    assert gh.files["main"]["requirements.txt"] == REQS                     # base untouched
    assert gh.pulls[0]["head"] == "triage/requests-2.32.4" and gh.pulls[0]["base"] == "main"
    rec = store.get(proposals[0].dependency_id, "2.32.4")
    assert (rec.status, rec.pr_url, rec.approved_by) == ("pr_opened", r.pr_url, "tester")
    assert (rec.package, rec.advisories) == ("requests", [{"id": "GHSA-TEST-REQ", "aliases": []}])


def test_retry_uses_store_and_makes_no_github_calls(setup):
    proposals, gh, client, store = setup
    open_pr(proposals[0], client, store)
    gh.calls.clear()
    r = open_pr(proposals[0], client, store)
    assert r.outcome == "existing_in_store" and gh.calls == [] and len(gh.pulls) == 1


def test_existing_pr_on_github_is_reused_even_with_empty_store(setup, tmp_path):
    proposals, gh, client, store = setup
    open_pr(proposals[0], client, store)
    fresh_store = ActionStore(str(tmp_path / "fresh.db"))     # e.g. DB lost, new machine
    gh.calls.clear()
    r = open_pr(proposals[0], client, fresh_store)
    assert r.outcome == "existing_on_github" and r.pr_number == 1
    assert gh.writes() == [] and len(gh.pulls) == 1
    assert fresh_store.get(proposals[0].dependency_id, "2.32.4").pr_url == r.pr_url


def test_crash_after_commit_does_not_commit_twice(setup):
    proposals, gh, client, store = setup
    # Simulate an earlier run that created the branch and committed, then died before the PR.
    gh.branches["triage/requests-2.32.4"] = "sha-main"
    gh.files["triage/requests-2.32.4"] = {"requirements.txt": REQS.replace("2.19.0", "2.32.4")}
    r = open_pr(proposals[0], client, store)
    assert r.outcome == "created"
    assert [c for c in gh.writes() if c[0] == "PUT"] == []          # no second commit
    assert [c for c in gh.writes() if c[1].endswith("/git/refs")] == []   # no second branch


def test_stale_file_aborts_before_commit(setup):
    proposals, gh, client, store = setup
    gh.files["main"]["requirements.txt"] = "requests==2.31.0\n"       # someone changed it meanwhile
    with pytest.raises(StaleProposal):
        open_pr(proposals[0], client, store)
    assert gh.pulls == [] and not any(c[0] == "PUT" for c in gh.calls)


def test_github_error_is_raised_not_swallowed(setup):
    proposals, gh, client, store = setup
    gh.request = lambda *a, **k: Resp(403, {"message": "Resource not accessible by token"})
    with pytest.raises(Exception, match="403"):
        open_pr(proposals[0], client, store)


# ---------- re-runs: merged/closed PR but base still vulnerable ----------

def _reset_main(gh):
    """What scripts/reset_demo.sh does: a new commit on main restoring the old pin."""
    gh.files["main"] = {"requirements.txt": REQS}


def test_merged_pr_and_file_vulnerable_again_needs_approval_then_opens_new_pr(setup):
    proposals, gh, client, store = setup
    p = proposals[0]
    open_pr(p, client, store)
    gh.merge(1)
    _reset_main(gh)

    res = resolve(p, client, store)
    assert res.action == "new" and res.proposal.attempt == 2
    assert res.proposal.branch == "triage/requests-2.32.4-2"
    assert "previous PR #1 was merged" in res.proposal.body
    assert gh.writes() and all(c[0] == "GET" for c in gh.calls[-3:])   # resolve itself only reads

    # Declined -> nothing happens.
    assert not ask_approval(res.proposal, input_fn=lambda _: "n", print_fn=lambda _: None)
    assert len(gh.pulls) == 1
    # Approved -> a fresh branch and PR #2; PR #1 untouched.
    r = open_pr(res.proposal, client, store)
    assert (r.outcome, r.pr_number) == ("created", 2)
    assert gh.pulls[1]["head"] == "triage/requests-2.32.4-2" and gh.pulls[0]["merged"]
    assert gh.files["triage/requests-2.32.4-2"]["requirements.txt"] == REQS.replace("2.19.0", "2.32.4")
    assert store.get(p.dependency_id, "2.32.4").attempt == 2
    assert store.get(p.dependency_id, "2.32.4", 1).pr_number == 1


def test_open_pr_is_reused_not_duplicated(setup, tmp_path):
    proposals, gh, client, store = setup
    open_pr(proposals[0], client, store)
    for s in (store, ActionStore(str(tmp_path / "fresh.db"))):     # also with an empty store
        gh.calls.clear()
        res = resolve(proposals[0], client, s)
        assert (res.action, res.pr["number"]) == ("reuse", 1)
        assert gh.writes() == [] and len(gh.pulls) == 1


def test_merged_pr_and_file_already_fixed_is_no_action(setup):
    proposals, gh, client, store = setup
    open_pr(proposals[0], client, store)
    gh.merge(1)                                      # main now pins 2.32.4
    gh.calls.clear()
    res = resolve(proposals[0], client, store)
    assert res.action == "no_action" and "no longer 'requests==2.19.0'" in res.reason
    assert gh.writes() == [] and len(gh.pulls) == 1


def test_closed_unmerged_and_still_vulnerable_is_new_attempt(setup):
    proposals, gh, client, store = setup
    open_pr(proposals[0], client, store)
    gh.pulls[0]["state"] = "closed"
    res = resolve(proposals[0], client, store)
    assert res.action == "new" and res.proposal.attempt == 2


def test_second_rerun_reuses_attempt_2_instead_of_opening_attempt_3(setup):
    proposals, gh, client, store = setup
    open_pr(proposals[0], client, store)
    gh.merge(1)
    _reset_main(gh)
    open_pr(resolve(proposals[0], client, store).proposal, client, store)
    res = resolve(proposals[0], client, store)
    assert (res.action, res.proposal.attempt, res.pr["number"]) == ("reuse", 2, 2)


def test_cli_rerun_after_merge_asks_and_respects_no(setup, tmp_path, monkeypatch, capsys):
    """Through the LangGraph run: the y/N answer is the resume value of the approval interrupt."""
    from triage.release_notes import ReleaseNotes
    _, gh, client, _ = setup
    db, cp = str(tmp_path / "cli.db"), str(tmp_path / "cp.db")
    reqs = tmp_path / "requirements.txt"
    reqs.write_text(REQS)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    monkeypatch.setenv("LLM_PROVIDER", "none")
    monkeypatch.setattr("triage.github_pr.GitHubClient", lambda token: client)
    monkeypatch.setattr("triage.osv.fetch_advisories", fake_fetch)
    monkeypatch.setattr("triage.release_notes.fetch_release_notes", lambda *a, **k: ReleaseNotes(None, note="none"))

    def run(answers, thread):
        it = iter(answers)
        monkeypatch.setattr("builtins.input", lambda _: next(it))
        assert cli.main(["run", str(reqs), "--repo", REPO, "--db", db, "--checkpoints", cp,
                         "--thread", thread, "--no-wait"]) == 0
        return capsys.readouterr().out

    run(["y", "n"], "t1")                            # requests: yes, Jinja2: no
    assert len(gh.pulls) == 1
    gh.merge(1)
    _reset_main(gh)

    out = run(["n", "n"], "t2")                      # re-run: decline the new requests attempt
    assert "new action, attempt 2" in out and len(gh.pulls) == 1

    run(["y", "n"], "t3")                            # re-run: approve it
    assert [p["head"] for p in gh.pulls] == ["triage/requests-2.32.4", "triage/requests-2.32.4-2"]
