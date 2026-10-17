"""Offline tests for the CI watcher: CI status rules, outcome labels, history, --wait.

FakeGitHub serves canned PR / check-run / commit-status JSON; a path can map to a
list of responses to simulate CI changing between polls.
"""
import json
from urllib.parse import urlparse

import pytest

from triage.ci_watch import (OUTCOME_CLOSED, OUTCOME_FAILING, OUTCOME_MERGED, OUTCOME_PASSING,
                             OUTCOME_PENDING, OUTCOME_UNKNOWN, Check, ci_status, render_table, watch)
from triage.github_pr import GitHubClient
from triage.store import ActionStore

REPO = "acme/demo"
ADVS = [{"id": "GHSA-1", "aliases": ["CVE-1"]}, {"id": "PYSEC-1", "aliases": ["CVE-1"]},
        {"id": "GHSA-2", "aliases": ["CVE-2"]}]


class Resp:
    def __init__(self, body, status=200):
        self.status_code, self._body, self.text = status, body, json.dumps(body)

    def json(self):
        return self._body


class FakeGitHub:
    def __init__(self, routes):
        self.headers, self.routes, self.calls = {}, routes, []

    def request(self, method, url, params=None, json=None, timeout=None):
        path = urlparse(url).path
        assert method == "GET", "the watcher must only read"
        self.calls.append(path)
        body = self.routes[path]
        if isinstance(body, list):                 # sequence: advance once per call, stick on the last
            body = body.pop(0) if len(body) > 1 else body[0]
        return Resp(body)


def pr(state="open", merged=False, sha="abc1234def", merged_at=None):
    return {"state": state, "merged": merged, "merged_at": merged_at, "head": {"sha": sha}}


def run(name, status="completed", conclusion="success"):
    return {"name": name, "status": status, "conclusion": conclusion,
            "html_url": f"https://github.com/{REPO}/actions/runs/{name}"}


def routes(pr_body, check_runs, statuses=(), sha="abc1234def", n=1):
    return {
        f"/repos/{REPO}/pulls/{n}": pr_body,
        f"/repos/{REPO}/commits/{sha}/check-runs": check_runs,
        f"/repos/{REPO}/commits/{sha}/status": {"statuses": list(statuses)},
    }


def check_runs(*runs):
    return {"check_runs": list(runs)}


@pytest.fixture
def store(tmp_path):
    s = ActionStore(str(tmp_path / "t.db"))
    s.record_approval("PyPI:x@1.0#L1", "2.0", REPO, "triage/x-2.0", "tester", "x", ADVS)
    s.record_pr("PyPI:x@1.0#L1", "2.0", 1, f"https://github.com/{REPO}/pull/1")
    return s


def observe_once(store, r):
    gh = FakeGitHub(r)
    statuses, timed_out = watch(REPO, GitHubClient("t", session=gh), store)
    assert not timed_out and len(statuses) == 1
    return statuses[0], gh


# ---------- the six required cases ----------

def test_passing(store):
    s, _ = observe_once(store, routes(pr(), check_runs(run("test (push)"), run("test (pull_request)"))))
    assert (s.pr_state, s.ci_status, s.outcome) == ("open", "passing", OUTCOME_PASSING)


def test_failing_when_one_of_two_checks_failed(store):
    s, _ = observe_once(store, routes(pr(), check_runs(run("lint"), run("test", conclusion="failure"))))
    assert (s.ci_status, s.outcome) == ("failing", OUTCOME_FAILING)
    assert "fixed" not in s.outcome.replace("NOT fixed", "")
    assert [(c.name, c.state) for c in s.checks] == [("lint", "success"), ("test", "failure")]
    assert s.checks[1].url.endswith("/runs/test")                       # evidence kept


def test_pending_then_passing_with_wait(store):
    sha_runs = [check_runs(run("test", status="in_progress", conclusion=None)),
                check_runs(run("test", status="in_progress", conclusion=None)),
                check_runs(run("test"))]
    gh = FakeGitHub(routes(pr(), sha_runs))
    sleeps = []
    statuses, timed_out = watch(REPO, GitHubClient("t", session=gh), store, wait=True,
                                timeout=600, interval=15, sleep=sleeps.append, clock=lambda: 0)
    assert not timed_out and sleeps == [15, 15]
    assert (statuses[0].ci_status, statuses[0].outcome) == ("passing", OUTCOME_PASSING)
    history = [o["ci_status"] for o in store.observations("PyPI:x@1.0#L1", "2.0")]
    assert history == ["pending", "pending", "passing"]                # history kept, not overwritten


def test_merged_is_not_deployed(store):
    s, _ = observe_once(store, routes(pr("closed", merged=True, merged_at="2026-10-18T10:00:00Z"),
                                      check_runs(run("test"))))
    assert (s.pr_state, s.outcome) == ("merged", OUTCOME_MERGED)
    assert "NOT deployed" in s.outcome
    assert "no deployment was observed" in render_table([s])


def test_closed_unmerged(store):
    s, _ = observe_once(store, routes(pr("closed"), check_runs(run("test"))))
    assert (s.pr_state, s.outcome) == ("closed", OUTCOME_CLOSED)


def test_no_checks_is_unknown(store):
    s, _ = observe_once(store, routes(pr(), check_runs()))
    assert (s.ci_status, s.outcome) == ("unknown", OUTCOME_UNKNOWN)


# ---------- rules and extras ----------

def test_commit_statuses_count_too(store):
    s, _ = observe_once(store, routes(pr(), check_runs(run("test")),
                                      statuses=[{"context": "ci/legacy", "state": "error", "target_url": "u"}]))
    assert s.ci_status == "failing" and s.checks[-1].kind == "status"


@pytest.mark.parametrize("states, expected", [
    (["success", "skipped", "neutral"], "passing"),
    (["success", "queued"], "pending"),
    (["queued", "cancelled"], "failing"),          # failure beats pending
    (["timed_out"], "failing"),
    (["success", "action_required"], "unknown"),   # not evidence of success
])
def test_ci_status_rules(states, expected):
    assert ci_status([Check(f"c{i}", "check_run", s, None) for i, s in enumerate(states)]) == expected


def test_wait_times_out_and_stays_pending(store):
    gh = FakeGitHub(routes(pr(), check_runs(run("test", status="queued", conclusion=None))))
    t = iter(range(0, 10_000, 15))
    statuses, timed_out = watch(REPO, GitHubClient("t", session=gh), store, wait=True,
                                timeout=60, interval=15, sleep=lambda _: None, clock=lambda: next(t))
    assert timed_out and statuses[0].outcome == OUTCOME_PENDING


def test_observation_records_intended_vs_observed(store):
    observe_once(store, routes(pr(), check_runs(run("test", conclusion="failure"))))
    (o,) = store.observations("PyPI:x@1.0#L1", "2.0")
    assert (o["intended_state"], o["ci_status"], o["head_sha"]) == ("ci_passing", "failing", "abc1234def")
    assert o["observed_at"] and o["checks"][0]["state"] == "failure"


def test_table_shows_unique_count_and_ids(store):
    s, _ = observe_once(store, routes(pr(), check_runs(run("test"))))
    table = render_table([s])
    assert "2 vulns (3 records)" in table and "GHSA-1, PYSEC-1, GHSA-2" in table
    assert f"https://github.com/{REPO}/pull/1" in table


def test_old_db_without_advisory_columns_is_migrated(tmp_path):
    import sqlite3
    path = str(tmp_path / "old.db")
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE actions (dependency_id TEXT, target_version TEXT, repo TEXT, branch TEXT,"
               " status TEXT, approved_by TEXT, approved_at TEXT, pr_number INTEGER, pr_url TEXT,"
               " updated_at TEXT, PRIMARY KEY (dependency_id, target_version))")
    db.execute("INSERT INTO actions VALUES ('d', '2.0', 'r', 'b', 'pr_opened', 'u', 't', 1, 'url', 't')")
    db.commit()
    s = ActionStore(path)
    s.fill_advisories("d", "2.0", "x", ADVS)
    rec = s.get("d", "2.0")
    assert rec.package == "x" and len(rec.advisories) == 3
