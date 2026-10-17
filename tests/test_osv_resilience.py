"""Offline tests: OSV retries with backoff, and an unreachable source means "uncertain", never a PR."""
import pytest
import requests

from triage import __main__ as cli
from triage import osv
from triage.models import PlanStatus
from triage.scanner import scan


class Resp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body, self.text = status, body or {"vulns": []}, "x"

    def json(self):
        return self._body


class FlakySession:
    """Plays back a script of outcomes: an exception class to raise, or a Resp to return."""

    def __init__(self, *script):
        self.script, self.calls = list(script), 0

    def post(self, url, json=None, timeout=None):
        self.calls += 1
        item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(item, type) and issubclass(item, Exception):
            raise item("boom")
        return item


@pytest.fixture
def sleeps(monkeypatch):
    log = []
    monkeypatch.setattr(osv, "_sleep", log.append)
    return log


def use(monkeypatch, session):
    monkeypatch.setattr(osv, "_session", session)
    return session


ADV = {"id": "A1", "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"},
                                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.4"}]}]}]}


def test_timeout_then_success(monkeypatch, sleeps):
    s = use(monkeypatch, FlakySession(requests.Timeout, Resp(body={"vulns": [ADV]})))
    vulns, _ = osv.fetch_advisories("requests")
    assert [v["id"] for v in vulns] == ["A1"] and s.calls == 2 and sleeps == [1]


@pytest.mark.parametrize("failure", [requests.Timeout, requests.ConnectionError, Resp(503), Resp(429)])
def test_all_retries_fail_raises_with_backoff(monkeypatch, sleeps, failure):
    s = use(monkeypatch, FlakySession(failure))
    with pytest.raises(osv.AdvisorySourceError):
        osv.fetch_advisories("requests")
    assert s.calls == 4 and sleeps == [1, 2, 4]          # first try + 3 retries


def test_client_error_is_not_retried(monkeypatch, sleeps):
    s = use(monkeypatch, FlakySession(Resp(400)))
    with pytest.raises(osv.AdvisorySourceError, match="HTTP 400"):
        osv.fetch_advisories("requests")
    assert s.calls == 1 and sleeps == []


def test_unreachable_source_makes_plan_uncertain(monkeypatch, sleeps):
    use(monkeypatch, FlakySession(requests.Timeout))
    plan = scan("requests==2.28.0\n", fetch=osv.fetch_advisories, other_ecosystems=()).plans[0]
    assert plan.status == PlanStatus.UNCERTAIN and plan.target_version is None
    assert plan.reason == "advisory source unavailable: Timeout"


def test_unreachable_source_opens_no_pr_and_prints_no_traceback(monkeypatch, sleeps, tmp_path, capsys):
    use(monkeypatch, FlakySession(requests.ConnectionError))
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("requests==2.28.0\n")
    monkeypatch.setenv("GITHUB_TOKEN", "t")

    def no_github(*a, **k):
        raise AssertionError("GitHub must not be contacted for an uncertain plan")
    monkeypatch.setattr("triage.github_pr.GitHubClient", no_github)
    code = cli.main([str(reqs), "--repo", "acme/demo", "--open-prs", "--db", str(tmp_path / "t.db")])
    out = capsys.readouterr().out
    assert code == 0
    assert "uncertain" in out and "advisory source unavailable: ConnectionError" in out
    assert "No upgrade plans - no PRs proposed." in out


def test_cli_reports_one_line_error(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["triage", "does-not-exist.txt"])
    assert cli.cli() == 1
    err = capsys.readouterr().err
    assert err.startswith("error: FileNotFoundError") and "Traceback" not in err
