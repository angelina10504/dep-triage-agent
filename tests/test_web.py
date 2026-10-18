"""Offline tests for the web UI: auth + CSRF on every action, the approval flow
(risk shown -> approve -> resume -> PR), CI refresh, and live TC1-TC4 results.
GitHub, OSV and the LLM are the same fakes the graph tests use; jobs run inline."""
import re
import threading

import pytest
from fastapi.testclient import TestClient

from tests.test_github_pr import REPO, T, fake_fetch
from tests.test_graph import FakeLLM, World, notes
from triage.github_pr import GitHubClient
from triage.graph import Runtime
from triage.llm import LLMCache
from triage.store import ActionStore
from triage.web.app import WebConfig, create_app, safe_url
from triage.web.runs import Busy, JobRunner, RunStore

PW = "correct horse"


def fetch(name, ecosystem):
    """PyPI advisories from the shared fake + one npm advisory named like a PyPI package (TC2)."""
    if ecosystem == "npm" and name == "markupsafe":
        return [{"id": "GHSA-NPM-MARKUPSAFE", "summary": "npm package with the same name",
                 "affected": [{"package": {"ecosystem": "npm", "name": "markupsafe"},
                               "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}]}]}], T
    return fake_fetch(name, ecosystem)


@pytest.fixture
def web(tmp_path, db_target):
    """Runs every web test twice: on SQLite and (when available) on Postgres, like Neon."""
    gh = World(ci="failure")
    db = db_target
    (tmp_path / "ev").mkdir()
    (tmp_path / "ev" / "tc2_excluded.txt").write_text("evidence")

    def make_runtime(github=True):
        return Runtime(store=ActionStore(db), cache=LLMCache(db),
                       github=(lambda: GitHubClient("t", session=gh)) if github else None,
                       fetch=fetch, other_ecosystems=("npm",), notes=notes, llm=FakeLLM(), wait=False)

    cfg = WebConfig(db=db, checkpoints=db if db.startswith("postgres") else str(tmp_path / "cp.db"), repo=REPO, password=PW, secret="s" * 32,
                    evidence_dir=str(tmp_path / "ev"), make_runtime=make_runtime, background=False)
    return TestClient(create_app(cfg)), gh, db, cfg


def csrf(client, url="/"):
    return re.search(r'name="csrf-token" content="([^"]+)"', client.get(url).text).group(1)


def login(client, name="alice", password=PW):
    return client.post("/login", data={"name": name, "password": password, "csrf_token": csrf(client, "/login")},
                       follow_redirects=False)


def post(client, url, **data):
    return client.post(url, data={"csrf_token": csrf(client), **data}, follow_redirects=False)


def badges(html):
    return dict((tc, res) for res, tc in re.findall(r'class="badge \w+">(\w+)</span> (TC\d)', html))


def awaiting(db):
    runs = RunStore(db).awaiting()
    assert len(runs) == 1
    return runs[0]


def idx_of(run, package):
    return next(i for i, p in enumerate(run["interrupt"]["proposals"]) if p["package"] == package)


# ---------------------------------------------------------------- security

def test_viewing_is_public_and_has_security_headers(web):
    client, *_ = web
    for url in ("/", "/test-cases", "/login"):
        r = client.get(url)
        assert r.status_code == 200
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


@pytest.mark.parametrize("url", ["/approvals/web-x/0/approve", "/approvals/web-x/0/reject", "/scan", "/refresh",
                                 "/approvals/web-x/resume"])
def test_actions_without_password_are_403(web, url):
    client, gh, db, _ = web
    r = client.post(url, data={"csrf_token": csrf(client)})
    assert r.status_code == 403
    assert RunStore(db).jobs() == [] and gh.calls == []


def test_approve_without_password_403_even_on_a_real_pending_run(web):
    client, gh, db, _ = web
    login(client)
    post(client, "/scan")
    run = awaiting(db)
    other = TestClient(client.app)                                     # a visitor without a login
    i = idx_of(run, "requests")
    other.get(f"/approvals/{run['thread_id']}/{i}/risk")                # even after seeing the risk
    r = other.post(f"/approvals/{run['thread_id']}/{i}/approve", data={"csrf_token": csrf(other)})
    assert r.status_code == 403
    assert RunStore(db).decisions() == [] and gh.pulls == []


def test_missing_or_wrong_csrf_is_403(web):
    client, gh, db, _ = web
    login(client)
    assert client.post("/scan", data={}).status_code == 403
    assert client.post("/scan", data={"csrf_token": "nope"}).status_code == 403
    assert client.post("/refresh", headers={"X-CSRF-Token": "nope"}).status_code == 403
    assert RunStore(db).jobs() == []


def test_csrf_header_is_accepted(web):
    client, *_ = web
    login(client)
    r = client.post("/refresh", headers={"X-CSRF-Token": csrf(client)}, follow_redirects=False)
    assert r.status_code == 303


def test_wrong_password_does_not_log_in_and_is_rate_limited(web):
    client, *_ = web
    for _ in range(5):
        assert login(client, password="wrong").status_code == 401
    assert post(client, "/scan").status_code == 403
    assert login(client).status_code == 429                            # even the right one, for a while


def test_login_needs_csrf(web):
    client, *_ = web
    client.get("/login")
    r = client.post("/login", data={"name": "a", "password": PW, "csrf_token": "x"})
    assert r.status_code == 403


def test_no_app_password_means_nobody_can_act(web, tmp_path):
    _, _, _, cfg = web
    cfg.password = None
    client = TestClient(create_app(cfg))
    assert login(client, password="").status_code == 401
    assert post(client, "/scan").status_code == 403


def test_evidence_files_are_whitelisted(web):
    client, *_ = web
    assert client.get("/evidence/tc2_excluded.txt").text == "evidence"
    assert client.get("/evidence/..%2F..%2Ft.db").status_code == 404
    assert client.get("/evidence/missing.txt").status_code == 404


def test_safe_url_blocks_script_links():
    assert safe_url("javascript:alert(1)") == "#"
    assert safe_url("https://osv.dev/x") == "https://osv.dev/x"
    assert safe_url(None) == "#"


# ---------------------------------------------------------------- full flow

def test_scan_approve_after_risk_resume_refresh_and_test_cases(web):
    client, gh, db, _ = web
    assert login(client).status_code == 303

    # Run scan: runs the graph until human_approval, with progress lines
    r = post(client, "/scan")
    assert r.status_code == 303 and r.headers["location"] == "/jobs/1"
    page = client.get("/jobs/1").text
    assert "human_approval: waiting for approval" in page and "assess_upgrade_risk: requests high" in page
    assert "Review and approve" in page and gh.pulls == []
    run = awaiting(db)
    t = run["thread_id"]

    # Approval page: diff + advisories; Approve disabled until the risk panel is served
    page = client.get(f"/approvals/{t}").text
    assert "- requests==2.19.0" in page and "+ requests==2.32.4" in page and "GHSA-TEST-REQ" in page
    assert "Approve (read the risk first)" in page
    req, jin = idx_of(run, "requests"), idx_of(run, "Jinja2")
    assert post(client, f"/approvals/{t}/{req}/approve").status_code == 409
    risk = client.get(f"/approvals/{t}/{req}/risk", headers={"HX-Request": "true"}).text
    assert 'class="risk high"' in risk and "app.py:1" in risk and "used by repo" in risk
    assert 'hx-swap-oob="true"' in risk and "Approve: open this PR" in risk

    # approve requests, reject Jinja2 -> run resumes -> exactly one PR
    assert post(client, f"/approvals/{t}/{req}/approve").headers["location"] == f"/approvals/{t}"
    r = post(client, f"/approvals/{t}/{jin}/reject")
    assert r.headers["location"] == "/jobs/2"
    assert [p["head"] for p in gh.pulls] == ["triage/requests-2.32.4"]
    assert "resuming" in client.get("/jobs/2").text
    decisions = {d["package"]: d for d in RunStore(db).decisions(t)}
    assert decisions["requests"]["decision"] == "approved" and decisions["requests"]["decided_by"] == "alice"
    assert decisions["requests"]["risk_shown_at"] and decisions["Jinja2"]["decision"] == "rejected"
    rec = ActionStore(db).with_prs(REPO)[0]
    assert rec.approved_by == "alice (web)"

    # a second approve after the run moved on changes nothing
    assert post(client, f"/approvals/{t}/{req}/approve").status_code == 409
    assert len(gh.pulls) == 1

    # table: failing PR in red, NOT fixed, diagnosis, evidence
    page = client.get("/").text
    assert 'class="row failing"' in page and "PR failing, NOT fixed" in page
    assert "url_quote was removed" in page and "app.py:1" in page and "GHSA-TEST-REQ" in page
    assert "Approved by <b>alice</b>" in page

    # test cases computed live
    tcs = badges(client.get("/test-cases").text)
    assert tcs == {"TC1": "PASS", "TC2": "PASS", "TC3": "PASS", "TC4": "PENDING"}

    # merge -> Refresh CI -> TC4 PASS, merged NOT deployed, blue
    gh.merge(1)
    assert post(client, "/refresh").status_code == 303
    page = client.get("/").text
    assert "merged, NOT deployed" in page and 'class="row merged"' in page
    tcs = badges(client.get("/test-cases").text)
    assert tcs["TC4"] == "PASS" and tcs["TC1"] == "PASS"


def test_test_cases_pending_before_any_run(web):
    client, *_ = web
    assert badges(client.get("/test-cases").text) == {f"TC{i}": "PENDING" for i in range(1, 5)}


def test_progress_partial_polls_only_while_running(web):
    client, *_ = web
    login(client)
    post(client, "/scan")
    part = client.get("/jobs/1/progress").text
    assert "hx-trigger" not in part and "collect: 3 dependencies" in part
    store = RunStore(web[2])
    job = store.new_job("scan", None, "x")
    assert 'hx-trigger="every 1s"' in client.get(f"/jobs/{job}/progress").text


def test_job_error_is_shown_not_swallowed(web):
    client, gh, db, cfg = web
    cfg.make_runtime = lambda: Runtime(store=ActionStore(db), cache=LLMCache(db), github=None)
    client = TestClient(create_app(cfg))
    login(client)
    post(client, "/scan")
    page = client.get("/jobs/1").text
    assert "error: RuntimeError: GitHub is needed" in page
    assert RunStore(db).runs()[0]["status"] == "error"


def test_only_one_job_at_a_time(tmp_path):
    store = RunStore(str(tmp_path / "t.db"))
    runner = JobRunner(store, background=True)
    go, started = threading.Event(), threading.Event()

    def slow(log):
        started.set()
        go.wait(5)

    runner.submit("scan", None, "a", slow)
    started.wait(5)
    with pytest.raises(Busy):
        runner.submit("refresh", None, "b", lambda log: None)
    go.set()
    for _ in range(100):
        if not runner.busy:
            break
        threading.Event().wait(0.05)
    assert runner.submit("refresh", None, "b", lambda log: None)


# ---------------------------------------------------------------- stored runs, risk on PRs, grouping

def cli_run(db, cp, gh, thread="cli-1"):
    """A graph run started outside the web UI (like `python -m triage run`), paused at approval."""
    from triage.graph import build_graph, sqlite_checkpointer
    rt = Runtime(store=ActionStore(db), cache=LLMCache(db), github=lambda: GitHubClient("t", session=gh),
                 fetch=fetch, other_ecosystems=("npm",), notes=notes, llm=FakeLLM(), wait=False)
    from tests.test_github_pr import REQS
    g = build_graph(rt, sqlite_checkpointer(cp))
    cfg = {"configurable": {"thread_id": thread}}
    g.invoke({"requirements_text": REQS, "repo": REPO, "path": "requirements.txt"}, cfg)
    return g, cfg


def test_scan_results_are_stored_and_survive_a_restart(web, tmp_path):
    client, gh, db, cfg = web
    cli_run(db, str(tmp_path / "cli.db"), gh)                         # no web scan at all
    run = ActionStore(db).latest_run(REPO)
    assert run["thread_id"] == "cli-1" and run["stage"] == "assessed"
    data = run["data"]
    assert {p["package"] for p in data["plans"]} == {"requests", "Jinja2", "MarkupSafe"}
    assert any(m["queried_ecosystem"] == "npm" and m["decision"] == "excluded" for m in data["matches"])
    req_risk = next(r for r in data["risks"].values() if r["package"] == "requests")
    assert req_risk["breaking_risk"] == "high" and req_risk["usages"][0]["path"] == "app.py"
    assert req_risk["breaking_changes"][0]["source_url"].startswith("https://")

    restarted = TestClient(create_app(cfg))                             # new process, same triage.db
    page = restarted.get("/").text
    assert "Showing stored run <code>cli-1</code>" in page
    assert 'class="risk high"' in page and "not assessed" not in page and "app.py:1" in page
    assert badges(restarted.get("/test-cases").text)["TC2"] == "PASS"


def test_tc2_card_names_the_other_ecosystem_package(web, tmp_path):
    client, gh, db, _ = web
    cli_run(db, str(tmp_path / "cli.db"), gh)
    html = client.get("/test-cases").text
    assert "MarkupSafe==2.0.1 (PyPI); advisory GHSA-NPM-MARKUPSAFE is for npm/markupsafe" in html
    assert "From stored run cli-1" in html and "no PR" in html


def test_pr_record_keeps_the_risk_shown_at_approval(web):
    client, gh, db, _ = web
    login(client)
    post(client, "/scan")
    run = awaiting(db)
    t, i, j = run["thread_id"], idx_of(run, "requests"), idx_of(run, "Jinja2")
    client.get(f"/approvals/{t}/{i}/risk")
    post(client, f"/approvals/{t}/{i}/approve")
    post(client, f"/approvals/{t}/{j}/reject")
    rec = ActionStore(db).with_prs(REPO)[0]
    assert rec.risk["breaking_risk"] == "high" and rec.risk["usages"]

    store = ActionStore(db)                                              # without any stored run...
    store.db.execute("DELETE FROM scan_runs")
    store.db.commit()
    page = client.get("/").text                                          # ...the PR still shows its risk
    assert 'class="risk high"' in page and "stored with PR #1 at approval" in page


def seed_two_attempts(db):
    """requests: attempt 1 = PR #1 merged; attempt 2 = PR #3 open, CI passing (after a demo reset)."""
    s = ActionStore(db)
    dep = "PyPI:requests@2.19.0#L1"
    for attempt, pr, at in ((1, 1, "2026-10-17T10:00:00+00:00"), (2, 3, "2026-10-17T20:00:00+00:00")):
        s.record_approval(dep, "2.32.4", REPO, f"triage/requests-2.32.4{'-2' if attempt > 1 else ''}", "alice",
                          "requests", [{"id": "GHSA-TEST-REQ", "aliases": []}], attempt)
        s.db.execute("UPDATE actions SET approved_at = ? WHERE attempt = ?", (at, attempt))
        s.record_pr(dep, "2.32.4", pr, f"https://github.com/{REPO}/pull/{pr}", attempt)
    s.add_observation(dependency_id=dep, target_version="2.32.4", repo=REPO, pr_number=1, pr_state="merged",
                      merged_at="2026-10-17T12:00:00Z", head_sha="aaa", ci_status="passing",
                      outcome="merged, NOT deployed (deployment not verified)", checks=[], observed_at=T)
    s.add_observation(dependency_id=dep, target_version="2.32.4", repo=REPO, pr_number=3, pr_state="open",
                      merged_at=None, head_sha="bbb", ci_status="passing",
                      outcome="PR open, CI passing (awaiting human merge)", checks=[], observed_at=T)


def test_one_row_per_package_latest_attempt_first(web):
    from triage.web.views import build_rows
    client, gh, db, _ = web
    seed_two_attempts(db)
    rows, _ = build_rows(db, REPO)
    assert [r.package for r in rows] == ["requests"]
    assert rows[0].pr.number == 3 and [a.number for a in rows[0].earlier] == [1]
    page = client.get("/").text
    assert page.count('<tr class="row ') == 1 and 'class="row passing"' in page
    assert "Attempt history (1 earlier)" in page and "+1 earlier" in page


def test_tc1_uses_latest_attempt_and_points_to_tc4(web):
    client, gh, db, _ = web
    seed_two_attempts(db)
    html = client.get("/test-cases").text
    assert "PR #3 opened (attempt 2), CI passing" in html
    assert "Earlier attempt: PR #1 (attempt 1), merged, see TC4" in html
    tcs = badges(html)
    assert tcs["TC1"] == "PASS" and tcs["TC4"] == "PASS"
    assert "PR #1 requests 2.19.0 -&gt; 2.32.4 (attempt 1) merged" in html


def test_existing_db_gets_the_risk_column(tmp_path):
    import sqlite3
    db = str(tmp_path / "old.db")
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE actions (dependency_id TEXT NOT NULL, target_version TEXT NOT NULL,"
                " attempt INTEGER NOT NULL DEFAULT 1, repo TEXT NOT NULL, branch TEXT NOT NULL, status TEXT NOT NULL,"
                " approved_by TEXT NOT NULL, approved_at TEXT NOT NULL, pr_number INTEGER, pr_url TEXT,"
                " updated_at TEXT NOT NULL, package TEXT, advisories TEXT,"
                " PRIMARY KEY (dependency_id, target_version, attempt))")
    con.execute("INSERT INTO actions VALUES ('d', '2', 1, 'o/r', 'b', 'pr_opened', 'x', 't', 1, 'u', 't', 'p', NULL)")
    con.commit()
    con.close()
    s = ActionStore(db)
    assert s.with_prs()[0].risk is None
    s.set_risk("d", "2", 1, {"breaking_risk": "low"})
    s.set_risk("d", "2", 1, {"breaking_risk": "high"})                 # never overwritten
    assert s.with_prs()[0].risk == {"breaking_risk": "low"}


def test_db_copy_moves_history_once(tmp_path, db_target):
    from triage.dbcopy import copy
    src = str(tmp_path / "local.db")
    seed_two_attempts(src)
    ActionStore(src).save_run("r1", {"plans": []}, repo=REPO, source="requirements.txt", dry_run=True, stage="complete")
    assert copy(src, db_target, log=lambda _: None)["actions"] == 2
    assert copy(src, db_target, log=lambda _: None)["ci_observations"] == 0          # idempotent
    dst = ActionStore(db_target)
    assert [r.pr_number for r in dst.with_prs(REPO)] == [1, 3]
    assert dst.latest_run(REPO)["thread_id"] == "r1"
    dst.add_observation(dependency_id="d", target_version="1", repo=REPO, pr_number=9, pr_state="open",
                        merged_at=None, head_sha="c", ci_status="pending", outcome="waiting for CI",
                        checks=[], observed_at=T)                                     # ids keep working


def test_healthz_does_not_touch_the_database(web, monkeypatch):
    client, *_ = web
    import triage.db

    def boom(*a, **k):
        raise AssertionError("healthz opened a database connection")
    monkeypatch.setattr(triage.db.Database, "__init__", boom)
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"ok": True}


def test_config_from_env_uses_database_url_for_both(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@host/db?sslmode=require")
    monkeypatch.delenv("TRIAGE_CHECKPOINTS", raising=False)
    cfg = WebConfig.from_env()
    assert cfg.db == cfg.checkpoints == "postgresql://u:p@host/db?sslmode=require"
    monkeypatch.delenv("DATABASE_URL")
    assert WebConfig.from_env().db == "triage.db"


def test_cli_run_reads_requirements_from_github_without_a_local_file(tmp_path, monkeypatch):
    """`python -m triage run --repo R` with no local path: the file comes from the base branch."""
    from triage.graph import build_graph, sqlite_checkpointer
    gh = World()
    db = str(tmp_path / "t.db")
    rt = Runtime(store=ActionStore(db), cache=LLMCache(db), github=lambda: GitHubClient("t", session=gh),
                 fetch=fetch, other_ecosystems=(), notes=notes, llm=FakeLLM(), wait=False)
    g = build_graph(rt, sqlite_checkpointer(str(tmp_path / "cp.db")))
    cfg = {"configurable": {"thread_id": "gh-1"}}
    g.invoke({"repo": REPO, "path": "requirements.txt", "dry_run": True}, cfg)
    v = g.get_state(cfg).values
    assert v["requirements_source"] == f"{REPO}@main:requirements.txt (GitHub API)"
    assert [d["raw_name"] for d in v["dependencies"]] == ["requests", "Jinja2", "MarkupSafe"]
    assert ("GET", f"/repos/{REPO}/contents/requirements.txt") in gh.calls
