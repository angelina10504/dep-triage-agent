"""Offline tests for diagnose_failure: log window, evidence must be in the log, outcome unchanged."""
import pytest

from triage.diagnose import diagnose_failure, failed_jobs, log_window
from triage.github_pr import GitHubError
from triage.llm import LLMCache

ERR = "E   ImportError: cannot import name 'url_quote' from 'werkzeug.urls' (/x/werkzeug/urls.py)"
LOG = "\n".join(
    [f"2026-10-17T17:03:{i:02d}.0000000Z setup line {i}" for i in range(60)] +
    ["2026-10-17T17:03:23.8755613Z ImportError while importing test module '/w/test_app.py'.",
     "2026-10-17T17:03:23.8757600Z Traceback:",
     "2026-10-17T17:03:23.8760000Z test_app.py:1: in <module>",
     "2026-10-17T17:03:23.8761000Z     from app import quote_path",
     f"2026-10-17T17:03:23.8764168Z {ERR}",
     "2026-10-17T17:03:23.8767232Z =============================== 1 error in 0.24s ===",
     "2026-10-17T17:03:23.9108254Z ##[error]Process completed with exit code 2.",
     "2026-10-17T17:03:24.1471309Z Cleaning up orphan processes",
     "2026-10-17T17:03:24.1772844Z ##[warning]Node.js 20 is deprecated."])
CHECKS = [
    {"name": "GitGuardian", "kind": "check_run", "state": "success", "url": "https://dashboard.gitguardian.com"},
    {"name": "test", "kind": "check_run", "state": "failure",
     "url": "https://github.com/acme/demo/actions/runs/390/job/1174"},
    {"name": "ci/legacy", "kind": "status", "state": "failure", "url": "https://ci.example/1"},
]


class Client:
    def __init__(self, log=LOG, fail=False):
        self.log, self.fail, self.paths = log, fail, []

    def get_text(self, path):
        self.paths.append(path)
        if self.fail:
            raise GitHubError("GET logs -> 403: Resource not accessible")
        return self.log


class FakeLLM:
    name, model = "fake", "m"

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), 0

    def complete_json(self, system, user, schema, schema_name):
        self.calls += 1
        return self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]


def good(evidence=(ERR,)):
    return {"root_cause": "Werkzeug 3 removed url_quote, imported by app.py.", "evidence_lines": list(evidence),
            "suggested_next_step": "Use urllib.parse.quote instead of werkzeug.urls.url_quote."}


@pytest.fixture
def cache(tmp_path):
    return LLMCache(str(tmp_path / "t.db"))


def run(cache, llm, client=None, checks=CHECKS):
    return diagnose_failure("acme/demo", 2, "Werkzeug", "2.2.2", "3.1.9", checks, client or Client(), cache, llm)


def test_failed_jobs_only_actions_check_runs():
    assert failed_jobs(CHECKS) == [("1174", "test", "https://github.com/acme/demo/actions/runs/390/job/1174")]


def test_log_window_ends_at_the_error_not_the_cleanup():
    window, errors = log_window(LOG)
    texts = [t for _, t in window]
    assert texts[-1] == "##[error]Process completed with exit code 2."
    assert ERR in texts and not any("Cleaning up" in t or "Node.js" in t for t in texts)
    assert errors[-1] == ERR and not texts[0].startswith("2026-")          # timestamps stripped


def test_diagnosis_points_at_the_import_error(cache):
    client = Client()
    d = run(cache, FakeLLM(good()), client)
    assert client.paths == ["/repos/acme/demo/actions/jobs/1174/logs"]
    assert d["status"] == "ok" and d["evidence_lines"] == [ERR]
    assert d["outcome_unchanged"] == "PR failing, NOT fixed" and d["job_url"].endswith("/job/1174")


def test_invented_evidence_is_dropped_and_retried(cache):
    llm = FakeLLM(good(("ModuleNotFoundError: no module named flask",)), good((ERR, "made up line")))
    d = run(cache, llm)
    assert llm.calls == 2 and d["evidence_lines"] == [ERR]


def test_invented_evidence_twice_falls_back_to_log_lines(cache):
    d = run(cache, FakeLLM(good(("totally invented",))))
    assert d["status"] == "unavailable" and d["root_cause"].startswith("LLM unavailable: InvalidOutput")
    assert d["evidence_lines"] == [ERR]                       # deterministic lines still shown


def test_banned_wording_in_root_cause_is_retried(cache):
    bad = {**good(), "root_cause": "It is resolved by pinning."}
    llm = FakeLLM(bad, good())
    assert run(cache, llm)["status"] == "ok" and llm.calls == 2


def test_no_failed_actions_job(cache):
    d = run(cache, FakeLLM(good()), checks=CHECKS[:1])
    assert d["status"] == "no_log" and d["evidence_lines"] == []


def test_unreadable_log_is_reported_not_raised(cache):
    d = run(cache, FakeLLM(good()), Client(fail=True))
    assert d["status"] == "no_log" and "403" in d["root_cause"]


def test_evidence_with_line_number_or_squashed_spaces_still_matches(cache):
    llm = FakeLLM(good(("223: E ImportError: cannot import name 'url_quote' from 'werkzeug.urls'",)))
    d = run(cache, llm)
    assert d["status"] == "ok" and llm.calls == 1
    assert d["evidence_lines"] == [ERR]                        # the log's own line, exactly


@pytest.mark.parametrize("step", ["Use werkzeug.urls.url_quote_plus instead.", "Keep from werkzeug.urls import url_quote.",
                                  "Replace the import with werkzeug.urls.url_quote from the correct module."])
def test_next_step_reusing_the_failed_module_is_rejected(cache, step):
    llm = FakeLLM({**good(), "suggested_next_step": step}, good())
    d = run(cache, llm)
    assert llm.calls == 2 and d["suggested_next_step"].startswith("Use urllib.parse.quote")


# ---------- never stay on / go back to a vulnerable version ----------

from triage.diagnose import backwards_step  # noqa: E402


@pytest.mark.parametrize("step", [
    "Pin Werkzeug to a 2.x version that still provides url_quote.",
    "Downgrade Werkzeug until the code is updated.",
    "Stay on the current version for now.",
    "Pin werkzeug<3 in requirements.txt.",
    "Set Werkzeug==2.3.8 and re-run CI.",
    "Use Werkzeug 3.0.x, which is closer to the old API.",
    "Revert the upgrade PR.",
    "Pin a compatible version of Werkzeug.",
])
def test_steps_that_keep_a_vulnerable_version_are_rejected(step):
    assert backwards_step(step, "3.1.9") is not None


@pytest.mark.parametrize("step", [
    "Replace werkzeug.urls.url_quote with urllib.parse.quote in app.py, keep Werkzeug 3.1.9 and re-run CI.",
    "Use urllib.parse.quote on Python 3.12 and re-run CI.",
    "Allow werkzeug<4 and change the import to urllib.parse.quote.",
    "See issue #2768 and line 223 of the log.",
])
def test_code_fixes_on_the_target_version_are_allowed(step):
    assert backwards_step(step, "3.1.9") is None


def test_pin_suggestion_is_retried_and_the_code_fix_kept(cache):
    pin = {**good(), "suggested_next_step": "Pin Werkzeug to a 2.x version that still provides url_quote."}
    fix = {**good(), "suggested_next_step": "Replace werkzeug.urls.url_quote with urllib.parse.quote in app.py, "
                                            "keep Werkzeug 3.1.9 and re-run CI."}
    llm = FakeLLM(pin, fix)
    d = run(cache, llm)
    assert llm.calls == 2 and d["status"] == "ok" and "urllib.parse.quote" in d["suggested_next_step"]


def test_pin_suggestion_twice_is_unavailable_with_log_evidence(cache):
    pin = {**good(), "suggested_next_step": "Downgrade to Werkzeug 2.2.2."}
    d = run(cache, FakeLLM(pin))
    assert d["status"] == "unavailable" and "keeps a vulnerable version" in d["root_cause"]
    assert d["suggested_next_step"] == "" and d["evidence_lines"] == [ERR]


def test_prompt_no_longer_suggests_pinning(cache):
    from triage.diagnose import SYSTEM
    assert "pin a compatible version" not in SYSTEM and "never suggest staying on it" in SYSTEM
