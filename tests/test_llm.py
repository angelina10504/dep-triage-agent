"""Offline tests for the LLM layer: provider selection, cache, retries, and graceful failure.

No real LLM calls: FakeSession plays back canned Chat Completions responses.
"""
import json

import pytest
import requests

from triage import __main__ as cli
from triage.explain import SCHEMA, explain, facts
from triage.llm import LLMCache, LLMError, OpenAICompatibleProvider, get_provider
from triage.models import PlanStatus
from triage.scanner import scan

T = "2026-10-18T00:00:00+00:00"
GOOD = {"summary": "Werkzeug 2.2.2 has 2 known issues.", "upgrade_risk": "Major jump to 3.x.",
        "reviewer_checklist": "Check url_quote usage."}


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}
        self.text = json.dumps(body)

    def json(self):
        return self._body


def ok(content):
    return Resp(200, {"choices": [{"message": {"content": content if isinstance(content, str)
                                               else json.dumps(content)}}]})


class FakeSession:
    def __init__(self, *script):
        self.script, self.headers, self.payloads = list(script), {}, []

    def post(self, url, json=None, timeout=None):
        self.payloads.append(json)
        item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(item, type):
            raise item("boom")
        return item


def provider(*script, sleeps=None):
    s = FakeSession(*script)
    p = OpenAICompatibleProvider("groq", "https://api.groq.com/openai/v1", "k", "openai/gpt-oss-20b",
                                 session=s, sleep=(sleeps.append if sleeps is not None else lambda _: None))
    return p, s


def adv(id_, name, fixed, aliases=()):
    return {"id": id_, "summary": f"issue {id_}", "aliases": list(aliases),
            "affected": [{"package": {"ecosystem": "PyPI", "name": name},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


def werkzeug_scan():
    db = {"werkzeug": [adv("GHSA-1", "werkzeug", "3.0.6", ["CVE-1"]), adv("PYSEC-1", "werkzeug", "3.0.6", ["CVE-1"]),
                       adv("GHSA-2", "werkzeug", "2.2.3")]}
    return scan("Werkzeug==2.2.2\n", fetch=lambda n, e: (db.get(n, []) if e == "PyPI" else [], T))


@pytest.fixture
def cache(tmp_path):
    return LLMCache(str(tmp_path / "t.db"))


# ---------- provider ----------

def test_request_uses_strict_json_schema(cache):
    p, s = provider(ok(GOOD))
    r = werkzeug_scan()
    e = explain(r.plans[0], r.matches, cache, p)
    assert e.status == "ok" and e.summary == GOOD["summary"]
    rf = s.payloads[0]["response_format"]
    assert rf["type"] == "json_schema" and rf["json_schema"]["strict"] is True
    assert s.payloads[0]["model"] == "openai/gpt-oss-20b"


def test_facts_are_deterministic_and_complete():
    r = werkzeug_scan()
    f = facts(r.plans[0], r.matches)
    assert (f["current_version"], f["target_version"], f["major_version_change"]) == ("2.2.2", "3.0.6", True)
    assert f["unique_vulnerabilities"] == 2 and [a["id"] for a in f["advisories"]] == ["GHSA-1", "GHSA-2", "PYSEC-1"]


def test_rate_limit_then_success_honours_retry_after(cache):
    sleeps = []
    p, s = provider(Resp(429, {}, {"retry-after": "3"}), ok(GOOD), sleeps=sleeps)
    r = werkzeug_scan()
    assert explain(r.plans[0], r.matches, cache, p).status == "ok"
    assert sleeps == [3] and len(s.payloads) == 2


def test_retry_after_is_capped(cache):
    sleeps = []
    p, _ = provider(Resp(429, {}, {"retry-after": "3600"}), ok(GOOD), sleeps=sleeps)
    p.complete_json("s", "u", SCHEMA, "x")
    assert sleeps == [30]


@pytest.mark.parametrize("failure, reason", [
    (Resp(429, {}), "HTTP 429"), (Resp(503, {}), "HTTP 503"), (requests.Timeout, "Timeout")])
def test_all_retries_fail_is_unavailable(cache, failure, reason):
    sleeps = []
    p, s = provider(failure, sleeps=sleeps)
    r = werkzeug_scan()
    e = explain(r.plans[0], r.matches, cache, p)
    assert (e.status, e.detail) == ("unavailable", reason) and len(s.payloads) == 4 and sleeps == [1, 2, 4]
    assert e.render() == f"LLM unavailable: {reason}"
    assert cache.events()[-1][1:] == ("unavailable", reason)            # failure is recorded


def test_auth_error_is_not_retried(cache):
    p, s = provider(Resp(401, {}))
    r = werkzeug_scan()
    assert explain(r.plans[0], r.matches, cache, p).detail == "HTTP 401" and len(s.payloads) == 1


@pytest.mark.parametrize("content", ["not json", {"summary": "x"}, {"summary": "", "upgrade_risk": "a",
                                                                     "reviewer_checklist": "b"}])
def test_bad_output_is_unavailable(cache, content):
    p, _ = provider(ok(content))
    r = werkzeug_scan()
    e = explain(r.plans[0], r.matches, cache, p)
    assert e.status == "unavailable" and e.detail.startswith("InvalidOutput")


def test_unexpected_exception_is_contained(cache):
    class Boom:
        name, model = "groq", "m"

        def complete_json(self, *a):
            raise KeyError("surprise")
    r = werkzeug_scan()
    assert explain(r.plans[0], r.matches, cache, Boom()).status == "unavailable"


# ---------- cache ----------

def test_cache_hit_makes_no_call(cache):
    p, s = provider(ok(GOOD))
    r = werkzeug_scan()
    explain(r.plans[0], r.matches, cache, p)
    e = explain(r.plans[0], r.matches, cache, p)
    assert e.status == "cached" and e.summary == GOOD["summary"] and len(s.payloads) == 1


def test_cache_key_changes_with_input_and_model(cache):
    k = LLMCache.key
    base = k("groq", "m1", "sys", "u1", SCHEMA)
    assert base == k("groq", "m1", "sys", "u1", SCHEMA)
    assert len({base, k("groq", "m2", "sys", "u1", SCHEMA), k("groq", "m1", "sys", "u2", SCHEMA),
                k("gemini", "m1", "sys", "u1", SCHEMA)}) == 4


def test_failures_are_not_cached(cache):
    p, s = provider(Resp(401, {}), ok(GOOD))
    r = werkzeug_scan()
    explain(r.plans[0], r.matches, cache, p)
    assert explain(r.plans[0], r.matches, cache, p).status == "ok" and len(s.payloads) == 2


# ---------- provider selection ----------

def test_provider_selection(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k")
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    assert get_provider().name == "groq"
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    assert get_provider().model == "openai/gpt-oss-120b"
    monkeypatch.setenv("LLM_PROVIDER", "none")
    assert get_provider() is None
    for name, reason in [("gemini", "not implemented"), ("nope", "unknown LLM_PROVIDER")]:
        monkeypatch.setenv("LLM_PROVIDER", name)
        with pytest.raises(LLMError, match=reason):
            get_provider()


def test_missing_key_is_unavailable_not_a_crash(monkeypatch, cache):
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    r = werkzeug_scan()
    assert explain(r.plans[0], r.matches, cache).render() == "LLM unavailable: GROQ_API_KEY not set"


# ---------- deterministic path never depends on the LLM ----------

def test_scan_output_is_identical_with_llm_down(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)                               # no .env here
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("Werkzeug==2.2.2\n")
    monkeypatch.setattr("triage.__main__.scan", lambda text: werkzeug_scan())
    db = str(tmp_path / "t.db")

    assert cli.main([str(reqs), "--db", db]) == 0
    plain = capsys.readouterr().out
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    assert cli.main([str(reqs), "--db", db, "--explain"]) == 0
    explained = capsys.readouterr().out

    assert explained.startswith(plain)                       # same table and decisions, explanation appended
    assert "LLM unavailable: GROQ_API_KEY not set" in explained
    assert werkzeug_scan().plans[0].status == PlanStatus.UPGRADE


def test_deterministic_modules_do_not_import_the_llm():
    import pathlib
    for mod in ("matcher", "scanner", "parser", "osv", "github_pr", "ci_watch", "store"):
        src = pathlib.Path(f"triage/{mod}.py").read_text()
        assert "llm" not in src and "explain" not in src, mod


def test_pr_body_gets_labelled_explanation_or_unavailable_note():
    from triage.explain import Explanation
    good = cli._with_explanation("BODY", Explanation("ok", **GOOD, detail="groq/m"))
    assert "### Explanation (LLM, advisory only)" in good and GOOD["upgrade_risk"] in good
    bad = cli._with_explanation("BODY", Explanation("unavailable", detail="HTTP 429"))
    assert bad.endswith("LLM explanation unavailable (HTTP 429).")
