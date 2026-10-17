"""Offline tests for assess_upgrade_risk: level computed in code from repo usage, never by the LLM."""
import pytest

from triage.llm import LLMCache, LLMError
from triage.release_notes import NoteItem, ReleaseNotes
from triage.repo_context import RepoContext
from triage.risk import assess_upgrade_risk, deprecation_removals, grounded, render_risk

U_REMOVE = "https://github.com/pallets/werkzeug/blob/3.1.9/CHANGES.rst#L278"
U_URLS = "https://github.com/pallets/werkzeug/blob/3.1.9/CHANGES.rst#L397-L398"
U_PY = "https://github.com/pallets/werkzeug/releases/tag/3.1.0"
U_DEFAULT = "https://github.com/pallets/werkzeug/releases/tag/3.1.1"
NOTES = ReleaseNotes("pallets/werkzeug", [
    NoteItem("2.3.0", "Deprecate the ``werkzeug.urls`` module. Use ``urllib.parse`` instead.", U_URLS, "changelog"),
    NoteItem("3.0.0", "Remove previously deprecated code. :pr:`2768`", U_REMOVE, "changelog"),
    NoteItem("3.1.0", "Drop support for Python 3.8.", U_PY, "github_release"),
    NoteItem("3.1.1", "max_form_memory_size defaults to 500kB.", U_DEFAULT, "github_release")])
APP = "import os\nfrom werkzeug.urls import url_quote\n\n\ndef q(p):\n    return url_quote(p)\n"


class FakeLLM:
    name, model = "fake", "m"

    def __init__(self, changes=None, symbols=None, reasons="Removals matter most."):
        self.changes, self.symbols, self.reasons, self.calls = changes, symbols, reasons, []

    def complete_json(self, system, user, schema, schema_name):
        self.calls.append(schema_name)
        if schema_name == "upgrade_breaking_changes":
            if isinstance(self.changes, Exception):
                raise self.changes
            r = self.reasons.pop(0) if isinstance(self.reasons, list) else self.reasons
            return {"breaking_changes": [{"change": c, "source_url": u} for c, u in (self.changes or [])], "reasons": r}
        if isinstance(self.symbols, Exception):
            raise self.symbols
        return {"apis": self.symbols or []}


def repo(files=None, python=("3.12",)):
    return RepoContext("acme/demo", "main", list(python), ".github/workflows/ci.yml",
                       {"app.py": APP} if files is None else files)


@pytest.fixture
def cache(tmp_path):
    return LLMCache(str(tmp_path / "t.db"))


def run(cache, llm, notes=NOTES, ctx="default"):
    return assess_upgrade_risk("Werkzeug", "2.2.2", "3.1.9", notes, cache, llm,
                               repo=repo() if ctx == "default" else ctx, import_name="werkzeug")


LLM_CHANGES = [("Removed the werkzeug.urls module that was deprecated in 2.3.0.", U_REMOVE),
               ("Dropped support for Python 3.8.", U_PY),
               ("max_form_memory_size now defaults to 500kB.", U_DEFAULT)]
SYMS = [{"index": 0, "symbols": ["werkzeug.urls"]}]


# ---------- level computed in code ----------

def test_high_when_repo_uses_a_removed_api_with_file_line_evidence(cache):
    r = run(cache, FakeLLM(LLM_CHANGES, SYMS))
    assert r["breaking_risk"] == "high"
    assert r["risk_reason"] == "repo uses werkzeug.urls.url_quote at app.py:2, app.py:6 -> likely to break"
    assert [(u["path"], u["line"]) for u in r["usages"]] == [("app.py", 2), ("app.py", 6)]


def test_medium_when_removals_apply_but_repo_does_not_use_them(cache):
    r = run(cache, FakeLLM(LLM_CHANGES, SYMS), ctx=repo({"app.py": "import werkzeug.serving\n"}))
    assert r["breaking_risk"] == "medium" and "the repo does not use the affected APIs" in r["risk_reason"]


def test_low_when_only_runtime_drops_that_do_not_apply(cache):
    notes = ReleaseNotes("pallets/werkzeug", [NOTES.items[2], NOTES.items[3]])
    r = run(cache, FakeLLM(LLM_CHANGES[1:]), notes)
    assert r["breaking_risk"] == "low" and "runtime drops do not apply: repo uses Python 3.12" in r["risk_reason"]
    drop = next(c for c in r["breaking_changes"] if c["runtime_drop"])
    assert drop["applicable"] is False and drop["not_applicable"] == "not applicable (repo uses Python 3.12)"


def test_runtime_drop_counts_when_repo_still_runs_that_python(cache):
    notes = ReleaseNotes("pallets/werkzeug", [NOTES.items[2]])
    r = run(cache, FakeLLM(LLM_CHANGES[1:2]), notes, ctx=repo(python=("3.8", "3.12")))
    assert r["breaking_risk"] == "medium" and r["breaking_changes"][0]["applicable"] is True


def test_llm_text_cannot_set_the_level(cache):
    notes = ReleaseNotes("pallets/werkzeug", [NOTES.items[3]])
    r = run(cache, FakeLLM(LLM_CHANGES[2:], reasons="Extremely high risk, everything breaks."), notes)
    assert r["breaking_risk"] == "low" and r["reasons"].startswith("Extremely high risk")


def test_without_repo_usage_is_not_checked(cache):
    r = run(cache, FakeLLM(LLM_CHANGES, SYMS), ctx=None)
    assert r["breaking_risk"] == "medium" and "repo code was not checked (no --repo)" in r["risk_reason"]


# ---------- symbols ----------

def test_symbols_must_be_grounded_in_the_change_text():
    text = "Removed the werkzeug.urls module (Deprecate the ``werkzeug.urls`` module.)"
    assert grounded("werkzeug.urls.url_quote", "werkzeug", text) == "werkzeug.urls"     # trimmed to what's cited
    assert grounded("werkzeug.secret.thing", "werkzeug", text) is None                   # invented
    assert grounded("flask.urls", "werkzeug", text) is None                              # other package
    assert grounded("url_quote", "werkzeug", text) is None                               # not qualified


def test_backticked_names_work_even_when_the_llm_is_down(cache):
    r = run(cache, FakeLLM(LLMError("HTTP 503"), LLMError("HTTP 503")))
    assert r["status"] == "unavailable" and r["breaking_risk"] == "high"       # deterministic pairs + ast
    assert "werkzeug.urls" in r["symbols"] and r["usages"][0]["line"] == 2


def test_symbols_from_runtime_drops_are_not_extracted(cache):
    llm = FakeLLM(LLM_CHANGES[1:2], SYMS)
    r = run(cache, llm, ReleaseNotes("pallets/werkzeug", [NOTES.items[2]]))
    assert r["symbols"] == [] and "removed_symbols" not in llm.calls


# ---------- citations, notes, wording ----------

def test_uncited_changes_dropped(cache):
    r = run(cache, FakeLLM(LLM_CHANGES + [("Invented change", "https://example.com/made-up")], SYMS))
    assert r["dropped_uncited"] == 1
    assert all(c["source_url"] != "https://example.com/made-up" for c in r["breaking_changes"])


def test_no_notes_means_no_llm_call(cache):
    llm = FakeLLM(LLM_CHANGES)
    r = run(cache, llm, ReleaseNotes(None, note="no release notes found (no GitHub repository in PyPI project_urls)"))
    assert llm.calls == [] and r["breaking_risk"] == "unknown"
    assert r["risk_reason"] == "no release notes found (no GitHub repository in PyPI project_urls)"


def test_banned_wording_in_reasons_retried(cache):
    llm = FakeLLM(LLM_CHANGES, reasons=["All issues resolved.", "Removals matter most."])
    r = run(cache, llm)
    assert r["status"] == "ok" and llm.calls.count("upgrade_breaking_changes") == 2


# ---------- deprecation -> removal pairs ----------

def test_removal_pairs_with_deprecations_since_the_previous_removal():
    items = [NoteItem("2.3.0", "Remove previously deprecated code.", "u0", "changelog"),
             NoteItem("2.3.0", "Deprecate the ``werkzeug.urls`` module.", "u1", "changelog"),
             NoteItem("3.0.0", "Remove previously deprecated code.", "u2", "changelog"),
             NoteItem("3.0.0", "Deprecate the ``__version__`` attribute.", "u3", "changelog"),
             NoteItem("3.1.0", "Remove previously deprecated code.", "u4", "github_release")]
    assert [(p["deprecated_in"], p["removed_in"], p["deprecation_url"]) for p in deprecation_removals(items)] == \
        [("2.3.0", "3.0.0", "u1"), ("3.0.0", "3.1.0", "u3")]


# ---------- rendering ----------

def test_render_puts_used_changes_first_and_marks_not_applicable(cache):
    r = run(cache, FakeLLM(LLM_CHANGES, SYMS))
    lines = render_risk(r, top=1)
    assert lines[0].startswith("breaking risk: high - repo uses werkzeug.urls.url_quote")
    assert lines[1].strip().startswith("app.py:2") and lines[2].strip().startswith("app.py:6")
    assert lines[3].startswith("  - [used by repo] ")
    assert any(l.startswith("  ... ") and "(--verbose)" in l for l in lines)
    assert any("not applicable (repo uses Python 3.12): 1 runtime-drop item(s), not counted" in l for l in lines)
