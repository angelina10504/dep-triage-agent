"""Offline tests for assess_upgrade_risk: citations must come from fetched notes."""
import pytest

from triage.llm import LLMCache, LLMError
from triage.release_notes import NoteItem, ReleaseNotes
from triage.risk import assess_upgrade_risk

U1 = "https://github.com/pallets/werkzeug/blob/3.1.9/CHANGES.rst#L278"
U2 = "https://github.com/pallets/werkzeug/blob/3.1.9/CHANGES.rst#L397-L398"
NOTES = ReleaseNotes("pallets/werkzeug", [
    NoteItem("3.0.0", "Remove previously deprecated code. :pr:`2768`", U1, "changelog"),
    NoteItem("2.3.0", "Deprecate the ``werkzeug.urls`` module.", U2, "changelog")])


class FakeLLM:
    name, model = "fake", "m"

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def complete_json(self, system, user, schema, schema_name):
        self.calls.append((system, user))
        a = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(a, Exception):
            raise a
        return a


def answer(*changes, risk="high", reasons="Major version with removals."):
    return {"breaking_risk": risk, "reasons": reasons,
            "breaking_changes": [{"change": c, "source_url": u} for c, u in changes]}


@pytest.fixture
def cache(tmp_path):
    return LLMCache(str(tmp_path / "t.db"))


def run(llm, cache, notes=NOTES):
    return assess_upgrade_risk("Werkzeug", "2.2.2", "3.1.9", notes, cache, llm)


def test_cited_changes_kept_uncited_dropped(cache):
    llm = FakeLLM(answer(("3.0 removed the deprecated werkzeug.urls functions such as url_quote", U1),
                         ("Invented change", "https://example.com/made-up")))
    r = run(llm, cache)
    assert r["breaking_risk"] == "high" and r["dropped_uncited"] == 1
    assert [c["source_url"] for c in r["breaking_changes"]] == [U1, U2]    # + deterministic pair
    assert r["breaking_changes"][1]["from"] == "release_notes"


def test_prompt_contains_only_fetched_items(cache):
    llm = FakeLLM(answer(("x", U1)))
    run(llm, cache)
    user = llm.calls[0][1]
    assert U1 in user and U2 in user and '"major_version_change": true' in user


def test_high_risk_without_any_valid_citation_is_retried_then_unavailable(cache):
    llm = FakeLLM(answer(("Invented", "https://example.com/x")))
    r = run(llm, cache)
    assert len(llm.calls) == 2
    assert r["breaking_risk"] == "unknown" and r["status"] == "unavailable"
    assert r["reasons"].startswith("LLM unavailable: InvalidOutput (risk claimed without a cited breaking change)")


def test_low_risk_with_no_changes_is_fine(cache):
    only_deprecation = ReleaseNotes("pallets/werkzeug", NOTES.items[1:])
    r = run(FakeLLM(answer(risk="low", reasons="Nothing that breaks callers.")), cache, only_deprecation)
    assert (r["breaking_risk"], r["breaking_changes"], r["status"]) == ("low", [], "ok")


def test_low_risk_is_raised_when_notes_show_removed_deprecations(cache):
    r = run(FakeLLM(answer(risk="low", reasons="Looks fine.")), cache)
    assert r["breaking_risk"] == "medium" and "raised from low" in r["reasons"]


def test_banned_wording_in_reasons_retried(cache):
    llm = FakeLLM(answer(("x", U1), reasons="All issues resolved."), answer(("x", U1)))
    assert run(llm, cache)["status"] == "ok" and len(llm.calls) == 2


def test_no_notes_means_no_llm_call(cache):
    llm = FakeLLM(answer(("x", U1)))
    r = run(llm, cache, ReleaseNotes(None, note="no release notes found (no GitHub repository in PyPI project_urls)"))
    assert llm.calls == [] and r["breaking_risk"] == "unknown"
    assert r["reasons"] == "no release notes found (no GitHub repository in PyPI project_urls)"


def test_llm_down_is_unknown_not_low(cache):
    r = run(FakeLLM(LLMError("HTTP 429")), cache)
    assert r["breaking_risk"] == "unknown" and "LLM unavailable: HTTP 429" in r["reasons"]


def test_cached_answer_gets_same_citation_check(cache):
    llm = FakeLLM(answer(("x", U1)))
    run(llm, cache)
    r = run(llm, cache)
    assert r["status"] == "cached" and len(llm.calls) == 1 and r["breaking_changes"][0]["source_url"] == U1


# ---------- deterministic deprecation -> removal pairs ----------

from triage.risk import deprecation_removals  # noqa: E402

U3 = "https://github.com/pallets/werkzeug/blob/3.1.9/CHANGES.rst#L279"
U4 = "https://github.com/pallets/werkzeug/releases/tag/3.1.0"
CHAIN = ReleaseNotes("pallets/werkzeug", [
    NoteItem("2.3.0", "Remove previously deprecated code.", "https://x/L390", "changelog"),
    NoteItem("2.3.0", "Deprecate the ``werkzeug.urls`` module.", U2, "changelog"),
    NoteItem("3.0.0", "Remove previously deprecated code. :pr:`2768`", U1, "changelog"),
    NoteItem("3.0.0", "Deprecate the ``__version__`` attribute.", U3, "changelog"),
    NoteItem("3.1.0", "Remove previously deprecated code. #2967", U4, "github_release")])


def test_removal_pairs_with_deprecations_since_the_previous_removal():
    pairs = [(p["deprecated_in"], p["removed_in"], p["deprecation_url"]) for p in deprecation_removals(CHAIN.items)]
    assert pairs == [("2.3.0", "3.0.0", U2), ("3.0.0", "3.1.0", U3)]


def test_pairs_the_llm_left_out_are_added_with_citation(cache):
    r = run(FakeLLM(answer(("Python 3.7 dropped", U1))), cache, CHAIN)
    urls = [c["source_url"] for c in r["breaking_changes"]]
    assert urls == [U1, U2, U3]
    urls_change = next(c for c in r["breaking_changes"] if c["source_url"] == U2)
    assert urls_change["from"] == "release_notes" and "werkzeug.urls" in urls_change["change"]
    assert f"then 3.0.0 removed previously deprecated code ({U1})" in urls_change["change"]


def test_pairs_shown_even_when_llm_is_down(cache):
    r = run(FakeLLM(LLMError("HTTP 503")), cache, CHAIN)
    assert r["breaking_risk"] == "unknown" and [c["source_url"] for c in r["breaking_changes"]] == [U2, U3]
