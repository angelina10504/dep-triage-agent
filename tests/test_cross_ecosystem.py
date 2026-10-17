"""Offline tests for TC2 live: same name in other ecosystems is looked up, shown, and excluded."""
from triage.models import Decision, PlanStatus
from triage.osv import AdvisorySourceError
from triage.scanner import OTHER_ECOSYSTEMS, scan

T = "2026-10-17T00:00:00+00:00"


def adv(id_, eco, name, fixed="9.9.9"):
    return {"id": id_, "summary": "s", "affected": [{"package": {"ecosystem": eco, "name": name},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


def fetcher(db, fail=()):
    calls = []

    def fetch(name, eco):
        calls.append((name, eco))
        if eco in fail:
            raise AdvisorySourceError("Timeout")
        return db.get((eco, name), []), T
    fetch.calls = calls
    return fetch


def test_every_other_ecosystem_is_queried_with_the_same_name():
    f = fetcher({})
    scan("markdown==3.7\n", fetch=f)
    assert f.calls == [("markdown", "PyPI")] + [("markdown", e) for e in OTHER_ECOSYSTEMS]
    assert set(OTHER_ECOSYSTEMS) == {"npm", "Maven", "Go", "RubyGems", "crates.io"}


def test_other_ecosystem_hit_is_excluded_with_exact_reason_and_no_upgrade():
    f = fetcher({("npm", "markdown"): [adv("GHSA-NPM", "npm", "markdown")],
                 ("RubyGems", "markdown"): [adv("GHSA-GEM", "RubyGems", "markdown")]})
    r = scan("markdown==3.7\n", fetch=f)
    hits = {m.advisory_id: m for m in r.matches}
    assert hits["GHSA-NPM"].decision == Decision.EXCLUDED
    assert hits["GHSA-NPM"].reason == "advisory is for npm/markdown, dependency is PyPI/markdown"
    assert hits["GHSA-NPM"].queried_ecosystem == "npm"
    assert hits["GHSA-GEM"].reason == "advisory is for RubyGems/markdown, dependency is PyPI/markdown"
    assert hits["GHSA-NPM"].url == "https://osv.dev/vulnerability/GHSA-NPM" and hits["GHSA-NPM"].retrieved_at == T
    plan = r.plans[0]
    assert plan.status == PlanStatus.NO_ACTION and plan.advisory_ids == []


def test_collision_does_not_change_a_real_pypi_upgrade():
    f = fetcher({("PyPI", "ws"): [adv("PY-1", "PyPI", "ws", fixed="2.0")],
                 ("npm", "ws"): [adv("NPM-1", "npm", "ws", fixed="8.0.0")]})
    r = scan("ws==1.0\n", fetch=f)
    assert (r.plans[0].target_version, r.plans[0].advisory_ids) == ("2.0", ["PY-1"])


def test_advisory_already_seen_on_pypi_is_not_listed_twice():
    both = {"id": "MULTI", "affected": adv("x", "PyPI", "tar")["affected"] + adv("x", "npm", "tar")["affected"]}
    f = fetcher({("PyPI", "tar"): [both], ("npm", "tar"): [both]})
    r = scan("tar==1.0\n", fetch=f)
    assert [m.advisory_id for m in r.matches] == ["MULTI"] and r.matches[0].queried_ecosystem == "PyPI"


def test_failed_collision_lookup_is_a_warning_not_a_change_of_plan():
    f = fetcher({("PyPI", "ws"): [adv("PY-1", "PyPI", "ws", fixed="2.0")]}, fail=("Maven",))
    r = scan("ws==1.0\n", fetch=f)
    assert r.plans[0].status == PlanStatus.UPGRADE
    assert r.warnings == ["PyPI:ws@1.0#L1: Maven name-collision lookup failed (Timeout)"]
