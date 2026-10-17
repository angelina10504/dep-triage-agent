"""Offline unit tests for the deterministic matching rules.

Advisories here are hand-written in OSV format (not live data), so the tests run
without network and pin down each rule, including the official test cases.
"""
from triage.matcher import match_advisory
from triage.models import Decision, PlanStatus
from triage.parser import parse_requirements
from triage.scanner import scan

T = "2026-10-17T00:00:00+00:00"


def adv(id_, ecosystem, name, events, versions=None, **extra):
    return {
        "id": id_,
        "summary": f"test advisory {id_}",
        "affected": [{
            "package": {"ecosystem": ecosystem, "name": name},
            "ranges": [{"type": "ECOSYSTEM", "events": events}],
            "versions": versions or [],
        }],
        **extra,
    }


def dep(line):
    return parse_requirements(line)[0]


# ---------- parser ----------

def test_parser_pins_extras_markers_comments():
    deps = parse_requirements(
        "# comment\nRequests==2.19.0\nuvicorn[standard]==0.30.0 ; python_version>'3.8'\n"
        "flask>=2.0\n-r other.txt\n\n"
    )
    assert [(d.name, d.version, d.line) for d in deps] == [
        ("requests", "2.19.0", 2), ("uvicorn", "0.30.0", 3), ("flask", None, 4)]
    assert deps[0].id == "PyPI:requests@2.19.0#L2"


# ---------- TC1: installed version inside advisory range ----------

def test_tc1_inside_range_is_vulnerable_with_fixed_version():
    m = match_advisory(dep("requests==2.19.0"),
                       adv("A1", "PyPI", "requests", [{"introduced": "0"}, {"fixed": "2.32.4"}]), T)
    assert m.decision == Decision.VULNERABLE
    assert m.fixed_version == "2.32.4"
    assert m.affected_range == ">=0, <2.32.4"
    assert m.url == "https://osv.dev/vulnerability/A1" and m.retrieved_at == T


def test_fixed_version_itself_is_safe():
    m = match_advisory(dep("requests==2.32.4"),
                       adv("A1", "PyPI", "requests", [{"introduced": "0"}, {"fixed": "2.32.4"}]), T)
    assert m.decision == Decision.NOT_AFFECTED


def test_multiple_intervals_in_one_range():
    events = [{"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "2.0"}, {"fixed": "2.3"}]
    assert match_advisory(dep("x==1.7"), adv("A", "PyPI", "x", events), T).decision == Decision.NOT_AFFECTED
    m = match_advisory(dep("x==2.1"), adv("A", "PyPI", "x", events), T)
    assert m.decision == Decision.VULNERABLE and m.fixed_version == "2.3"


def test_last_affected_is_inclusive_and_has_no_fix():
    m = match_advisory(dep("x==3.0"), adv("A", "PyPI", "x", [{"introduced": "0"}, {"last_affected": "3.0"}]), T)
    assert m.decision == Decision.VULNERABLE and m.fixed_version is None


def test_explicit_versions_list():
    m = match_advisory(dep("x==1.2.3"), adv("A", "PyPI", "x", [], versions=["1.2.3"]), T)
    assert m.decision == Decision.VULNERABLE


# ---------- TC2: unrelated package with the same name ----------

def test_tc2_same_name_other_ecosystem_is_excluded():
    m = match_advisory(dep("requests==2.19.0"),
                       adv("N1", "npm", "requests", [{"introduced": "0"}, {"fixed": "9.9.9"}]), T)
    assert m.decision == Decision.EXCLUDED
    assert "npm/requests" in m.reason


def test_name_normalisation_still_matches_same_package():
    m = match_advisory(dep("Jinja2==2.10"),
                       adv("J", "PyPI", "jinja2", [{"introduced": "0"}, {"fixed": "2.10.1"}]), T)
    assert m.decision == Decision.VULNERABLE


def test_withdrawn_advisory_is_excluded():
    a = adv("W", "PyPI", "x", [{"introduced": "0"}, {"fixed": "2.0"}], withdrawn="2024-01-01T00:00:00Z")
    assert match_advisory(dep("x==1.0"), a, T).decision == Decision.EXCLUDED


# ---------- uncertain state when evidence is missing ----------

def test_unpinned_dependency_is_uncertain():
    m = match_advisory(dep("requests>=2.0"),
                       adv("A1", "PyPI", "requests", [{"introduced": "0"}, {"fixed": "2.32.4"}]), T)
    assert m.decision == Decision.UNCERTAIN


def test_invalid_installed_version_is_uncertain():
    m = match_advisory(dep("x==not-a-version"), adv("A", "PyPI", "x", [{"introduced": "0"}, {"fixed": "2"}]), T)
    assert m.decision == Decision.UNCERTAIN


# ---------- upgrade plan ----------

def _fetcher(db):
    return lambda name, eco: (db.get(name, []) if eco == "PyPI" else [], T)


def test_plan_picks_highest_fix_across_advisories():
    db = {"requests": [
        adv("A1", "PyPI", "requests", [{"introduced": "0"}, {"fixed": "2.20.0"}]),
        adv("A2", "PyPI", "requests", [{"introduced": "0"}, {"fixed": "2.32.4"}]),
        adv("N1", "npm", "requests", [{"introduced": "0"}, {"fixed": "9.0.0"}]),
    ]}
    plan = scan("requests==2.19.0\n", fetch=_fetcher(db)).plans[0]
    assert plan.status == PlanStatus.UPGRADE and plan.target_version == "2.32.4"
    assert plan.advisory_ids == ["A1", "A2"]                 # npm advisory excluded


def test_plan_rechecks_target_against_later_advisory():
    # Fix for A1 is 2.0, but 2.0 is inside A2's range (introduced 1.9, fixed 2.1).
    db = {"x": [
        adv("A1", "PyPI", "x", [{"introduced": "0"}, {"fixed": "2.0"}]),
        adv("A2", "PyPI", "x", [{"introduced": "1.9"}, {"fixed": "2.1"}]),
    ]}
    plan = scan("x==1.0\n", fetch=_fetcher(db)).plans[0]
    assert plan.target_version == "2.1"


def test_plan_no_fix_published_is_uncertain():
    db = {"x": [adv("A", "PyPI", "x", [{"introduced": "0"}])]}
    assert scan("x==1.0\n", fetch=_fetcher(db)).plans[0].status == PlanStatus.UNCERTAIN


def test_plan_clean_package_is_no_action():
    db = {"x": [adv("A", "PyPI", "x", [{"introduced": "0"}, {"fixed": "1.0"}])]}
    assert scan("x==1.5\n", fetch=_fetcher(db)).plans[0].status == PlanStatus.NO_ACTION


# ---------- ranges before the explicit versions list ----------

def test_range_wins_over_versions_list_and_reports_fix():
    a = adv("A", "PyPI", "x", [{"introduced": "0"}, {"fixed": "2.0"}], versions=["1.0", "1.5"])
    m = match_advisory(dep("x==1.5"), a, T)
    assert m.decision == Decision.VULNERABLE
    assert (m.affected_range, m.fixed_version) == (">=0, <2.0", "2.0")
    assert m.reason == "1.5 is inside affected range >=0, <2.0"


def test_versions_list_is_only_a_fallback_without_fix():
    # Listed explicitly, but the range says 1.5 is outside -> fallback, no fixed version claimed.
    a = adv("A", "PyPI", "x", [{"introduced": "2.0"}, {"fixed": "3.0"}], versions=["1.5"])
    m = match_advisory(dep("x==1.5"), a, T)
    assert m.decision == Decision.VULNERABLE and m.fixed_version is None
    assert m.reason == "1.5 is listed explicitly as affected, but no version range covers it"


# ---------- unique vulnerability count ----------

def test_plan_counts_aliased_records_once():
    db = {"x": [
        adv("GHSA-1", "PyPI", "x", [{"introduced": "0"}, {"fixed": "2.0"}], aliases=["CVE-1"]),
        adv("PYSEC-1", "PyPI", "x", [{"introduced": "0"}, {"fixed": "2.0"}], aliases=["CVE-1", "GHSA-1"]),
        adv("PYSEC-2", "PyPI", "x", [{"introduced": "0"}, {"fixed": "2.0"}], aliases=["CVE-1"]),
        adv("GHSA-2", "PyPI", "x", [{"introduced": "0"}, {"fixed": "2.0"}], aliases=["CVE-2"]),
    ]}
    plan = scan("x==1.0\n", fetch=_fetcher(db)).plans[0]
    assert plan.reason == "upgrade to 2.0 fixes 2 vulnerabilities (4 advisory records)"


def test_plan_merges_chains_of_aliases():
    # A~B via CVE-1, B~C via CVE-2: one vulnerability even though A and C share nothing directly.
    db = {"x": [
        adv("A", "PyPI", "x", [{"introduced": "0"}, {"fixed": "2.0"}], aliases=["CVE-1"]),
        adv("C", "PyPI", "x", [{"introduced": "0"}, {"fixed": "2.0"}], aliases=["CVE-2"]),
        adv("B", "PyPI", "x", [{"introduced": "0"}, {"fixed": "2.0"}], aliases=["CVE-1", "CVE-2"]),
    ]}
    plan = scan("x==1.0\n", fetch=_fetcher(db)).plans[0]
    assert plan.reason == "upgrade to 2.0 fixes 1 vulnerability (3 advisory records)"
