"""Step 02 - Plan the next steps: match exact package and version ranges.

Pure, deterministic rules - no LLM. Each comparison returns a Decision plus the
reason and the exact range that decided it, so a judge can check every row.

OSV range semantics (https://ossf.github.io/osv-schema/#affectedranges-field):
  events are ordered; "introduced" opens an affected interval, "fixed" closes it
  (fixed version itself is safe), "last_affected" closes it inclusively.
"""
from __future__ import annotations

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from .models import AdvisoryMatch, Decision, Dependency
from .osv import SOURCE, advisory_url

_VERSION_RANGE_TYPES = {"ECOSYSTEM", "SEMVER"}   # GIT ranges are commit hashes, not versions


def _v(s: str) -> Version:
    return Version("0") if s == "0" else Version(s)


def _check_range(installed: Version, events: list[dict]) -> tuple[bool, str, str | None]:
    """Return (affected, range_text, fixed_version) for one OSV range."""
    lower: str | None = None
    for ev in events:
        if "introduced" in ev:
            lower = ev["introduced"]
        elif "fixed" in ev and lower is not None:
            if _v(lower) <= installed < _v(ev["fixed"]):
                return True, f">={lower}, <{ev['fixed']}", ev["fixed"]
            lower = None
        elif "last_affected" in ev and lower is not None:
            if _v(lower) <= installed <= _v(ev["last_affected"]):
                return True, f">={lower}, <={ev['last_affected']} (no fix published)", None
            lower = None
    if lower is not None and installed >= _v(lower):  # open-ended: introduced, never fixed
        return True, f">={lower} (no fix published)", None
    return False, "", None


def match_advisory(dep: Dependency, adv: dict, retrieved_at: str) -> AdvisoryMatch:
    adv_id = adv.get("id", "UNKNOWN")

    def result(decision: Decision, reason: str, rng: str = "", fixed: str | None = None) -> AdvisoryMatch:
        return AdvisoryMatch(
            dependency_id=dep.id,
            advisory_id=adv_id,
            aliases=adv.get("aliases", []),
            summary=adv.get("summary") or (adv.get("details") or "")[:120],
            url=advisory_url(adv_id),
            decision=decision,
            reason=reason,
            affected_range=rng,
            fixed_version=fixed,
            source=SOURCE,
            retrieved_at=retrieved_at,
        )

    if adv.get("withdrawn"):
        return result(Decision.EXCLUDED, f"advisory withdrawn on {adv['withdrawn']}")

    # Rule 1: package identity = canonical name AND ecosystem must both match.
    same_pkg = [
        a for a in adv.get("affected", [])
        if a.get("package", {}).get("ecosystem") == dep.ecosystem
        and canonicalize_name(a.get("package", {}).get("name", "")) == dep.name
    ]
    if not same_pkg:
        others = sorted({
            f"{a.get('package', {}).get('ecosystem')}/{a.get('package', {}).get('name')}"
            for a in adv.get("affected", [])
        })
        return result(
            Decision.EXCLUDED,
            f"advisory is for {', '.join(others) or 'no listed package'}, "
            f"dependency is {dep.ecosystem}/{dep.name}",
        )

    # Rule 2: we need an exact installed version to compare.
    if dep.version is None:
        return result(Decision.UNCERTAIN, f"'{dep.spec}' is not pinned with ==, installed version unknown")
    try:
        installed = Version(dep.version)
    except InvalidVersion:
        return result(Decision.UNCERTAIN, f"installed version '{dep.version}' is not a valid version")

    # Rule 3: compare against version ranges first - they carry the range and the fix.
    saw_comparable_range = False
    for a in same_pkg:
        for r in a.get("ranges", []):
            if r.get("type") not in _VERSION_RANGE_TYPES:
                continue
            saw_comparable_range = True
            try:
                affected, rng, fixed = _check_range(installed, r.get("events", []))
            except InvalidVersion as e:
                return result(Decision.UNCERTAIN, f"advisory range has an unparseable version: {e}")
            if affected:
                return result(Decision.VULNERABLE, f"{dep.version} is inside affected range {rng}", rng, fixed)

    # Rule 4: fallback - the explicit versions list, which gives no fixed version.
    if any(dep.version in a.get("versions", []) for a in same_pkg):
        return result(Decision.VULNERABLE,
                      f"{dep.version} is listed explicitly as affected, but no version range covers it",
                      "explicit versions list", None)

    if not saw_comparable_range and not any(a.get("versions") for a in same_pkg):
        return result(Decision.UNCERTAIN, "advisory gives no version ranges to compare against")
    return result(Decision.NOT_AFFECTED, f"{dep.version} is outside every affected range")
