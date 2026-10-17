"""Steps 01-03 tied together: parse -> fetch advisories -> match -> upgrade plan."""
from __future__ import annotations

from typing import Callable

from packaging.version import Version

from .matcher import match_advisory
from .models import AdvisoryMatch, Decision, PlanStatus, ScanResult, UpgradePlan
from .osv import AdvisorySourceError, fetch_advisories
from .parser import parse_requirements

Fetcher = Callable[[str, str], tuple[list[dict], str]]
_MAX_BUMPS = 10
# Same name, different package: looked up only to show (and exclude) name collisions - TC2.
OTHER_ECOSYSTEMS = ("npm", "Maven", "Go", "RubyGems", "crates.io")


def count_vulnerabilities(matches: list[AdvisoryMatch]) -> int:
    """Unique vulnerabilities: records sharing an id or alias (GHSA-x, PYSEC-y, same CVE) count once."""
    return count_unique([{m.advisory_id, *m.aliases} for m in matches])


def count_unique(id_sets: list[set[str]]) -> int:
    """Number of groups after merging every pair of id sets that overlap (transitively)."""
    groups: list[set[str]] = []
    for ids in id_sets:
        ids = set(ids)
        overlapping = [g for g in groups if g & ids]
        for g in overlapping:
            ids |= g
            groups.remove(g)
        groups.append(ids)
    return len(groups)


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _plan(dep, matches: list[AdvisoryMatch], advisories: list[dict], retrieved_at: str) -> UpgradePlan:
    vuln = [m for m in matches if m.decision == Decision.VULNERABLE]
    unsure = [m for m in matches if m.decision == Decision.UNCERTAIN]
    base = dict(dependency_id=dep.id, package=dep.raw_name, current_version=dep.version)

    if not vuln and unsure:
        return UpgradePlan(**base, target_version=None, status=PlanStatus.UNCERTAIN,
                           reason="; ".join(sorted({m.reason for m in unsure})),
                           advisory_ids=[m.advisory_id for m in unsure])
    if not vuln:
        return UpgradePlan(**base, target_version=None, status=PlanStatus.NO_ACTION,
                           reason="no advisory affects the installed version")

    ids = [m.advisory_id for m in vuln]
    no_fix = [m.advisory_id for m in vuln if not m.fixed_version]
    if no_fix:
        return UpgradePlan(**base, target_version=None, status=PlanStatus.UNCERTAIN,
                           reason=f"no fixed version published for {', '.join(no_fix)}", advisory_ids=ids)

    # Smallest version that clears every matched advisory = highest "fixed" among them...
    target = max((m.fixed_version for m in vuln), key=Version)
    # ...then re-check the target itself: it may fall inside a LATER advisory's range.
    for _ in range(_MAX_BUMPS):
        probe = dep.__class__(**{**dep.__dict__, "version": target})
        still = [m for adv in advisories
                 if (m := match_advisory(probe, adv, retrieved_at)).decision == Decision.VULNERABLE]
        if not still:
            return UpgradePlan(**base, target_version=target, status=PlanStatus.UPGRADE,
                               reason=f"upgrade to {target} fixes "
                                      f"{_plural(count_vulnerabilities(vuln), 'vulnerability', 'vulnerabilities')} "
                                      f"({_plural(len(ids), 'advisory record', 'advisory records')})",
                               advisory_ids=ids)
        if any(not m.fixed_version for m in still):
            break
        target = max((m.fixed_version for m in still), key=Version)
    return UpgradePlan(**base, target_version=None, status=PlanStatus.UNCERTAIN,
                       reason="could not find a version that clears every advisory", advisory_ids=ids)


def _source_unavailable(dep, err: AdvisorySourceError) -> UpgradePlan:
    return UpgradePlan(dependency_id=dep.id, package=dep.raw_name, current_version=dep.version,
                       target_version=None, status=PlanStatus.UNCERTAIN,
                       reason=f"advisory source unavailable: {err.error_type}")


def fetch_all(deps, fetch: Fetcher = fetch_advisories,
              other_ecosystems: tuple[str, ...] = OTHER_ECOSYSTEMS) -> tuple[dict, list[str]]:
    """Step 03 for every dependency. Plain JSON-able result keyed by dependency id."""
    fetched: dict[str, dict] = {}
    warnings: list[str] = []
    for dep in deps:
        try:
            advisories, retrieved_at = fetch(dep.name, dep.ecosystem)
        except AdvisorySourceError as e:
            fetched[dep.id] = {"error": e.error_type, "advisories": [], "retrieved_at": None, "other": []}
            continue
        entry = {"error": None, "advisories": advisories, "retrieved_at": retrieved_at, "other": []}
        for eco in other_ecosystems:
            try:
                others, other_at = fetch(dep.name, eco)
            except AdvisorySourceError as e:
                warnings.append(f"{dep.id}: {eco} name-collision lookup failed ({e.error_type})")
                continue
            entry["other"].append({"ecosystem": eco, "advisories": others, "retrieved_at": other_at})
        fetched[dep.id] = entry
    return fetched, warnings


def match_all(deps, fetched: dict) -> list[AdvisoryMatch]:
    """Step 02: deterministic matching, including the cross-ecosystem collisions (TC2)."""
    out: list[AdvisoryMatch] = []
    for dep in deps:
        f = fetched[dep.id]
        if f["error"]:
            continue
        out += [match_advisory(dep, adv, f["retrieved_at"]) for adv in f["advisories"]]
        seen = {a.get("id") for a in f["advisories"]}
        for o in f["other"]:
            for adv in o["advisories"]:
                if adv.get("id") in seen:
                    continue
                seen.add(adv.get("id"))
                m = match_advisory(dep, adv, o["retrieved_at"])
                m.queried_ecosystem = o["ecosystem"]
                out.append(m)
    return out


def plan_all(deps, fetched: dict, matches: list[AdvisoryMatch]) -> list[UpgradePlan]:
    plans = []
    for dep in deps:
        f = fetched[dep.id]
        if f["error"]:
            # No data is not "no advisories": never plan an upgrade or call it safe.
            plans.append(_source_unavailable(dep, AdvisorySourceError(f["error"])))
            continue
        own = [m for m in matches if m.dependency_id == dep.id and m.queried_ecosystem == "PyPI"]
        plans.append(_plan(dep, own, f["advisories"], f["retrieved_at"]))
    return plans


def scan(requirements_text: str, fetch: Fetcher = fetch_advisories,
         other_ecosystems: tuple[str, ...] = OTHER_ECOSYSTEMS) -> ScanResult:
    deps = parse_requirements(requirements_text)
    fetched, warnings = fetch_all(deps, fetch, other_ecosystems)
    matches = match_all(deps, fetched)
    return ScanResult(dependencies=deps, matches=matches, plans=plan_all(deps, fetched, matches),
                      warnings=warnings)
