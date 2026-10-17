"""Steps 01-03 tied together: parse -> fetch advisories -> match -> upgrade plan."""
from __future__ import annotations

from typing import Callable

from packaging.version import Version

from .matcher import match_advisory
from .models import AdvisoryMatch, Decision, PlanStatus, ScanResult, UpgradePlan
from .osv import fetch_advisories
from .parser import parse_requirements

Fetcher = Callable[[str, str], tuple[list[dict], str]]
_MAX_BUMPS = 10


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
                               reason=f"upgrade to {target} clears {len(ids)} "
                                      f"advisor{'y' if len(ids) == 1 else 'ies'}", advisory_ids=ids)
        if any(not m.fixed_version for m in still):
            break
        target = max((m.fixed_version for m in still), key=Version)
    return UpgradePlan(**base, target_version=None, status=PlanStatus.UNCERTAIN,
                       reason="could not find a version that clears every advisory", advisory_ids=ids)


def scan(requirements_text: str, fetch: Fetcher = fetch_advisories) -> ScanResult:
    deps = parse_requirements(requirements_text)
    all_matches: list[AdvisoryMatch] = []
    plans: list[UpgradePlan] = []
    for dep in deps:
        advisories, retrieved_at = fetch(dep.name, dep.ecosystem)
        matches = [match_advisory(dep, adv, retrieved_at) for adv in advisories]
        all_matches.extend(matches)
        plans.append(_plan(dep, matches, advisories, retrieved_at))
    return ScanResult(dependencies=deps, matches=all_matches, plans=plans)
