"""Plain-text rendering shared by the CLI and the graph's report node."""
from __future__ import annotations

from .models import AdvisoryMatch, UpgradePlan


def format_scan(plans: list[UpgradePlan], matches: list[AdvisoryMatch], warnings: list[str],
                verbose: bool = True) -> str:
    out = [f"\n{'PACKAGE':<14}{'CURRENT':<10}{'TARGET':<10}{'STATUS':<11}REASON"]
    out += [f"{p.package:<14}{p.current_version or '-':<10}{p.target_version or '-':<10}"
            f"{p.status.value:<11}{p.reason}" for p in plans]
    collisions = [m for m in matches if m.queried_ecosystem != "PyPI"]
    if not verbose:
        if collisions:
            out.append(f"TC2: {len(collisions)} same-name advisor{'y' if len(collisions) == 1 else 'ies'} in other "
                       f"ecosystems excluded ({', '.join(sorted({m.reason.split(',')[0].removeprefix('advisory is for ') for m in collisions}))})"
                       " - details with --verbose")
        out += [f"warning: {w}" for w in warnings]
        return "\n".join(out)
    out.append("\nPer-advisory decisions (PyPI):")
    out += [f"  [{m.decision.value:<12}] {m.dependency_id:<28} {m.advisory_id:<22} {m.reason}"
            for m in matches if m.queried_ecosystem == "PyPI"]
    out.append("\nSame name in other ecosystems (TC2 - not this package, never upgraded):")
    out += [f"  {m.dependency_id:<28} {m.advisory_id:<22} {m.decision.value}: {m.reason}" for m in collisions]
    if not collisions:
        out.append("  none found")
    out += [f"  warning: {w}" for w in warnings]
    return "\n".join(out)
