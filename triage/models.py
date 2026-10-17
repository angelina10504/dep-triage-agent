"""Plain data records shared by every step of the agent.

Every record carries a stable ID and the evidence behind it, so any row in the
final triage table can be traced back to its input line and advisory source.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class Decision(str, Enum):
    """Outcome of comparing ONE dependency against ONE advisory."""

    VULNERABLE = "vulnerable"        # installed version is inside an affected range
    NOT_AFFECTED = "not_affected"    # same package, but installed version is outside every range
    EXCLUDED = "excluded"            # advisory is about a different package/ecosystem, or withdrawn
    UNCERTAIN = "uncertain"          # required evidence missing (unpinned version, unparseable range...)


class PlanStatus(str, Enum):
    """What the agent intends to do for ONE dependency."""

    UPGRADE = "upgrade"
    NO_ACTION = "no_action"
    UNCERTAIN = "uncertain"


@dataclass
class Dependency:
    id: str                 # stable ID, e.g. "PyPI:requests@2.19.0#L1"
    name: str               # canonical name (PEP 503), e.g. "jinja2"
    raw_name: str           # as written in the file, e.g. "Jinja2"
    version: str | None     # exact pinned version, or None if not pinned with ==
    line: int               # 1-based line number in the dependency file
    spec: str               # the raw line, kept as evidence
    ecosystem: str = "PyPI"


@dataclass
class AdvisoryMatch:
    dependency_id: str
    advisory_id: str
    aliases: list[str]
    summary: str
    url: str
    decision: Decision
    reason: str             # human-readable explanation of the decision
    affected_range: str     # the range that decided it, e.g. ">=0, <2.32.4"
    fixed_version: str | None
    source: str             # where the advisory came from, e.g. "osv.dev"
    retrieved_at: str       # ISO-8601 UTC timestamp of the fetch
    queried_ecosystem: str = "PyPI"   # which OSV lookup returned it (other values = TC2 name-collision check)


@dataclass
class UpgradePlan:
    dependency_id: str
    package: str
    current_version: str | None
    target_version: str | None
    status: PlanStatus
    reason: str
    advisory_ids: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    dependencies: list[Dependency]
    matches: list[AdvisoryMatch]
    plans: list[UpgradePlan]
    warnings: list[str] = field(default_factory=list)   # e.g. a cross-ecosystem lookup that failed

    def to_dict(self) -> dict:
        return asdict(self)
