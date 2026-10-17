"""Plain-language explanation of ONE upgrade plan, written by the LLM from facts we computed.

The LLM gets only deterministic facts (versions, advisory IDs, ranges, fixed versions,
whether the major version changes) and is asked to explain them. Its text is shown
next to the plan and in the PR body, labelled as an LLM explanation; it is never read
back into any decision. Failure -> Explanation(status="unavailable"), never an exception.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from packaging.version import Version

from .llm import LLMCache, LLMProvider, ask_json
from .models import AdvisoryMatch, Decision, UpgradePlan
from .scanner import count_vulnerabilities

SYSTEM = (
    "You explain dependency security upgrades to a developer team. Use ONLY the facts given in "
    "the JSON. Do not invent advisories, versions, CVEs or test results. Whether the upgrade works "
    "is decided later by the PR's CI result and a human merge. Plain English, short sentences, no markdown."
)
SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "2-3 sentences: what is vulnerable and why upgrade"},
        "upgrade_risk": {"type": "string", "description": "1-2 sentences on compatibility risk of the jump"},
        "reviewer_checklist": {"type": "string", "description": "1-3 short things a reviewer should check"},
    },
    "required": ["summary", "upgrade_risk", "reviewer_checklist"],
    "additionalProperties": False,
}


@dataclass
class Explanation:
    status: str                  # ok | cached | unavailable | disabled
    summary: str = ""
    upgrade_risk: str = ""
    reviewer_checklist: str = ""
    detail: str = ""             # why unavailable, or provider/model used

    @property
    def available(self) -> bool:
        return self.status in ("ok", "cached")

    def render(self) -> str:
        if not self.available:
            return f"LLM unavailable: {self.detail}" if self.status == "unavailable" else "LLM disabled"
        return (f"Summary: {self.summary}\nUpgrade risk: {self.upgrade_risk}\n"
                f"Reviewer checklist: {self.reviewer_checklist}")


def facts(plan: UpgradePlan, matches: list[AdvisoryMatch]) -> dict:
    vuln = [m for m in matches if m.dependency_id == plan.dependency_id and m.decision == Decision.VULNERABLE]
    cur, tgt = Version(plan.current_version), Version(plan.target_version)
    return {
        "package": plan.package,
        "ecosystem": "PyPI",
        "current_version": plan.current_version,
        "target_version": plan.target_version,
        "major_version_change": tgt.major != cur.major,
        "unique_vulnerabilities": count_vulnerabilities(vuln),
        "advisories": [{"id": m.advisory_id, "aliases": m.aliases, "summary": m.summary,
                        "affected_range": m.affected_range, "fixed_version": m.fixed_version}
                       for m in sorted(vuln, key=lambda m: m.advisory_id)],
    }


def explain(plan: UpgradePlan, matches: list[AdvisoryMatch], cache: LLMCache,
            provider: LLMProvider | None | str = "env") -> Explanation:
    """provider="env" reads LLM_PROVIDER; pass a provider (or None to disable) in tests."""
    r = ask_json(provider, cache, f"explain:{plan.dependency_id}->{plan.target_version}", SYSTEM,
                 json.dumps(facts(plan, matches), sort_keys=True), SCHEMA, "upgrade_explanation",
                 claim_fields=tuple(SCHEMA["required"]))
    if not r.available:
        return Explanation(r.status, detail=r.detail)
    return Explanation(r.status, **{k: r.data[k].strip() for k in SCHEMA["required"]}, detail=r.detail)


def with_explanation(body: str, e: Explanation | None) -> str:
    """PR body + a clearly labelled LLM section (or a note that the LLM was unavailable)."""
    if e is None or e.status == "disabled":
        return body
    text = e.render() if e.available else f"LLM explanation unavailable ({e.detail})."
    return (body + "\n\n### Explanation (LLM, advisory only)\n"
            "_Written by an LLM from the facts above; it did not choose the version or open this PR._\n\n"
            + text.replace("\n", "\n\n"))
