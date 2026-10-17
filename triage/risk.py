"""assess_upgrade_risk: how likely is the upgrade to break code, from fetched release notes.

The LLM sees only the relevant release-note items (release_notes.py) and must cite one of
their URLs for every breaking change. Anything citing a URL we did not fetch is dropped.
No notes -> "no release notes found", no LLM call. LLM down -> risk "unknown".
"""
from __future__ import annotations

import json
import re

from packaging.version import Version

from .llm import LLMCache, LLMError, LLMProvider, ask_json
from .release_notes import NoteItem, ReleaseNotes

_REMOVES_DEPRECATED = re.compile(r"remov\w*\s+(?:all\s+)?(?:previously\s+)?deprecated", re.IGNORECASE)
_DEPRECATES = re.compile(r"\bdeprecat", re.IGNORECASE)

SYSTEM = (
    "You assess whether upgrading a Python dependency may break the code that uses it. You get the "
    "release-note items between the current and target version, each with a source_url. List only "
    "changes that can break callers (removed or renamed APIs, removed previously deprecated code, "
    "dropped Python versions, changed defaults). Quote or closely paraphrase the item, and set "
    "source_url to EXACTLY the source_url of the item you used. Never cite anything else. When a "
    "release says it removes previously deprecated code, the APIs deprecated in EARLIER versions of "
    "the given range are what disappears; deprecated_then_removed lists these pairs. Include each pair "
    "as a breaking change citing its deprecation_url. "
    "breaking_risk: high (removals of APIs likely in use or a major version jump with "
    "removals), medium (behaviour or default changes), low (nothing found). Plain English, no markdown."
)
SCHEMA = {
    "type": "object",
    "properties": {
        "breaking_risk": {"type": "string", "enum": ["high", "medium", "low"]},
        "breaking_changes": {"type": "array", "items": {
            "type": "object",
            "properties": {"change": {"type": "string"}, "source_url": {"type": "string"}},
            "required": ["change", "source_url"],
            "additionalProperties": False,
        }},
        "reasons": {"type": "string"},
    },
    "required": ["breaking_risk", "breaking_changes", "reasons"],
    "additionalProperties": False,
}


def deprecation_removals(items: list[NoteItem]) -> list[dict]:
    """Deterministic: "removed previously deprecated code" in V removes what was deprecated
    since the previous such removal. Pairs each removal with those earlier deprecation items."""
    removals = sorted((i for i in items if _REMOVES_DEPRECATED.search(i.text)), key=lambda i: Version(i.version))
    out, floor = [], None
    for r in removals:
        rv = Version(r.version)
        for d in items:
            dv = Version(d.version)
            if d is not r and _DEPRECATES.search(d.text) and not _REMOVES_DEPRECATED.search(d.text) \
                    and dv < rv and (floor is None or dv >= floor):
                out.append({"deprecated": d.text, "deprecated_in": d.version, "deprecation_url": d.source_url,
                            "removed_in": r.version, "removal_url": r.source_url})
        floor = rv
    return out


def _guaranteed(pairs: list[dict]) -> list[dict]:
    return [{"change": f"Deprecated in {p['deprecated_in']}, then {p['removed_in']} removed previously "
                       f"deprecated code ({p['removal_url']}): {p['deprecated']}",
             "source_url": p["deprecation_url"], "from": "release_notes"} for p in pairs]


def _merge(llm_changes: list[dict], pairs: list[dict]) -> list[dict]:
    """LLM changes plus every deterministic deprecation->removal pair it left out."""
    cited = {c["source_url"] for c in llm_changes}
    return llm_changes + [g for g in _guaranteed(pairs) if g["source_url"] not in cited]


def _cited_only(allowed: set[str], out: dict) -> dict:
    """Keep only breaking changes that cite a fetched URL; count what was dropped."""
    kept = [c for c in out["breaking_changes"]
            if isinstance(c, dict) and c.get("source_url") in allowed and str(c.get("change", "")).strip()]
    return {**out, "breaking_changes": kept, "dropped_uncited": len(out["breaking_changes"]) - len(kept)}


def _check(allowed: set[str]):
    def validate(out: dict) -> dict:
        if out["breaking_risk"] in ("high", "medium") and not _cited_only(allowed, out)["breaking_changes"]:
            raise LLMError("InvalidOutput (risk claimed without a cited breaking change)")
        return out
    return validate


def assess_upgrade_risk(package: str, current: str, target: str, notes: ReleaseNotes, cache: LLMCache,
                        provider: LLMProvider | None | str = "env") -> dict:
    base = {"package": package, "current_version": current, "target_version": target,
            "notes_repo": notes.repo, "notes_items": len(notes.items), "fetched_urls": notes.fetched_urls}
    if not notes.items:
        return {**base, "breaking_risk": "unknown", "breaking_changes": [], "dropped_uncited": 0,
                "reasons": notes.note or "no release notes found", "status": "no_notes", "detail": ""}
    facts = {
        "package": package, "current_version": current, "target_version": target,
        "major_version_change": Version(target).major != Version(current).major,
        "release_notes": [{"version": i.version, "source_url": i.source_url, "text": i.text} for i in notes.items],
        "deprecated_then_removed": deprecation_removals(notes.items),
    }
    allowed = {i.source_url for i in notes.items}
    r = ask_json(provider, cache, f"risk:{package}:{current}->{target}", SYSTEM,
                 json.dumps(facts, sort_keys=True), SCHEMA, "upgrade_risk",
                 claim_fields=("reasons",), validate=_check(allowed))
    if not r.available:
        reason = f"LLM unavailable: {r.detail}" if r.status == "unavailable" else "LLM disabled"
        return {**base, "breaking_risk": "unknown", "breaking_changes": _guaranteed(facts["deprecated_then_removed"]),
                "dropped_uncited": 0,
                "reasons": f"{reason}; {len(notes.items)} relevant release-note items were fetched",
                "status": r.status, "detail": r.detail}
    # The citation filter runs here, so cached answers get the same check as fresh ones.
    data = _cited_only(allowed, {k: r.data[k] for k in SCHEMA["required"]})
    data["breaking_changes"] = _merge(data["breaking_changes"], facts["deprecated_then_removed"])
    if facts["deprecated_then_removed"] and data["breaking_risk"] == "low":
        data["breaking_risk"] = "medium"
        data["reasons"] += " (raised from low: the release notes show deprecated APIs being removed)"
    return {**base, **data, "status": r.status, "detail": r.detail}


def render_risk(risk: dict) -> list[str]:
    lines = [f"breaking risk: {risk['breaking_risk']} - {risk['reasons']}"]
    short = lambda t: t if len(t) <= 180 else t[:177].rstrip() + "..."
    lines += [f"  - {short(c['change'])} ({c['source_url']})" for c in risk["breaking_changes"] if not c.get("from")]
    pairs = [c for c in risk["breaking_changes"] if c.get("from")]
    if pairs:
        lines.append("  deprecated earlier, removed later (deterministic, from the fetched notes):")
        lines += [f"  - {short(c['change'].split('): ', 1)[-1])} ({c['source_url']})" for c in pairs]
    if risk.get("dropped_uncited"):
        lines.append(f"  ({risk['dropped_uncited']} claimed change(s) dropped: cited no fetched URL)")
    return lines
