"""assess_upgrade_risk: will THIS repo break on the upgrade? Decided in code, explained by the LLM.

1. Release notes between the versions (release_notes.py), relevant items only.
2. LLM lists breaking changes, each citing a fetched URL (uncited ones are dropped);
   deterministic "deprecated in X, removed in Y" pairs are always added.
3. Runtime drops ("Drop support for Python 3.8") are marked not applicable when the repo
   runs a newer Python (repo_context.py) and do not count.
4. LLM extracts the removed/renamed API symbols (JSON); each must be grounded in the
   change text. Backticked dotted names from the notes are added deterministically.
5. The repo's .py files are searched for those symbols (ast, file:line evidence).
6. breaking_risk, in code: high = repo uses a removed API, medium = applicable removals
   but no use found, low = nothing applicable. The LLM's text never sets the level.
"""
from __future__ import annotations

import json
import re

from packaging.version import Version

from .llm import LLMCache, LLMProvider, ask_json
from .release_notes import NoteItem, ReleaseNotes
from .repo_context import RepoContext, Usage, drop_applies, find_usages, runtime_drop

_REMOVES_DEPRECATED = re.compile(r"remov\w*\s+(?:all\s+)?(?:previously\s+)?deprecated", re.IGNORECASE)
_DEPRECATES = re.compile(r"\bdeprecat", re.IGNORECASE)
_REMOVAL = re.compile(r"\b(remov\w*|renam\w*|no longer (?:available|exists|accepted|exported)|deleted?)\b",
                      re.IGNORECASE)
_BACKTICKED = re.compile(r"`{1,2}([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)`{1,2}")
_DOTTED = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$")

SYSTEM = (
    "You read release-note items between the current and target version of a Python dependency and "
    "list the changes that can break callers: removed or renamed APIs, removed previously deprecated "
    "code, dropped Python versions, changed defaults. Quote or closely paraphrase each item and set "
    "source_url to EXACTLY the source_url of the item you used; never cite anything else. When a "
    "release removes previously deprecated code, the APIs deprecated earlier in the range are what "
    "disappears; deprecated_then_removed lists these pairs - include each, citing its deprecation_url. "
    "reasons: one or two sentences on which changes matter most for a typical caller. Do not rate the "
    "risk; that is computed elsewhere. Plain English, no markdown."
)
SCHEMA = {
    "type": "object",
    "properties": {
        "breaking_changes": {"type": "array", "items": {
            "type": "object",
            "properties": {"change": {"type": "string"}, "source_url": {"type": "string"}},
            "required": ["change", "source_url"],
            "additionalProperties": False,
        }},
        "reasons": {"type": "string"},
    },
    "required": ["breaking_changes", "reasons"],
    "additionalProperties": False,
}
SYMBOLS_SYSTEM = (
    "For each numbered breaking change, list the Python API symbols it removes or renames, as fully "
    "qualified dotted paths starting with the given import name (e.g. pkg.module.function, or "
    "pkg.module for a whole module). Use only names that appear in the change text. Use an empty list "
    "when the change is not about a specific API (e.g. a default value or a Python version)."
)
SYMBOLS_SCHEMA = {
    "type": "object",
    "properties": {"apis": {"type": "array", "items": {
        "type": "object",
        "properties": {"index": {"type": "integer"}, "symbols": {"type": "array", "items": {"type": "string"}}},
        "required": ["index", "symbols"],
        "additionalProperties": False,
    }}},
    "required": ["apis"],
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


def _cited_only(allowed: set[str], changes: list) -> tuple[list[dict], int]:
    kept = [{"change": str(c["change"]).strip(), "source_url": c["source_url"]} for c in changes
            if isinstance(c, dict) and c.get("source_url") in allowed and str(c.get("change", "")).strip()]
    return kept, len(changes) - len(kept)


def grounded(symbol: str, import_name: str, evidence: str) -> str | None:
    """Shorten a symbol to its longest prefix whose last part appears in the evidence text."""
    if not isinstance(symbol, str) or not _DOTTED.match(symbol.strip()):
        return None
    parts = symbol.strip().split(".")
    if parts[0] != import_name:
        return None
    while len(parts) >= 2:
        if re.search(rf"(?<!\w){re.escape(parts[-1])}(?!\w)", evidence):
            return ".".join(parts)
        parts.pop()
    return None


def _symbols(changes: list[dict], notes: ReleaseNotes, import_name: str, cache: LLMCache, provider,
             subject: str) -> tuple[dict[int, list[str]], str]:
    """{change index: symbols}, plus the LLM status for the record."""
    by_url: dict[str, str] = {}
    for i in notes.items:
        by_url[i.source_url] = by_url.get(i.source_url, "") + " " + i.text
    candidates = [n for n, c in enumerate(changes)
                  if c["applicable"] and not c["runtime_drop"] and (c.get("from") or _REMOVAL.search(c["change"]))]
    evidence = {n: changes[n]["change"] + " " + by_url.get(changes[n]["source_url"], "") for n in candidates}
    out: dict[int, set[str]] = {n: set() for n in candidates}
    for n in candidates:                                  # deterministic: ``pkg.module.name`` in the text
        for s in _BACKTICKED.findall(changes[n]["change"]):
            if (g := grounded(s, import_name, evidence[n])):
                out[n].add(g)
    ask = [n for n in candidates if not out[n]][:20]      # only what the text alone could not name
    status = "skipped (no applicable removals)" if not candidates else "skipped (all named in the notes)"
    if ask:
        user = json.dumps({"import_name": import_name,
                           "changes": [{"index": n, "text": changes[n]["change"][:300]} for n in ask]})
        r = ask_json(provider, cache, f"symbols:{subject}", SYMBOLS_SYSTEM, user, SYMBOLS_SCHEMA,
                     "removed_symbols", claim_fields=())
        status = r.status if r.status != "unavailable" else f"unavailable ({r.detail})"
        for api in (r.data or {}).get("apis", []):
            n = api.get("index") if isinstance(api, dict) else None
            if n in evidence:
                for s in api.get("symbols", []):
                    if (g := grounded(s, import_name, evidence[n])):
                        out[n].add(g)
    return {n: sorted(v) for n, v in out.items() if v}, status


def _level(changes: list[dict], usages: list[Usage], repo: RepoContext | None) -> tuple[str, str]:
    applicable = [c for c in changes if c["applicable"]]
    removals = [c for c in applicable
                if c["symbols"] or c.get("from") or c["runtime_drop"] or _REMOVAL.search(c["change"])]
    if usages:
        groups: dict[str, list[str]] = {}
        for u in usages:
            groups.setdefault(u.used_as, []).append(u.where())
        return "high", "; ".join(f"repo uses {s} at {', '.join(w)} -> likely to break" for s, w in groups.items())
    if removals:
        checked = "the repo does not use the affected APIs" if repo else "repo code was not checked (no --repo)"
        return "medium", f"{len(removals)} applicable removal(s)/rename(s) in the release notes, but {checked}"
    na = any(not c["applicable"] for c in changes)
    return "low", "no applicable removals or renames in the release notes" + (
        f" (runtime drops do not apply: repo uses Python {repo.python_label})" if na and repo else "")


def import_name_for(package: str) -> str:
    return package.lower().replace("-", "_").replace(".", "_")


def assess_upgrade_risk(package: str, current: str, target: str, notes: ReleaseNotes, cache: LLMCache,
                        provider: LLMProvider | None | str = "env", repo: RepoContext | None = None,
                        import_name: str | None = None) -> dict:
    base = {"package": package, "current_version": current, "target_version": target,
            "notes_repo": notes.repo, "notes_items": len(notes.items), "fetched_urls": notes.fetched_urls,
            "repo_python": repo.python_label if repo else None, "usages": [], "symbols": [],
            "symbols_status": "", "dropped_uncited": 0}
    if not notes.items:
        return {**base, "breaking_risk": "unknown", "risk_reason": notes.note or "no release notes found",
                "breaking_changes": [], "reasons": "", "status": "no_notes", "detail": ""}
    pairs = deprecation_removals(notes.items)
    facts = {"package": package, "current_version": current, "target_version": target,
             "release_notes": [{"version": i.version, "source_url": i.source_url, "text": i.text} for i in notes.items],
             "deprecated_then_removed": pairs}
    subject = f"{package}:{current}->{target}"
    r = ask_json(provider, cache, f"risk:{subject}", SYSTEM, json.dumps(facts, sort_keys=True), SCHEMA,
                 "upgrade_breaking_changes", claim_fields=("reasons",))
    llm_changes, dropped = _cited_only({i.source_url for i in notes.items}, (r.data or {}).get("breaking_changes", []))
    changes = _merge(llm_changes, pairs)

    for c in changes:                                     # applicability: deterministic
        c["runtime_drop"] = runtime_drop(c["change"])
        c["applicable"] = drop_applies(c["runtime_drop"], repo)
        c["not_applicable"] = "" if c["applicable"] else f"not applicable (repo uses Python {repo.python_label})"
    syms, sym_status = _symbols(changes, notes, import_name or import_name_for(package), cache, provider, subject)
    for n, c in enumerate(changes):
        c["symbols"] = syms.get(n, [])
    all_symbols = sorted({s for c in changes for s in c["symbols"]})
    usages = find_usages(repo.files, all_symbols) if repo else []
    for c in changes:
        c["used"] = any(u.symbol in c["symbols"] for u in usages)
    level, why = _level(changes, usages, repo)
    reasons = (r.data or {}).get("reasons", "") if r.available else (
        f"LLM unavailable: {r.detail}" if r.status == "unavailable" else "LLM disabled")
    return {**base, "breaking_risk": level, "risk_reason": why, "breaking_changes": changes,
            "dropped_uncited": dropped, "symbols": all_symbols, "symbols_status": sym_status,
            "usages": [u.__dict__ for u in usages], "reasons": reasons, "status": r.status, "detail": r.detail}


def render_risk(risk: dict, top: int = 3, verbose: bool = False) -> list[str]:
    short = (lambda t: t) if verbose else (lambda t: t if len(t) <= 160 else t[:157].rstrip() + "...")
    lines = [f"breaking risk: {risk['breaking_risk']} - {risk['risk_reason']}"]
    lines += [f"  {u['path']}:{u['line']}  {u['code']}" for u in risk.get("usages", [])]
    changes = risk["breaking_changes"]
    applicable = sorted((c for c in changes if c.get("applicable", True)),
                        key=lambda c: (not c.get("used"), not c.get("symbols"), not c.get("from")))
    shown = applicable if verbose else applicable[:top]
    for c in shown:
        tag = "[used by repo] " if c.get("used") else ""
        text = c["change"].split("): ", 1)[-1] if c.get("from") else c["change"]
        lines.append(f"  - {tag}{short(text)} ({c['source_url']})")
    if len(applicable) > len(shown):
        lines.append(f"  ... {len(applicable) - len(shown)} more applicable change(s) (--verbose)")
    na = [c for c in changes if not c.get("applicable", True)]
    if na:
        lines.append(f"  {na[0]['not_applicable']}: {len(na)} runtime-drop item(s), not counted")
        if verbose:
            lines += [f"    - {short(c['change'])} ({c['source_url']})" for c in na]
    if verbose:
        if risk.get("symbols"):
            lines.append(f"  symbols searched in repo: {', '.join(risk['symbols'])}")
        if risk.get("reasons"):
            lines.append(f"  LLM note: {risk['reasons']}")
        if risk.get("dropped_uncited"):
            lines.append(f"  ({risk['dropped_uncited']} claimed change(s) dropped: cited no fetched URL)")
    return lines
