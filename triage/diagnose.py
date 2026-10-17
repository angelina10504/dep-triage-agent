"""diagnose_failure: why did CI fail on an upgrade PR? Evidence from the job log, LLM summary.

Deterministic part: find the failed GitHub Actions job, download its log, cut the window
around the error (not the plain tail: post-job cleanup lines come after the error), and
pick out lines like "E   ImportError: ...". The LLM explains the window; every evidence
line it quotes must appear in the window or it is dropped. The PR outcome is NOT changed:
it stays "PR failing, NOT fixed".
"""
from __future__ import annotations

import json
import re

from packaging.version import InvalidVersion, Version

from .github_pr import GitHubClient, GitHubError
from .llm import LLMCache, LLMError, LLMProvider, ask_json

_TS = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ?")
_JOB = re.compile(r"/actions/runs/\d+/job/(\d+)")
_ANCHOR = re.compile(r"##\[error\]")
_ERROR = re.compile(r"^E\s{2,}\S|\b\w+(?:Error|Exception)\b:|^Traceback|\bFAILED\b|##\[error\]")
_FAILED_STATES = {"failure", "timed_out", "cancelled"}
WINDOW_BEFORE = 40

SYSTEM = (
    "You diagnose why a CI job failed after a dependency upgrade. You get the package, the version "
    "change and an excerpt of the failed job log. root_cause: one or two sentences naming the error "
    "and the code it comes from. evidence_lines: copy 1-4 lines EXACTLY as they appear in the log "
    "excerpt (without the line numbers). suggested_next_step: one concrete CODE change that makes the "
    "project work on the target version, then re-run CI (for example: replace a removed function with "
    "its standard-library equivalent). The old version is vulnerable: never suggest staying on it, "
    "downgrading, or pinning to any version below the target. If an import from a module failed because "
    "a name was removed, do not suggest other names from that same module. Plain English, no markdown."
)
SCHEMA = {
    "type": "object",
    "properties": {
        "root_cause": {"type": "string"},
        "evidence_lines": {"type": "array", "items": {"type": "string"}},
        "suggested_next_step": {"type": "string"},
    },
    "required": ["root_cause", "evidence_lines", "suggested_next_step"],
    "additionalProperties": False,
}


def failed_jobs(checks: list[dict]) -> list[tuple[str, str, str]]:
    """(job_id, check name, url) for failed GitHub Actions check runs."""
    out = []
    for c in checks:
        if c.get("kind") == "check_run" and c.get("state") in _FAILED_STATES and \
                (m := _JOB.search(c.get("url") or "")):
            out.append((m.group(1), c["name"], c["url"]))
    return out


def log_window(log: str) -> tuple[list[tuple[int, str]], list[str]]:
    """((line_no, text) window around the error, deterministic error lines in it)."""
    lines = [_TS.sub("", l) for l in log.splitlines()]
    anchors = [i for i, l in enumerate(lines) if _ANCHOR.search(l)]
    errors = [i for i, l in enumerate(lines) if _ERROR.search(l)]
    end = anchors[-1] if anchors else (errors[-1] if errors else len(lines) - 1)
    window = [(i + 1, lines[i]) for i in range(max(0, end - WINDOW_BEFORE), end + 1) if lines[i].strip()]
    error_lines = [t.strip() for _, t in window if re.search(r"\b\w+(?:Error|Exception)\b:", t)]
    return window, list(dict.fromkeys(error_lines))


def _norm(line: str) -> str:
    """Compare log lines ignoring a "123: " line-number prefix and whitespace differences."""
    return " ".join(re.sub(r"^\s*\d+:\s", "", line).split())


_BACKWARDS = re.compile(r"\b(downgrad\w*|revert\w*|roll(?:ing|ed)?\s+back|stay(?:ing)?\s+on|"
                        r"remain(?:ing)?\s+on|keep(?:ing)?\s+(?:the\s+)?(?:current|old|existing)\s+version|"
                        r"(?:older|previous|earlier|lower|compatible)\s+version)\b", re.IGNORECASE)
_DOTTED = re.compile(r"(?<![\w.])(\d+(?:\.(?:\d+|x|\*))+)(?![\w.]*\w)")
_PIN = re.compile(r"(<=?|==|~=)\s*(\d+(?:\.\d+)*)")


def _below(token: str, target: Version) -> bool:
    """True if a version or wildcard like '2.x' / '3.0.*' lies entirely below the target."""
    parts = token.split(".")
    if parts[-1] in ("x", "*"):
        prefix = tuple(int(p) for p in parts[:-1])
        return prefix < target.release[:len(prefix)]
    try:
        return Version(token) < target
    except InvalidVersion:
        return False


def backwards_step(step: str, target: str) -> str | None:
    """Why a suggested next step would leave the project on a vulnerable version, else None.

    The target is the lowest version outside every matched advisory's affected range
    (deterministic plan), so anything below it may still be inside a range.
    """
    t = Version(target)
    if m := _BACKWARDS.search(step):
        return f"suggests '{m.group(0)}'"
    for op, v in _PIN.findall(step):
        if (op == "<" and Version(v) <= t) or (op != "<" and Version(v) < t):
            return f"pins '{op}{v}' below the target {target}"
    for v in _DOTTED.findall(step):
        if _below(v, t):
            return f"mentions version {v}, below the target {target}"
    return None


def _in_window(window_text: str, target: str):
    lines = [(_norm(l), l.strip()) for l in window_text.splitlines()]
    failed = set(re.findall(r"cannot import name '(\w+)' from '([\w.]+)'", window_text))

    def validate(out: dict) -> dict:
        kept = []
        for e in out["evidence_lines"]:
            n = _norm(e) if isinstance(e, str) else ""
            match = next((orig for norm, orig in lines if n and n in norm), None)
            if match and match not in kept:
                kept.append(match)                      # report the log's own line, not the LLM's copy
        if not kept:
            raise LLMError("InvalidOutput (evidence lines not found in the log)")
        step = out.get("suggested_next_step", "")
        if why := backwards_step(step, target):
            raise LLMError(f"InvalidOutput (next step keeps a vulnerable version: {why})")
        for name, module in failed:
            m = re.escape(module)
            sibling = any(n != name for n in re.findall(rf"\b{m}\.(\w+)", step))
            same = re.search(rf"\b(?:use|with|switch to|import)\s+`?{m}\.{name}\b", step, re.IGNORECASE)
            if sibling or same or f"from {module} import" in step:
                raise LLMError(f"InvalidOutput (next step reuses the failing module '{module}')")
        return {**out, "evidence_lines": kept}
    return validate


def diagnose_failure(repo: str, pr_number: int, package: str, current: str, target: str,
                     checks: list[dict], client: GitHubClient, cache: LLMCache,
                     provider: LLMProvider | None | str = "env") -> dict:
    jobs = failed_jobs(checks)
    base = {"pr_number": pr_number, "outcome_unchanged": "PR failing, NOT fixed"}
    if not jobs:
        return {**base, "status": "no_log", "root_cause": "no failed GitHub Actions job found to read",
                "evidence_lines": [], "error_lines": [], "suggested_next_step": "", "job_url": None}
    job_id, name, url = jobs[0]
    try:
        log = client.get_text(f"/repos/{repo}/actions/jobs/{job_id}/logs")
    except GitHubError as e:
        return {**base, "status": "no_log", "root_cause": f"job log not readable ({str(e)[:80]})",
                "evidence_lines": [], "error_lines": [], "suggested_next_step": "", "job_url": url}
    window, error_lines = log_window(log)
    text = "\n".join(t for _, t in window)
    facts = {"package": package, "current_version": current, "target_version": target, "job": name,
             "log_excerpt": "\n".join(f"{n}: {t}" for n, t in window)}
    r = ask_json(provider, cache, f"diagnose:{repo}#{pr_number}:{job_id}", SYSTEM,
                 json.dumps(facts, sort_keys=True), SCHEMA, "ci_failure_diagnosis",
                 claim_fields=("root_cause", "suggested_next_step"), validate=_in_window(text, target))
    common = {**base, "job_url": url, "error_lines": error_lines,
              "log_window": f"lines {window[0][0]}-{window[-1][0]}" if window else ""}
    data = None
    if r.available:
        try:     # same checks for cached answers as for fresh ones (rules may be newer than the cache)
            data = _in_window(text, target)({k: r.data[k] for k in SCHEMA["required"]})
        except LLMError as e:
            r = type(r)("unavailable", None, e.reason)
    if data is None:
        reason = f"LLM unavailable: {r.detail}" if r.status == "unavailable" else "LLM disabled"
        return {**common, "status": r.status, "root_cause": reason, "evidence_lines": error_lines,
                "suggested_next_step": "", "detail": r.detail}
    return {**common, **data, "status": r.status, "detail": r.detail}


def render_diagnosis(d: dict) -> list[str]:
    lines = [f"diagnosis ({d['status']}): {d['root_cause']}"]
    lines += [f"  evidence: {e}" for e in d["evidence_lines"]]
    if d.get("suggested_next_step"):
        lines.append(f"  next step: {d['suggested_next_step']}")
    if d.get("job_url"):
        lines.append(f"  log: {d['job_url']} ({d.get('log_window', '')})")
    lines.append(f"  outcome unchanged: {d['outcome_unchanged']}")
    return lines
