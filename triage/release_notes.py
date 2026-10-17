"""Release notes between two versions, as small citable items. Deterministic, no LLM.

Source order, per version in (current, target]:
  1. the GitHub release for that version (repo found via PyPI project_urls), if its body
     has real bullet points (not just "Changes: <link>");
  2. otherwise that version's section of the changelog file (CHANGES.rst, CHANGELOG.md...).
Each item keeps a URL that points at exactly what was fetched (release page, or the
changelog file at the target tag with line anchors), so the LLM can only cite those.
Only items that look compatibility-relevant (removed, deprecated, dropped...) are kept.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import requests
from packaging.version import InvalidVersion, Version

CHANGELOG_FILES = ("CHANGES.rst", "CHANGES.md", "CHANGELOG.md", "CHANGELOG.rst", "HISTORY.md",
                   "HISTORY.rst", "NEWS.md", "NEWS.rst")
RELEVANT = re.compile(r"remov|deprecat|\bdrop|breaking|no longer|renam|incompatib|minimum|"
                      r"require|default|replac|changed", re.IGNORECASE)
MAX_CHARS = 9000                 # what is sent to the LLM (free-tier token budget)
_GITHUB = re.compile(r"https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/|$)")
# "Version 3.0.0", "## [3.0.0] - 2023-09-30", "3.0.0 (2023-09-30)" - at column 0, nothing but a date after.
_HEADING = re.compile(r"^(?:#{1,6}\s*)?\[?(?:version\s+|v)?(\d+(?:\.\d+)+(?:(?:a|b|rc|\.post|\.dev)\d+)?)\]?"
                      r"\s*(?:$|[-–(:]|\d{4}-)", re.IGNORECASE)
_BULLET = re.compile(r"^(\s*)[-*+]\s+(.*)$")
_LINK_ONLY = re.compile(r"^[\w .-]{1,40}:\s*<?https?://\S+>?$")


@dataclass
class NoteItem:
    version: str
    text: str
    source_url: str
    source: str                  # github_release | changelog


@dataclass
class ReleaseNotes:
    repo: str | None
    items: list[NoteItem] = field(default_factory=list)
    fetched_urls: list[str] = field(default_factory=list)
    skipped_irrelevant: int = 0
    truncated: int = 0
    note: str = ""               # e.g. "no release notes found (...)"


def _v(s: str) -> Version | None:
    try:
        return Version(s)
    except InvalidVersion:
        return None


def github_repo(project_urls: dict | None, home_page: str | None = None) -> str | None:
    urls = list((project_urls or {}).items())
    # Prefer keys that name the source code over docs/funding links.
    urls.sort(key=lambda kv: 0 if re.search(r"source|repo|code|github", kv[0], re.I) else 1)
    for _, url in urls + [("home", home_page or "")]:
        if m := _GITHUB.match(url or ""):
            return f"{m.group(1)}/{m.group(2)}"
    return None


def _bullets(lines: list[str], first_lineno: int = 1) -> list[tuple[int, int, str]]:
    """(start_line, end_line, text) per bullet; indented lines continue the bullet above."""
    out: list[list] = []
    for i, line in enumerate(lines, start=first_lineno):
        if m := _BULLET.match(line):
            out.append([i, i, m.group(2).strip()])
        elif out and line.strip() and line[:1].isspace() and out[-1][1] == i - 1:
            out[-1][1], out[-1][2] = i, f"{out[-1][2]} {line.strip()}"
    return [(a, b, " ".join(t.split())) for a, b, t in out]


def _tag_version(tag: str, package: str) -> Version | None:
    t = re.sub(rf"^(?:{re.escape(package)}[-@_ ]?)?v?", "", tag.strip(), flags=re.IGNORECASE)
    return _v(t)


def changelog_sections(text: str) -> list[tuple[Version, int, list[str]]]:
    """(version, first_line_number, lines) for every version heading in a changelog."""
    lines = text.splitlines()
    heads = [(i, v) for i, line in enumerate(lines)
             if len(line) < 80 and (m := _HEADING.match(line)) and (v := _v(m.group(1)))]
    out = []
    for n, (i, v) in enumerate(heads):
        end = heads[n + 1][0] if n + 1 < len(heads) else len(lines)
        out.append((v, i + 2, lines[i + 1:end]))       # +2: 1-based and skip the heading line
    return out


class _Http:
    def __init__(self, session: requests.Session, github_token: str | None):
        self.s, self.token = session, github_token

    def get(self, url: str, raw: bool = False, **params):
        headers = {"Accept": "application/vnd.github.raw" if raw else "application/vnd.github+json"} \
            if "api.github.com" in url else {}
        # Token only for the API (rate limits). Raw file downloads are public, and sending a
        # fine-grained token for another owner's repo there stalls for ~20-30s.
        if self.token and url.startswith("https://api.github.com/"):
            headers["Authorization"] = f"Bearer {self.token}"
        return self.s.get(url, params=params or None, headers=headers, timeout=20)


def fetch_release_notes(package: str, current: str, target: str, session: requests.Session | None = None,
                        github_token: str | None = None) -> ReleaseNotes:
    http = _Http(session or requests.Session(), github_token)
    lo, hi = Version(current), Version(target)
    in_range = lambda v: v is not None and lo < v <= hi and (not v.is_prerelease or hi.is_prerelease)

    r = http.get(f"https://pypi.org/pypi/{package}/json")
    if r.status_code != 200:
        return ReleaseNotes(None, note=f"no release notes found (PyPI HTTP {r.status_code})")
    info = r.json().get("info", {})
    repo = github_repo(info.get("project_urls"), info.get("home_page"))
    if not repo:
        return ReleaseNotes(None, note="no release notes found (no GitHub repository in PyPI project_urls)")
    notes = ReleaseNotes(repo)

    # 1. GitHub releases.
    by_version: dict[Version, list[NoteItem]] = {}
    target_tag = None
    for page in range(1, 4):
        url = f"https://api.github.com/repos/{repo}/releases"
        resp = http.get(url, per_page=100, page=page)
        if resp.status_code != 200:
            break
        notes.fetched_urls.append(f"{url}?page={page}")
        releases = resp.json()
        for rel in releases:
            v = _tag_version(rel.get("tag_name", ""), package)
            if v == hi:
                target_tag = rel["tag_name"]
            if not in_range(v) or rel.get("draft"):
                continue
            items = [NoteItem(str(v), t, rel["html_url"], "github_release")
                     for _, _, t in _bullets((rel.get("body") or "").splitlines())
                     if len(t) >= 15 and not _LINK_ONLY.match(t)]
            if items:
                by_version[v] = items
        if len(releases) < 100:
            break

    # 2. Changelog file for versions whose release has no real notes.
    ref = target_tag or "HEAD"
    for name in CHANGELOG_FILES:
        # Contents API with the raw media type: same file as raw.githubusercontent.com, but on
        # api.github.com (raw.githubusercontent.com connects slowly from some networks).
        url = f"https://api.github.com/repos/{repo}/contents/{name}"
        resp = http.get(url, raw=True, ref=ref)
        if resp.status_code != 200:
            continue
        notes.fetched_urls.append(f"{url}?ref={ref}")
        blob = f"https://github.com/{repo}/blob/{ref}/{name}"
        for v, first, lines in changelog_sections(resp.text):
            if in_range(v) and v not in by_version:
                items = [NoteItem(str(v), t, f"{blob}#L{a}" + (f"-L{b}" if b > a else ""), "changelog")
                         for a, b, t in _bullets(lines, first)]
                if items:
                    by_version[v] = items
        break

    # 3. Keep relevant items; feature releases first (x.0.0, then x.y.0), then patches.
    all_items = [i for v in sorted(by_version) for i in by_version[v]]
    relevant = [i for i in all_items if RELEVANT.search(i.text)]
    notes.skipped_irrelevant = len(all_items) - len(relevant)
    rank = lambda i: (0 if Version(i.version).release[1:] in ((0,), (0, 0)) else
                      1 if Version(i.version).micro == 0 else 2, Version(i.version))
    size = 0
    for item in sorted(relevant, key=rank):
        if size + len(item.text) > MAX_CHARS:
            notes.truncated += 1
            continue
        notes.items.append(item)
        size += len(item.text)
    if not notes.items:
        notes.note = (f"no release notes found between {current} and {target}" if not all_items
                      else f"release notes found, but none mention removals/deprecations ({len(all_items)} items)")
    return notes
