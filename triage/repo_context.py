"""What the target repo actually uses: its Python version(s) and where it touches an API.

Deterministic, no LLM. Files are read through the GitHub API (tree + contents) at the
base branch. Usages are found with Python's ast, resolving imports, so
    from werkzeug.urls import url_quote      (line 6)
    return url_quote(path)                   (line 10)
are both reported as uses of werkzeug.urls.url_quote. Files that do not parse fall back
to a plain text search for the dotted name.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

MAX_FILES = 300
MAX_BYTES = 300_000
_SKIP = re.compile(r"(^|/)(\.venv|venv|site-packages|node_modules|\.tox|build|dist)/")
_PY_IN_WORKFLOW = re.compile(r"python-version\s*:\s*(\[[^\]]*\]|['\"]?[\d.]+['\"]?)", re.IGNORECASE)
_MAJOR_MINOR = re.compile(r"\b(\d+\.\d+)(?:\.\d+)?\b")
_REQUIRES_PYTHON = re.compile(r"requires-python\s*=\s*['\"]([^'\"]+)['\"]")
# "Drop support for Python 3.7", "Removed support for Python 3.7 and 3.8", "Python 3.8 is no longer supported"
_RUNTIME_DROP = re.compile(r"(?:drop\w*|remov\w*|end\w*)\s+(?:official\s+)?support\s+for\s+(c?python|pypy)\s*"
                           r"(\d+\.\d+(?:\s*(?:,|and|&)\s*\d+\.\d+)*)"
                           r"|(c?python|pypy)\s*(\d+\.\d+)\s+(?:is\s+)?no\s+longer\s+supported", re.IGNORECASE)


@dataclass
class Usage:
    symbol: str          # the removed/renamed symbol we looked for, e.g. werkzeug.urls
    used_as: str         # what the code refers to, e.g. werkzeug.urls.url_quote
    path: str
    line: int
    code: str

    def where(self) -> str:
        return f"{self.path}:{self.line}"


@dataclass
class RepoContext:
    repo: str
    ref: str
    python_versions: list[str] = field(default_factory=list)   # e.g. ["3.12"]
    python_source: str = ""                                     # where they came from
    files: dict[str, str] = field(default_factory=dict)          # .py path -> text
    note: str = ""
    pypy: bool = False                                          # a workflow tests on PyPy

    @property
    def python_label(self) -> str:
        return ", ".join(self.python_versions) or "unknown"


def python_versions(workflows: dict[str, str], pyproject: str | None) -> tuple[list[str], str]:
    found: set[str] = set()
    sources = []
    for path, text in sorted(workflows.items()):
        vs = {m for raw in _PY_IN_WORKFLOW.findall(text) for m in _MAJOR_MINOR.findall(raw)}
        if vs:
            found |= vs
            sources.append(path)
    if found:
        return sorted(found, key=Version), ", ".join(sources)
    if pyproject and (m := _REQUIRES_PYTHON.search(pyproject)):
        try:
            spec = SpecifierSet(m.group(1))
        except InvalidSpecifier:
            return [], ""
        lows = [s.version for s in spec if s.operator in (">=", ">", "~=", "==")]
        if lows:
            return [".".join(min(lows, key=Version).split(".")[:2])], f"pyproject.toml requires-python {m.group(1)}"
    return [], ""


def runtime_drop(text: str) -> list[str]:
    """Runtimes a release-note item says it drops: ['3.7', '3.8'] (CPython) or ['pypy3.8']; [] if none."""
    out = []
    for m in _RUNTIME_DROP.finditer(text):
        impl = (m.group(1) or m.group(3) or "").lower()
        prefix = "pypy" if impl == "pypy" else ""
        out += [prefix + v for v in _MAJOR_MINOR.findall(m.group(2) or m.group(4) or "")]
    return out


def drop_applies(dropped: list[str], ctx: RepoContext | None) -> bool:
    """A dropped runtime matters only if the repo still runs on it (or we don't know)."""
    if not dropped or ctx is None or not ctx.python_versions:
        return True
    cpython = [d for d in dropped if not d.startswith("pypy")]
    if not cpython:                                   # PyPy-only drop
        return ctx.pypy
    try:
        return min(Version(v) for v in ctx.python_versions) <= max(Version(d) for d in cpython)
    except InvalidVersion:
        return True


def fetch_repo_context(client, repo: str, ref: str) -> RepoContext:
    """Read workflows, pyproject.toml and .py files at ref via the GitHub API."""
    tree = client.get(f"/repos/{repo}/git/trees/{ref}", recursive=1)
    blobs = [t for t in tree.get("tree", []) if t.get("type") == "blob"]
    ctx = RepoContext(repo, ref)
    workflows, pyproject = {}, None
    py = [b for b in blobs if b["path"].endswith(".py") and not _SKIP.search(b["path"])
          and b.get("size", 0) <= MAX_BYTES]
    for b in blobs:
        p = b["path"]
        if re.match(r"\.github/workflows/[^/]+\.ya?ml$", p):
            workflows[p], _ = client.get_file(repo, p, ref)
        elif p == "pyproject.toml":
            pyproject, _ = client.get_file(repo, p, ref)
    ctx.python_versions, ctx.python_source = python_versions(workflows, pyproject)
    ctx.pypy = any(re.search(r"python-version\s*:.*pypy", t, re.IGNORECASE) for t in workflows.values())
    for b in py[:MAX_FILES]:
        ctx.files[b["path"]], _ = client.get_file(repo, b["path"], ref)
    if len(py) > MAX_FILES or tree.get("truncated"):
        ctx.note = f"only the first {MAX_FILES} Python files were searched"
    return ctx


def _matches(full: str, symbol: str) -> bool:
    return full == symbol or full.startswith(symbol + ".")


def _dotted(node: ast.AST) -> tuple[str, list[str]] | None:
    attrs = []
    while isinstance(node, ast.Attribute):
        attrs.append(node.attr)
        node = node.value
    return (node.id, attrs[::-1]) if isinstance(node, ast.Name) else None


def find_usages(files: dict[str, str], symbols: list[str]) -> list[Usage]:
    found: dict[tuple, Usage] = {}

    def add(sym, used_as, path, line, lines):
        found.setdefault((sym, path, line), Usage(sym, used_as, path, line, lines[line - 1].strip()))

    for path, text in sorted(files.items()):
        lines = text.splitlines()
        try:
            tree = ast.parse(text)
        except SyntaxError:
            for i, l in enumerate(lines, 1):
                for s in symbols:
                    if re.search(rf"\b{re.escape(s)}\b", l):
                        add(s, s, path, i, lines)
            continue
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    local = a.asname or a.name.split(".")[0]
                    aliases[local] = a.name if a.asname else a.name.split(".")[0]
                    for s in symbols:
                        if _matches(a.name, s) or _matches(s, a.name) and a.name != s.split(".")[0]:
                            add(s, a.name, path, node.lineno, lines)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for a in node.names:
                    full = f"{node.module}.{a.name}"
                    aliases[a.asname or a.name] = full
                    for s in symbols:
                        if _matches(full, s) or _matches(node.module, s):
                            add(s, full, path, node.lineno, lines)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Name, ast.Attribute)) and (d := _dotted(node)) and d[0] in aliases:
                full = ".".join([aliases[d[0]], *d[1]])
                for s in symbols:
                    if _matches(full, s):
                        add(s, full, path, node.lineno, lines)
    # Keep the most specific name per location (werkzeug.urls.url_quote over werkzeug.urls).
    best: dict[tuple, Usage] = {}
    for u in found.values():
        k = (u.path, u.line)
        if k not in best or len(u.used_as) > len(best[k].used_as):
            best[k] = u
    return sorted(best.values(), key=lambda u: (u.path, u.line))
