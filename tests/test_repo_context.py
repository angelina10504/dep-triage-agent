"""Offline tests for repo_context: Python version detection, runtime drops, ast usage search."""
import pytest

from triage.repo_context import (RepoContext, drop_applies, fetch_repo_context, find_usages, python_versions,
                                 runtime_drop)


def test_python_from_workflow_single_and_matrix():
    single = {".github/workflows/ci.yml": 'with:\n  python-version: "3.12"\n'}
    matrix = {".github/workflows/t.yml": "matrix:\n  python-version: ['3.10', '3.11', 3.12]\n"
                                         "steps:\n  - with:\n      python-version: ${{ matrix.python-version }}\n"}
    assert python_versions(single, None) == (["3.12"], ".github/workflows/ci.yml")
    assert python_versions(matrix, None)[0] == ["3.10", "3.11", "3.12"]


def test_python_from_pyproject_when_no_workflow():
    assert python_versions({}, '[project]\nrequires-python = ">=3.10, <4"\n') == \
        (["3.10"], "pyproject.toml requires-python >=3.10, <4")
    assert python_versions({}, None) == ([], "")


@pytest.mark.parametrize("text, versions", [
    ("Drop support for Python 3.8.", ["3.8"]),
    ("Removed support for Python 3.7 and 3.8", ["3.7", "3.8"]),
    ("Python 3.9 is no longer supported.", ["3.9"]),
    ("Dropped official support for CPython 3.7", ["3.7"]),
    ("Remove previously deprecated code.", []),
    ("Require Python 3.8+ syntax in examples", []),
])
def test_runtime_drop_detection(text, versions):
    assert runtime_drop(text) == versions


def test_drop_applies_only_if_repo_still_runs_it():
    ctx = RepoContext("r", "main", ["3.12"])
    assert drop_applies(["3.7", "3.8"], ctx) is False
    assert drop_applies(["3.12"], ctx) is True
    assert drop_applies(["3.8"], RepoContext("r", "main", [])) is True        # unknown python -> counts
    assert drop_applies(["3.8"], None) is True


def test_usages_resolve_from_imports_aliases_and_attribute_chains():
    files = {
        "a.py": "from werkzeug.urls import url_quote as q\nq('x')\n",
        "b.py": "import werkzeug.urls\nwerkzeug.urls.url_quote('x')\n",
        "c.py": "import werkzeug as wz\nwz.urls.url_unquote('y')\nwz.serving.run_simple()\n",
        "d.py": "import werkzeug\nfrom werkzeug import serving\nurls = 1\nurls\n",
    }
    got = [(u.path, u.line, u.used_as) for u in find_usages(files, ["werkzeug.urls"])]
    assert got == [("a.py", 1, "werkzeug.urls.url_quote"), ("a.py", 2, "werkzeug.urls.url_quote"),
                   ("b.py", 1, "werkzeug.urls"), ("b.py", 2, "werkzeug.urls.url_quote"),
                   ("c.py", 2, "werkzeug.urls.url_unquote")]


def test_unparseable_file_falls_back_to_text_search():
    files = {"bad.py": "def broken(:\n    werkzeug.urls.url_quote(1)\n"}
    u = find_usages(files, ["werkzeug.urls"])
    assert [(x.path, x.line) for x in u] == [("bad.py", 2)]


class Client:
    def __init__(self, files):
        self.files, self.read = files, []

    def get(self, path, **params):
        assert params == {"recursive": 1}
        return {"tree": [{"path": p, "type": "blob", "size": len(t)} for p, t in self.files.items()]}

    def get_file(self, repo, path, ref):
        self.read.append(path)
        return self.files[path], "sha"


def test_fetch_reads_workflows_pyproject_and_py_files_only():
    c = Client({".github/workflows/ci.yml": 'python-version: "3.12"', "app.py": "x = 1\n", "README.md": "hi",
                ".venv/lib/site.py": "nope", "pkg/mod.py": "y = 2\n"})
    ctx = fetch_repo_context(c, "acme/demo", "main")
    assert ctx.python_versions == ["3.12"] and set(ctx.files) == {"app.py", "pkg/mod.py"}
    assert "README.md" not in c.read and ".venv/lib/site.py" not in c.read


def test_pypy_drops_apply_only_if_the_repo_tests_on_pypy():
    assert runtime_drop("Requests has officially dropped support for PyPy 3.7 and 3.8.") == ["pypy3.7", "pypy3.8"]
    cpython_only = RepoContext("r", "main", ["3.12"])
    assert drop_applies(["pypy3.8"], cpython_only) is False
    assert drop_applies(["pypy3.8"], RepoContext("r", "main", ["3.12"], pypy=True)) is True


def test_pypy_detected_in_workflow():
    c = Client({".github/workflows/ci.yml": "python-version: ['3.12', 'pypy3.10']\n"})
    assert fetch_repo_context(c, "r", "main").pypy is True
