"""Offline tests for release-note collection: repo discovery, releases vs changelog, citations."""
import json

from triage.release_notes import changelog_sections, fetch_release_notes, github_repo

CHANGES = """\
Version 3.0.1
-------------

-   Fix a typo in docs.

Version 3.0.0
-------------

Released 2023-09-30

-   Remove previously deprecated code. :pr:`2768`
-   ``generate_password_hash`` uses scrypt by default.
-   Add a profiler item.
-   Explicitly marked something,
    continued on a second line. Python
    2.6 no longer does that.

Version 2.3.0
-------------

-   Deprecate the ``werkzeug.urls`` module. Use ``urllib.parse`` instead.
-   Make things faster.

Version 2.2.3
-------------

-   Security fix only.

Version 2.2.2
-------------

-   Old stuff removed long ago.
"""

RELEASES = [
    {"tag_name": "3.1.0", "html_url": "https://github.com/pallets/werkzeug/releases/tag/3.1.0", "draft": False,
     "body": "Intro text.\n\n* Remove previously deprecated code. #2967\n* Drop support for Python 3.8."},
    {"tag_name": "3.0.0", "html_url": "https://github.com/pallets/werkzeug/releases/tag/3.0.0", "draft": False,
     "body": "Feature release.\n\n* Changes: https://werkzeug.palletsprojects.com/changes/#3-0-0\n"
             "* Milestone: https://github.com/pallets/werkzeug/milestone/21"},
    {"tag_name": "3.1.0rc1", "html_url": "https://x/rc", "draft": False, "body": "* Remove everything forever."},
    {"tag_name": "2.0.0", "html_url": "https://x/old", "draft": False, "body": "* Remove old stuff entirely."},
]


class Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = body if isinstance(body, str) else json.dumps(body)

    def json(self):
        return self._body


class FakeHttp:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, headers))
        key = f"{url}?ref={params['ref']}" if params and "ref" in params else url
        return self.routes.get(key, Resp(404, "not found"))


def world(changes=CHANGES, releases=RELEASES, project_urls=None):
    return FakeHttp({
        "https://pypi.org/pypi/werkzeug/json": Resp(200, {"info": {"project_urls": project_urls or {
            "Documentation": "https://werkzeug.palletsprojects.com/", "Source": "https://github.com/pallets/werkzeug/"}}}),
        "https://api.github.com/repos/pallets/werkzeug/releases": Resp(200, releases),
        "https://api.github.com/repos/pallets/werkzeug/contents/CHANGES.rst?ref=3.1.0": Resp(200, changes),
    })


def test_repo_found_from_project_urls():
    assert github_repo({"Docs": "https://x.io", "Source": "https://github.com/pallets/werkzeug/"}) == "pallets/werkzeug"
    assert github_repo({"Homepage": "https://github.com/psf/requests.git"}) == "psf/requests"
    assert github_repo({"Docs": "https://x.io"}, "https://gitlab.com/a/b") is None


def test_changelog_headings_ignore_indented_text():
    versions = [str(v) for v, _, _ in changelog_sections(CHANGES)]
    assert versions == ["3.0.1", "3.0.0", "2.3.0", "2.2.3", "2.2.2"]      # not "2.6"


def test_releases_used_when_substantive_changelog_when_only_links():
    http = world()
    n = fetch_release_notes("werkzeug", "2.2.2", "3.1.0", session=http)
    by = {(i.version, i.source) for i in n.items}
    assert ("3.1.0", "github_release") in by                    # real bullets in the release
    assert ("3.0.0", "changelog") in by                         # release was link-only -> changelog
    assert ("2.3.0", "changelog") in by
    assert not any(i.version in ("2.0.0", "2.2.2", "3.1.0rc1") for i in n.items)   # out of range / prerelease


def test_changelog_items_cite_the_exact_lines_at_the_target_tag():
    n = fetch_release_notes("werkzeug", "2.2.2", "3.1.0", session=world())
    removed = next(i for i in n.items if i.version == "3.0.0" and "previously deprecated" in i.text)
    assert removed.source_url == "https://github.com/pallets/werkzeug/blob/3.1.0/CHANGES.rst#L11"
    multi = next(i for i in n.items if "continued on a second line" in i.text)
    assert multi.source_url.endswith("#L14-L16")
    assert "https://api.github.com/repos/pallets/werkzeug/contents/CHANGES.rst?ref=3.1.0" in n.fetched_urls


def test_only_relevant_items_are_kept_feature_releases_first():
    n = fetch_release_notes("werkzeug", "2.2.2", "3.1.0", session=world())
    texts = [i.text for i in n.items]
    assert not any("profiler" in t or "faster" in t or "typo" in t for t in texts)
    assert any("``werkzeug.urls``" in t for t in texts) and n.skipped_irrelevant >= 3
    assert n.items[0].version == "3.0.0"                        # x.0.0 before x.y.0 before patches


def test_github_token_only_sent_to_the_github_api():
    http = world()
    fetch_release_notes("werkzeug", "2.2.2", "3.1.0", session=http, github_token="secret")
    for url, headers in http.calls:
        assert ("Authorization" in (headers or {})) == url.startswith("https://api.github.com/")
    raw = [h for u, h in http.calls if "/contents/" in u]
    assert raw and raw[0]["Accept"] == "application/vnd.github.raw"


def test_no_github_repo_means_no_release_notes_found():
    n = fetch_release_notes("werkzeug", "2.2.2", "3.1.0", session=world(project_urls={"Docs": "https://x.io"}))
    assert n.items == [] and n.note.startswith("no release notes found")


def test_nothing_in_range_means_no_release_notes_found():
    n = fetch_release_notes("werkzeug", "2.2.2", "3.1.0", session=world(changes="nothing here", releases=[]))
    assert n.items == [] and n.note == "no release notes found between 2.2.2 and 3.1.0"
