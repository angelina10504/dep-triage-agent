"""Step 03 - Find the information: fetch advisories from the public OSV database.

We deliberately query by package name only (no version). OSV can do the version
matching for us, but the brief asks the agent to match exact package and version
ranges itself and keep the evidence, so matching happens in matcher.py.

Transient failures (timeouts, connection errors, HTTP 5xx/429) are retried with
backoff. If OSV still can't be reached, AdvisorySourceError is raised and the
scanner marks that dependency "uncertain" - no advisories is never read as "safe".
"""
from __future__ import annotations

import time
from datetime import datetime, timezone

import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
SOURCE = "osv.dev"
BACKOFF = (1, 2, 4)              # seconds to wait before retry 1, 2, 3

_session = requests.Session()
_sleep = time.sleep


class AdvisorySourceError(RuntimeError):
    """OSV could not be queried; error_type is a short label such as 'Timeout' or 'HTTP 503'."""

    def __init__(self, error_type: str, detail: str = ""):
        super().__init__(f"{error_type}: {detail}" if detail else error_type)
        self.error_type = error_type


def advisory_url(advisory_id: str) -> str:
    return f"https://osv.dev/vulnerability/{advisory_id}"


def _post(payload: dict, timeout: int) -> dict:
    last: AdvisorySourceError | None = None
    for attempt in range(len(BACKOFF) + 1):
        if attempt:
            _sleep(BACKOFF[attempt - 1])
        try:
            resp = _session.post(OSV_QUERY_URL, json=payload, timeout=timeout)
        except (requests.Timeout, requests.ConnectionError) as e:
            last = AdvisorySourceError(type(e).__name__, str(e)[:200])
            continue
        if resp.status_code == 429 or resp.status_code >= 500:
            last = AdvisorySourceError(f"HTTP {resp.status_code}")
            continue
        if resp.status_code != 200:                     # other 4xx: retrying won't help
            raise AdvisorySourceError(f"HTTP {resp.status_code}", resp.text[:200])
        try:
            return resp.json()
        except ValueError as e:
            raise AdvisorySourceError("InvalidJSON", str(e)[:200]) from e
    raise last


def fetch_advisories(name: str, ecosystem: str = "PyPI", timeout: int = 20) -> tuple[list[dict], str]:
    """Return (advisories, retrieved_at_iso) for one package. Raises AdvisorySourceError."""
    payload: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    vulns: list[dict] = []
    while True:
        data = _post(payload, timeout)
        vulns.extend(data.get("vulns", []))
        token = data.get("next_page_token")
        if not token:
            break
        payload["page_token"] = token
    retrieved_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return vulns, retrieved_at
