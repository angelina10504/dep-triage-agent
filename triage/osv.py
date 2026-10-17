"""Step 03 - Find the information: fetch advisories from the public OSV database.

We deliberately query by package name only (no version). OSV can do the version
matching for us, but the brief asks the agent to match exact package and version
ranges itself and keep the evidence, so matching happens in matcher.py.
"""
from __future__ import annotations

from datetime import datetime, timezone

import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
SOURCE = "osv.dev"


def advisory_url(advisory_id: str) -> str:
    return f"https://osv.dev/vulnerability/{advisory_id}"


def fetch_advisories(name: str, ecosystem: str = "PyPI", timeout: int = 20) -> tuple[list[dict], str]:
    """Return (advisories, retrieved_at_iso) for one package."""
    payload: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    vulns: list[dict] = []
    while True:
        resp = requests.post(OSV_QUERY_URL, json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        vulns.extend(data.get("vulns", []))
        token = data.get("next_page_token")
        if not token:
            break
        payload["page_token"] = token
    retrieved_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return vulns, retrieved_at
