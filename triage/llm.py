"""LLM layer: plain-language explanations only. Never decides versions, matches or PRs.

The deterministic scan/plan/PR path does not import this module. Explanations are
an optional add-on: if the provider is missing, rate-limited or returns junk, the
result is recorded as "LLM unavailable: <reason>" and everything else carries on.

Provider is chosen by LLM_PROVIDER (default "groq"; "none" disables). To add
Gemini later, implement LLMProvider and register it in PROVIDERS.
Results are cached in SQLite by a hash of (provider, model, prompt version, input).
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol

import requests

PROMPT_VERSION = "explain-v1"
BACKOFF = (1, 2, 4)
MAX_RETRY_AFTER = 30          # never sleep longer than this on one Retry-After


class LLMError(RuntimeError):
    """The LLM could not give a usable answer; reason is a short label for the record."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class LLMProvider(Protocol):
    name: str
    model: str

    def complete_json(self, system: str, user: str, schema: dict, schema_name: str) -> dict: ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class OpenAICompatibleProvider:
    """Chat Completions with strict JSON-schema output (Groq speaks this API)."""

    def __init__(self, name: str, base_url: str, api_key: str, model: str,
                 session: requests.Session | None = None, sleep: Callable[[float], None] = time.sleep,
                 timeout: int = 30):
        self.name, self.base_url, self.model = name, base_url.rstrip("/"), model
        self.s = session or requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
        self.sleep, self.timeout = sleep, timeout

    def _post(self, payload: dict) -> dict:
        reason = "unknown"
        for attempt in range(len(BACKOFF) + 1):
            try:
                r = self.s.post(f"{self.base_url}/chat/completions", json=payload, timeout=self.timeout)
            except (requests.Timeout, requests.ConnectionError) as e:
                reason = type(e).__name__
            else:
                if r.status_code == 200:
                    return r.json()
                reason = f"HTTP {r.status_code}"
                if r.status_code != 429 and r.status_code < 500:
                    raise LLMError(reason)          # 400/401/403...: retrying won't help
                if r.status_code == 429 and attempt < len(BACKOFF):
                    try:
                        wait = float(r.headers.get("retry-after", ""))
                    except ValueError:
                        wait = BACKOFF[attempt]
                    self.sleep(min(max(wait, BACKOFF[attempt]), MAX_RETRY_AFTER))
                    continue
            if attempt < len(BACKOFF):
                self.sleep(BACKOFF[attempt])
        raise LLMError(reason)

    def complete_json(self, system: str, user: str, schema: dict, schema_name: str) -> dict:
        data = self._post({
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": schema_name, "strict": True, "schema": schema}},
            "temperature": 0.2,
            "max_completion_tokens": 1024,
        })
        try:
            out = json.loads(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError, ValueError):
            raise LLMError("InvalidOutput") from None
        missing = [k for k in schema["required"] if not isinstance(out.get(k), str) or not out[k].strip()]
        if missing:
            raise LLMError(f"InvalidOutput (missing {', '.join(missing)})")
        return out


def _groq() -> LLMProvider:
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        raise LLMError("GROQ_API_KEY not set")
    return OpenAICompatibleProvider("groq", "https://api.groq.com/openai/v1", key,
                                    os.environ.get("GROQ_MODEL", "openai/gpt-oss-20b"))


def _gemini() -> LLMProvider:
    raise LLMError("provider 'gemini' not implemented yet")


PROVIDERS: dict[str, Callable[[], LLMProvider]] = {"groq": _groq, "gemini": _gemini}


def get_provider() -> LLMProvider | None:
    """The configured provider, or None if LLM_PROVIDER=none. Raises LLMError if misconfigured."""
    name = os.environ.get("LLM_PROVIDER", "groq").strip().lower()
    if name in ("", "none", "off"):
        return None
    if name not in PROVIDERS:
        raise LLMError(f"unknown LLM_PROVIDER '{name}'")
    return PROVIDERS[name]()


class LLMCache:
    """Successful answers keyed by input hash; every call (hit, miss, failure) is logged."""

    def __init__(self, path: str = "triage.db"):
        self.db = sqlite3.connect(path)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS llm_cache (
                key TEXT PRIMARY KEY, provider TEXT NOT NULL, model TEXT NOT NULL,
                prompt_version TEXT NOT NULL, response TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS llm_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, subject TEXT NOT NULL,
                status TEXT NOT NULL, detail TEXT, at TEXT NOT NULL);
        """)

    @staticmethod
    def key(provider: str, model: str, system: str, user: str, schema: dict) -> str:
        blob = json.dumps({"p": provider, "m": model, "v": PROMPT_VERSION, "s": system, "u": user,
                           "schema": schema}, sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()

    def get(self, key: str) -> dict | None:
        row = self.db.execute("SELECT response FROM llm_cache WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key: str, provider: str, model: str, response: dict) -> None:
        self.db.execute("INSERT OR REPLACE INTO llm_cache VALUES (?, ?, ?, ?, ?, ?)",
                        (key, provider, model, PROMPT_VERSION, json.dumps(response), _now()))
        self.db.commit()

    def log(self, key: str, subject: str, status: str, detail: str | None = None) -> None:
        self.db.execute("INSERT INTO llm_events (key, subject, status, detail, at) VALUES (?, ?, ?, ?, ?)",
                        (key, subject, status, detail, _now()))
        self.db.commit()

    def events(self) -> list[tuple]:
        return self.db.execute("SELECT subject, status, detail FROM llm_events ORDER BY id").fetchall()
