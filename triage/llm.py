"""LLM layer: plain-language explanations only. Never decides versions, matches or PRs.

The deterministic scan/plan/PR path does not import this module. Explanations are
an optional add-on: if the provider is missing, rate-limited or returns junk, the
result is recorded as "LLM unavailable: <reason>" and everything else carries on.

Provider is chosen by LLM_PROVIDER (default "groq"; "none" disables). To add
Gemini later, implement LLMProvider and register it in PROVIDERS.
Results are cached in SQLite by a hash of (provider, model, prompt version, input).
"""
from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Protocol

import requests

PROMPT_VERSION = "v2"
# Claims only CI + a human merge (and a deployment we never observe) could justify.
BANNED = re.compile(r"\b(fixed|deployed|resolved)\b|\bsafe now\b", re.IGNORECASE)
NO_CLAIMS = ("Never use the words 'fixed', 'deployed', 'resolved' or 'safe now'. To say the upgrade "
             "clears an advisory, write: the target version is outside these advisories' affected ranges.")
BACKOFF = (1, 2, 4)
MAX_RETRY_AFTER = 30          # never sleep longer than this on one Retry-After


_deadline: contextvars.ContextVar[float | None] = contextvars.ContextVar("llm_deadline", default=None)


@contextlib.contextmanager
def llm_budget(seconds: float | None):
    """Cap the total LLM time inside the block (e.g. one graph node). Past the cap, calls fail
    fast with "time budget exceeded" and callers fall back to their deterministic result."""
    token = _deadline.set(time.monotonic() + seconds if seconds else None)
    try:
        yield
    finally:
        _deadline.reset(token)


def _remaining() -> float | None:
    d = _deadline.get()
    return None if d is None else d - time.monotonic()


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
                 timeout: int = 30, extra: dict | None = None):
        self.name, self.base_url, self.model = name, base_url.rstrip("/"), model
        self.extra = extra or {}            # provider/model-specific request fields
        self.s = session or requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
        self.sleep, self.timeout = sleep, timeout

    def _post(self, payload: dict) -> dict:
        reason = "unknown"
        for attempt in range(len(BACKOFF) + 1):
            left = _remaining()
            if left is not None and left < 2:
                raise LLMError("time budget exceeded" + (f" (after {reason})" if attempt else ""))
            try:
                r = self.s.post(f"{self.base_url}/chat/completions", json=payload,
                                timeout=self.timeout if left is None else max(1.0, min(self.timeout, left)))
            except (requests.Timeout, requests.ConnectionError) as e:
                reason = type(e).__name__
            else:
                if r.status_code == 200:
                    return r.json()
                reason = f"HTTP {r.status_code}"
                if r.status_code == 400 and "json_validate_failed" in r.text:
                    # The model's output did not fit the schema (often: ran out of tokens).
                    raise LLMError("InvalidOutput (json_validate_failed)")
                if r.status_code != 429 and r.status_code < 500:
                    raise LLMError(reason)          # 400/401/403...: retrying won't help
                if r.status_code == 429 and attempt < len(BACKOFF):
                    try:
                        wait = float(r.headers.get("retry-after", ""))
                    except ValueError:
                        wait = BACKOFF[attempt]
                    self._sleep(min(max(wait, BACKOFF[attempt]), MAX_RETRY_AFTER), reason)
                    continue
            if attempt < len(BACKOFF):
                self._sleep(BACKOFF[attempt], reason)
        raise LLMError(reason)

    def _sleep(self, seconds: float, reason: str) -> None:
        left = _remaining()
        if left is not None and seconds >= left:
            raise LLMError(f"time budget exceeded (after {reason})")
        self.sleep(seconds)

    def complete_json(self, system: str, user: str, schema: dict, schema_name: str) -> dict:
        data = self._post({
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {"type": "json_schema",
                                "json_schema": {"name": schema_name, "strict": True, "schema": schema}},
            "temperature": 0.2,
            "max_completion_tokens": 4096,      # reasoning models spend part of this before answering
            **self.extra,
        })
        try:
            out = json.loads(data["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError, ValueError):
            raise LLMError("InvalidOutput") from None
        if not isinstance(out, dict):
            raise LLMError("InvalidOutput")
        missing = []
        for k in schema["required"]:
            typ = schema["properties"][k].get("type")
            v = out.get(k)
            if (typ == "array" and not isinstance(v, list)) or \
               (typ == "string" and (not isinstance(v, str) or not v.strip())):
                missing.append(k)
        if missing:
            raise LLMError(f"InvalidOutput (missing {', '.join(missing)})")
        return out


def _groq() -> LLMProvider:
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        raise LLMError("GROQ_API_KEY not set")
    model = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
    extra = {"reasoning_effort": "low"} if model.startswith("openai/gpt-oss") else {}
    return OpenAICompatibleProvider("groq", "https://api.groq.com/openai/v1", key, model, extra=extra)


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
        from .db import connect
        self.db = connect(path)                      # SQLite file or postgres:// URL
        self.db.script("""
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
        self.db.execute("INSERT INTO llm_cache VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (key) DO UPDATE SET"
                        " provider = excluded.provider, model = excluded.model, prompt_version = excluded.prompt_version,"
                        " response = excluded.response, created_at = excluded.created_at",
                        (key, provider, model, PROMPT_VERSION, json.dumps(response), _now()))
        self.db.commit()

    def log(self, key: str, subject: str, status: str, detail: str | None = None) -> None:
        self.db.execute("INSERT INTO llm_events (key, subject, status, detail, at) VALUES (?, ?, ?, ?, ?)",
                        (key, subject, status, detail, _now()))
        self.db.commit()

    def events(self) -> list[tuple]:
        return [tuple(r.values()) for r in self.db.execute("SELECT subject, status, detail FROM llm_events ORDER BY id")]


@dataclass
class LLMResult:
    status: str              # ok | cached | unavailable | disabled
    data: dict | None
    detail: str              # provider/model, or why unavailable

    @property
    def available(self) -> bool:
        return self.status in ("ok", "cached")


def banned_word(out: dict, fields: tuple[str, ...]) -> str | None:
    for f in fields:
        if isinstance(out.get(f), str) and (m := BANNED.search(out[f])):
            return m.group(0)
    return None


def ask_json(llm: LLMProvider | None | str, cache: "LLMCache", subject: str, system: str, user: str,
             schema: dict, schema_name: str, claim_fields: tuple[str, ...],
             validate: Callable[[dict], dict] | None = None) -> LLMResult:
    """One cached, validated LLM call. Never raises.

    claim_fields are checked for BANNED wording; validate() may clean the output or raise
    LLMError. Either problem gets ONE retry with a correction note, then "unavailable".
    provider "env" means: read LLM_PROVIDER.
    """
    try:
        llm = get_provider() if llm == "env" else llm
    except LLMError as e:
        cache.log("-", subject, "unavailable", e.reason)
        return LLMResult("unavailable", None, e.reason)
    if llm is None:
        return LLMResult("disabled", None, "LLM disabled")
    system = f"{system}\n{NO_CLAIMS}"
    key = cache.key(llm.name, llm.model, system, user, schema)
    if (hit := cache.get(key)) is not None:
        try:     # the rules may be newer than the cached answer: re-check, else treat as a miss
            hit = validate(hit) if validate else hit
            stale = banned_word(hit, claim_fields)
        except LLMError as e:
            stale = e.reason
        if not stale:
            cache.log(key, subject, "cached")
            return LLMResult("cached", hit, f"{llm.name}/{llm.model} (cached)")
        cache.log(key, subject, "cache_rejected", str(stale))
    problem = ""
    for attempt in range(2):
        prompt = system if not attempt else (
            f"{system}\nYour previous answer was rejected: {problem}. Answer again and correct that.")
        try:
            out = llm.complete_json(prompt, user, schema, schema_name)
            if validate:
                out = validate(out)
        except LLMError as e:
            if not e.reason.startswith("InvalidOutput (") or attempt:
                cache.log(key, subject, "unavailable", e.reason)
                return LLMResult("unavailable", None, e.reason)
            problem = e.reason
            continue
        except Exception as e:                  # never let the optional layer break the run
            cache.log(key, subject, "unavailable", type(e).__name__)
            return LLMResult("unavailable", None, type(e).__name__)
        word = banned_word(out, claim_fields)
        if word is None:
            cache.put(key, llm.name, llm.model, out)
            cache.log(key, subject, "ok")
            return LLMResult("ok", out, f"{llm.name}/{llm.model}")
        problem = f"InvalidOutput (banned wording '{word}')"
    cache.log(key, subject, "unavailable", problem)
    return LLMResult("unavailable", None, problem)
