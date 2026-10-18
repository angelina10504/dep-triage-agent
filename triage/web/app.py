"""Step 6 web UI: FastAPI + Jinja + HTMX (no build step).

Viewing is public. Anything that acts (Run scan, Approve/Reject, Refresh CI) needs a
login (APP_PASSWORD, session cookie) and a CSRF token. The repo is fixed by config, so
a visitor can never point the server's GitHub token at another repo.

Approve is only accepted after the proposal's risk panel was served to this session
(server-side check, not just a disabled button); the decision is stored with who/when.
"""
from __future__ import annotations

import hmac
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from ..graph import Runtime
from ..risk import render_risk
from .jobs import refresh_job, resume_job, scan_job
from .runs import Busy, JobRunner, RunStore, now
from .views import build_rows, status_class, test_cases

HERE = Path(__file__).parent


@dataclass
class WebConfig:
    db: str = "triage.db"
    checkpoints: str = "checkpoints.db"
    repo: str = "angelina10504/dep-triage-demo"
    path: str = "requirements.txt"
    password: str | None = None            # APP_PASSWORD; unset = nobody can act
    secret: str | None = None              # APP_SECRET signs the session cookie
    cookie_secure: bool = False            # COOKIE_SECURE=1 behind HTTPS
    evidence_dir: str = "evidence"
    make_runtime: Callable[[], Runtime] | None = None
    background: bool = True
    login_attempts: int = 5                # failed logins per IP per window
    login_window: float = 300

    @classmethod
    def from_env(cls, **kw) -> "WebConfig":
        e = os.environ.get
        return cls(db=e("TRIAGE_DB", "triage.db"), checkpoints=e("TRIAGE_CHECKPOINTS", "checkpoints.db"),
                   repo=e("TRIAGE_REPO", "angelina10504/dep-triage-demo"), path=e("TRIAGE_PATH", "requirements.txt"),
                   password=e("APP_PASSWORD") or None, secret=e("APP_SECRET") or None,
                   cookie_secure=e("COOKIE_SECURE", "") in ("1", "true", "yes"), **kw)


def default_runtime(db: str) -> Callable[[], Runtime]:
    def make() -> Runtime:
        from .. import osv
        from ..github_pr import GitHubClient
        from ..llm import LLMCache
        from ..release_notes import fetch_release_notes
        from ..store import ActionStore
        token = os.environ.get("GITHUB_TOKEN")
        return Runtime(store=ActionStore(db), cache=LLMCache(db),
                       github=(lambda: GitHubClient(token)) if token else None, fetch=osv.fetch_advisories,
                       notes=lambda n, c, t: fetch_release_notes(n, c, t, github_token=token),
                       wait=True, timeout=600, interval=15)
    return make


def safe_url(url: str | None) -> str:
    """Only http(s) links reach an href; anything else (javascript:, data:...) becomes '#'."""
    return url if url and urlparse(url).scheme in ("http", "https") else "#"


def create_app(cfg: WebConfig | None = None) -> FastAPI:
    cfg = cfg or WebConfig.from_env()
    make_runtime = cfg.make_runtime or default_runtime(cfg.db)
    store = RunStore(cfg.db)
    store.mark_stale()
    runner = JobRunner(store, background=cfg.background)
    failed_logins: dict[str, list[float]] = {}

    app = FastAPI(title="Dependency Advisory Triage", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SessionMiddleware, secret_key=cfg.secret or secrets.token_hex(32),
                       session_cookie="triage_session", max_age=8 * 3600, same_site="lax",
                       https_only=cfg.cookie_secure)
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    tpl = Jinja2Templates(directory=HERE / "templates")
    tpl.env.filters["safe_url"] = safe_url
    tpl.env.globals["status_class"] = status_class
    tpl.env.globals["render_risk"] = render_risk

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.update({
            "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; "
                                       "script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin"})
        return resp

    # ---------- session helpers ----------
    def csrf(request: Request) -> str:
        if "csrf" not in request.session:
            request.session["csrf"] = secrets.token_urlsafe(32)
        return request.session["csrf"]

    def user(request: Request) -> str | None:
        return request.session.get("user")

    def require(request: Request, token: str, header: str | None) -> str:
        """Login first (403 without it), then a matching CSRF token (403 otherwise)."""
        who = user(request)
        if not who or not cfg.password:
            raise HTTPException(403, "Log in with the app password to do this.")
        expected = request.session.get("csrf", "")
        given = token or header or ""
        if not expected or not hmac.compare_digest(expected, given):
            raise HTTPException(403, "Invalid or missing CSRF token. Reload the page and try again.")
        return who

    def flash(request: Request, msg: str) -> None:
        request.session["flash"] = msg

    def page(request: Request, name: str, **ctx) -> HTMLResponse:
        return tpl.TemplateResponse(request, name, {
            "user": user(request), "csrf": csrf(request), "repo": cfg.repo, "path": cfg.path,
            "can_login": bool(cfg.password), "busy": runner.busy, "awaiting": store.awaiting(),
            "flash": request.session.pop("flash", None), **ctx})

    def evidence_files() -> list[str]:
        d = Path(cfg.evidence_dir)
        return sorted(p.name for p in d.glob("*.txt")) if d.is_dir() else []

    # ---------- public pages ----------
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        rows, latest = build_rows(cfg.db, cfg.repo)
        return page(request, "index.html", rows=rows, latest=latest, jobs=store.jobs(5))

    @app.get("/test-cases", response_class=HTMLResponse)
    def tcs(request: Request):
        rows, latest = build_rows(cfg.db, cfg.repo)
        return page(request, "test_cases.html", cases=test_cases(rows, latest, evidence_files()), latest=latest)

    @app.get("/evidence/{name}")
    def evidence(name: str):
        if name not in evidence_files():                  # whitelist: no path traversal
            raise HTTPException(404)
        return FileResponse(Path(cfg.evidence_dir) / name, media_type="text/plain; charset=utf-8")

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_page(request: Request, job_id: int):
        job = store.job(job_id) or _404()
        return page(request, "job.html", job=job, run=store.run(job["thread_id"]) if job["thread_id"] else None)

    @app.get("/jobs/{job_id}/progress", response_class=HTMLResponse)
    def job_progress(request: Request, job_id: int):
        job = store.job(job_id) or _404()
        return tpl.TemplateResponse(request, "_progress.html", {
            "job": job, "run": store.run(job["thread_id"]) if job["thread_id"] else None})

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    # ---------- login ----------
    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        return page(request, "login.html", error=None)

    @app.post("/login")
    def login(request: Request, name: str = Form(""), password: str = Form(""), csrf_token: str = Form("")):
        ip = request.client.host if request.client else "?"
        t = time.monotonic()
        recent = [x for x in failed_logins.get(ip, []) if t - x < cfg.login_window]
        failed_logins[ip] = recent
        if len(recent) >= cfg.login_attempts:
            raise HTTPException(429, "Too many failed logins. Try again in a few minutes.")
        if not hmac.compare_digest(request.session.get("csrf", ""), csrf_token or ""):
            raise HTTPException(403, "Invalid or missing CSRF token. Reload the page and try again.")
        name = " ".join(name.split())[:40]
        ok = bool(cfg.password) and hmac.compare_digest(password.encode(), cfg.password.encode())
        if not ok or not name:
            if not ok:
                failed_logins[ip].append(t)
            return tpl.TemplateResponse(request, "login.html", {
                "user": None, "csrf": csrf(request), "repo": cfg.repo, "can_login": bool(cfg.password),
                "busy": runner.busy, "awaiting": [], "flash": None,
                "error": "Enter your name." if ok else "Wrong password."}, status_code=401)
        request.session.clear()                              # new session id on privilege change
        request.session.update(user=name, csrf=secrets.token_urlsafe(32), risk_seen={})
        flash(request, f"Logged in as {name}.")
        return RedirectResponse("/", status_code=303)

    @app.post("/logout")
    def logout(request: Request, csrf_token: str = Form("")):
        if hmac.compare_digest(request.session.get("csrf", ""), csrf_token or ""):
            request.session.clear()
        return RedirectResponse("/", status_code=303)

    # ---------- actions (login + CSRF) ----------
    def submit(request: Request, kind: str, thread: str | None, who: str, fn) -> Response:
        try:
            job_id = runner.submit(kind, thread, who, fn)
        except Busy as e:
            flash(request, str(e))
            return RedirectResponse("/", status_code=303)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/scan")
    def run_scan(request: Request, csrf_token: str = Form(""), dry_run: str = Form(""),
                 x_csrf_token: str | None = Header(None)):
        who = require(request, csrf_token, x_csrf_token)
        if runner.busy:
            flash(request, "Another job is still running; wait for it to finish.")
            return RedirectResponse("/", status_code=303)
        thread = f"web-{datetime.now(timezone.utc):%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"
        store.new_run(thread, cfg.repo, cfg.path, bool(dry_run), who)
        return submit(request, "scan", thread, who,
                      scan_job(make_runtime, cfg.checkpoints, store, thread, cfg.repo, cfg.path, bool(dry_run)))

    @app.post("/refresh")
    def refresh(request: Request, csrf_token: str = Form(""), x_csrf_token: str | None = Header(None)):
        who = require(request, csrf_token, x_csrf_token)
        return submit(request, "refresh", None, who, refresh_job(make_runtime, store, cfg.repo))

    # ---------- approvals ----------
    def awaiting_run(thread: str) -> dict:
        run = store.run(thread) or _404()
        if run["status"] != "awaiting_approval" or not run["interrupt"]:
            raise HTTPException(409, f"Run {thread} is not waiting for approval (status: {run['status']}).")
        return run

    def proposal(run: dict, idx: int) -> dict:
        props = run["interrupt"]["proposals"]
        if not 0 <= idx < len(props):
            raise HTTPException(404, "No such proposal.")
        return props[idx]

    def details(run: dict, prop: dict) -> dict:
        snap = run["snapshot"] or {}
        dep = prop.get("dependency_id")
        return {"risk": (snap.get("risks") or {}).get(dep),
                "matches": [m for m in snap.get("matches") or [] if m["dependency_id"] == dep and m["decision"] == "vulnerable"]}

    @app.get("/approvals/{thread}", response_class=HTMLResponse)
    def approval_page(request: Request, thread: str):
        run = store.run(thread) or _404()
        decided = {d["key"]: d for d in store.decisions(thread)}
        props = (run["interrupt"] or {}).get("proposals", [])
        items = [{"idx": i, "p": p, "d": decided.get(p["key"]), **details(run, p)} for i, p in enumerate(props)]
        return page(request, "approval.html", run=run, items=items, decided=decided,
                    all_decided=bool(props) and all(p["key"] in decided for p in props))

    @app.get("/approvals/{thread}/{idx}/risk", response_class=HTMLResponse)
    def risk_panel(request: Request, thread: str, idx: int):
        run = store.run(thread) or _404()
        if not run["interrupt"]:
            raise HTTPException(409, "Nothing to approve in this run.")
        prop = proposal(run, idx)
        seen = dict(request.session.get("risk_seen") or {})
        seen[f"{thread}|{idx}"] = now()                      # Approve accepted only after this
        request.session["risk_seen"] = seen
        decided = {d["key"]: d for d in store.decisions(thread)}
        return tpl.TemplateResponse(request, "_risk.html", {
            "run": run, "idx": idx, "p": prop, "d": decided.get(prop["key"]), "user": user(request),
            "csrf": csrf(request), "can_act": run["status"] == "awaiting_approval",
            "hx": request.headers.get("HX-Request") == "true", **details(run, prop)})

    @app.post("/approvals/{thread}/{idx}/{decision}")
    def decide(request: Request, thread: str, idx: int, decision: str, csrf_token: str = Form(""),
               x_csrf_token: str | None = Header(None)):
        who = require(request, csrf_token, x_csrf_token)
        if decision not in ("approve", "reject"):
            raise HTTPException(404)
        run = awaiting_run(thread)
        prop = proposal(run, idx)
        shown = (request.session.get("risk_seen") or {}).get(f"{thread}|{idx}")
        if decision == "approve" and not shown:
            raise HTTPException(409, "Open the risk panel for this proposal before approving it.")
        status = "approved" if decision == "approve" else "rejected"
        if not store.decide(thread, prop["key"], prop["package"], status, who, shown):
            flash(request, f"{prop['package']} was already decided; the first decision stands.")
        else:
            flash(request, f"{prop['package']}: {status} by {who}.")
        return maybe_resume(request, thread, who)

    @app.post("/approvals/{thread}/resume")
    def resume(request: Request, thread: str, csrf_token: str = Form(""), x_csrf_token: str | None = Header(None)):
        who = require(request, csrf_token, x_csrf_token)
        return maybe_resume(request, thread, who)

    def maybe_resume(request: Request, thread: str, who: str) -> Response:
        run = awaiting_run(thread)
        decided = {d["key"]: d for d in store.decisions(thread)}
        props = run["interrupt"]["proposals"]
        if not all(p["key"] in decided for p in props):
            return RedirectResponse(f"/approvals/{thread}", status_code=303)
        answers = {p["key"]: decided[p["key"]]["decision"] == "approved" for p in props}
        approvers = sorted({d["decided_by"] for d in decided.values() if d["decision"] == "approved"})
        approved_by = f"{', '.join(approvers) or who} (web)"
        try:
            job_id = runner.submit("resume", thread, who,
                                   resume_job(make_runtime, cfg.checkpoints, store, thread, run["repo"], answers, approved_by))
        except Busy as e:
            flash(request, f"All proposals decided, but {e}. Use 'Resume run' when it is done.")
            return RedirectResponse(f"/approvals/{thread}", status_code=303)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    return app


def _404():
    raise HTTPException(404, "Not found.")
