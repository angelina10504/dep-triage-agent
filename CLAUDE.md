# CLAUDE.md — Dependency Advisory Triage Agent
Ziro Agentic AI Hackathon 2026, Developer & Enterprise AI. Solo entry. Build & Submit opens 20 Oct 2026 11:00 IST.
Brief: a team checks its dependencies against security advisories and opens upgrade PRs.
Workflow: 01 collect dependency file + repo -> 02 match exact package + version ranges -> 03 fetch advisory databases -> 04 open upgrade PR (HUMAN APPROVAL REQUIRED).
Output: triage table with package, advisory, PR and CI status. Verify: wait for the CI result on the upgrade PR.
Official test cases (must demo each with input, expected, actual, evidence):
- TC1 installed version inside advisory range -> upgrade PR opened
- TC2 unrelated package with the same name -> excluded
- TC3 tests fail after upgrade -> PR marked failing, NOT "fixed"
- TC4 PR merged -> reported "merged", NOT "deployed"
Rubric: problem fit 20, agentic capability 25, technical 20, innovation 15, UX 10, presentation 10. Deployed agent + source evidence + presentation + test cases are mandatory.

## Repos
- This repo: ~/dep-triage-agent (Python 3.12 via uv, venv at .venv)
- Demo target: ~/dep-triage-demo -> github.com/angelina10504/dep-triage-demo (public). requests==2.28.0 (upgrade passes CI = TC1), Werkzeug==2.2.2 (3.x removes werkzeug.urls.url_quote, CI fails = TC3), MarkupSafe==2.1.5. CI: GitHub Actions, Python 3.12, pytest.

## Rules
- Version matching is deterministic code (triage/matcher.py), never an LLM. LLM only for explanations / PR text / orchestration later.
- Every decision keeps evidence: advisory ID, URL, range, fixed version, source, retrieved_at. Missing evidence -> "uncertain", never a guess.
- Any irreversible action (opening a PR) needs explicit human approval first. Store approved actions; never execute twice on retry.
- CI verification is separate from the action. Failed/pending stays visible. Merged != deployed.
- Use mock/synthetic data for anything sensitive. Never commit tokens; read GITHUB_TOKEN from .env.
- Do NOT add Claude as co-author or any Claude attribution in commits or PRs.
- Explain changes to me in short plain language; tell me the exact next thing to do. Run pytest after every change.

## Status
- [x] Step 2 scanner core: parser.py, osv.py (OSV query by name, no version), matcher.py, scanner.py, CLI `python -m triage <requirements.txt> [--json]`, 17 unit tests
- [x] Step 3 upgrade PR action (triage/github_pr.py, triage/store.py): y/N approval gate, idempotent via SQLite + existing PR/branch checks. Verified live: PR #1 requests 2.28.0->2.33.0 CI 2/2 green (TC1), PR #2 Werkzeug 2.2.2->3.1.9 CI 1/2 red (TC3)
- [x] Step 4 CI watcher (triage/ci_watch.py, `python -m triage status --repo R [--wait]`): check runs + commit statuses, append-only ci_observations history. Verified live: PR #1 passing (TC1), PR #2 "PR failing, NOT fixed" (TC3). TC4 (merge) not yet demoed
- [x] Step 5 LangGraph + LLM. triage/graph.py: collect -> fetch_advisories -> match -> plan -> assess_upgrade_risk -> human_approval (interrupt, SQLite checkpointer checkpoints.db, resume by thread id) -> open_pr -> watch_ci -> diagnose_failure (only if failing) -> report; nodes wrap existing modules. CLI: `run`, `resume --thread`, `--open-prs` = run, `graph` -> docs/graph.md. LLM (triage/llm.py ask_json): Groq openai/gpt-oss-120b strict JSON, LLM_PROVIDER interface, SQLite cache (stale hits re-validated), 429/5xx retry, banned wording fixed/deployed/resolved/safe now -> 1 retry -> "LLM unavailable". release_notes.py (PyPI project_urls -> GitHub releases, changelog fallback, line-anchored URLs), risk.py (uncited changes dropped; deterministic deprecated->removed pairs always included), diagnose.py (failed Actions job log window, evidence must be in log, outcome stays "PR failing, NOT fixed"; suggested_next_step must be a code fix on the target version: anything that pins/downgrades/stays below the target is rejected in code, 1 retry). Live evidence: evidence/step5_*.txt
- [ ] Step 6 SQLite store + simple web triage table with approve buttons
- [ ] Step 7 deploy (free host) + 4 labelled TC runs + presentation
