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
- [ ] Step 4 CI watcher (pending/passing/failing; merged != deployed)
- [ ] Step 5 LangGraph orchestration + LLM explanations
- [ ] Step 6 SQLite store + simple web triage table with approve buttons
- [ ] Step 7 deploy (free host) + 4 labelled TC runs + presentation
