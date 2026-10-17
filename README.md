# Dependency Advisory Triage Agent

Ziro Agentic AI Hackathon 2026 — Developer & Enterprise AI.

Checks a repo's dependencies against public security advisories (OSV), opens upgrade PRs after human approval, and tracks each PR's CI result.

## Status

- [x] Step 2 — Scanner core: parse `requirements.txt`, fetch OSV advisories, deterministic version-range matching with evidence
- [x] Step 3 — Upgrade PR action (human approval, no duplicate PRs on retry)
- [x] Step 4 — CI watcher (passing / failing / pending; merged is not deployed)
- [x] Step 5 — LangGraph orchestration + LLM explanations, upgrade risk, CI failure diagnosis
- [ ] Step 6 — SQLite store + web triage table
- [ ] Step 7 — Deploy + run the 4 official test cases

## Run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q                                    # offline unit tests
python -m triage path/to/requirements.txt    # live scan against osv.dev
python -m triage path/to/requirements.txt --json   # full evidence
# propose upgrade PRs; each one asks y/N, approvals are stored in triage.db
python -m triage path/to/requirements.txt --repo owner/name --open-prs
# PR + CI triage table; --wait polls until no CI is pending
python -m triage status --repo owner/name --wait
# full agent run as a LangGraph graph: pauses for y/N, resumable (see docs/graph.md)
python -m triage run path/to/requirements.txt --repo owner/name
python -m triage resume --thread <id>
# add plain-language LLM explanations (Groq by default, see .env.example); never changes a decision
python -m triage path/to/requirements.txt --explain
```

## Decision rules (no LLM)

| Rule | Outcome |
|---|---|
| Advisory's package name (PEP 503 normalised) **and** ecosystem match the dependency | considered |
| Name matches but ecosystem differs, or advisory withdrawn | `excluded` (TC2) |
| Installed version inside an OSV `introduced`/`fixed`/`last_affected` interval | `vulnerable` (TC1) |
| Version not pinned with `==`, invalid, or no comparable range | `uncertain` |
| Upgrade target | highest `fixed` across matched advisories, re-checked against every advisory |
