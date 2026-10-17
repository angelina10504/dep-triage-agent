# Dependency Advisory Triage Agent

Ziro Agentic AI Hackathon 2026 — Developer & Enterprise AI.

Checks a repo's dependencies against public security advisories (OSV), opens upgrade PRs after human approval, and tracks each PR's CI result.

## Status

- [x] Step 2 — Scanner core: parse `requirements.txt`, fetch OSV advisories, deterministic version-range matching with evidence
- [ ] Step 3 — Upgrade PR action (human approval, no duplicate PRs on retry)
- [ ] Step 4 — CI watcher (passing / failing / pending; merged is not deployed)
- [ ] Step 5 — LangGraph orchestration + LLM explanations
- [ ] Step 6 — SQLite store + web triage table
- [ ] Step 7 — Deploy + run the 4 official test cases

## Run

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -q                                    # offline unit tests
python -m triage path/to/requirements.txt    # live scan against osv.dev
python -m triage path/to/requirements.txt --json   # full evidence
```

## Decision rules (no LLM)

| Rule | Outcome |
|---|---|
| Advisory's package name (PEP 503 normalised) **and** ecosystem match the dependency | considered |
| Name matches but ecosystem differs, or advisory withdrawn | `excluded` (TC2) |
| Installed version inside an OSV `introduced`/`fixed`/`last_affected` interval | `vulnerable` (TC1) |
| Version not pinned with `==`, invalid, or no comparable range | `uncertain` |
| Upgrade target | highest `fixed` across matched advisories, re-checked against every advisory |
