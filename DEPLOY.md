# Deploying the web UI (free): Render + Neon

**What runs where**
- **Render** (free web service, Docker): runs `python -m triage web`, which serves the FastAPI app.
- **Neon** (free Postgres): holds all state, including PRs, CI history, stored scan runs, approvals, the LLM cache and the LangGraph checkpoints. Render's free disk is wiped on every restart and redeploy, so nothing is kept on it.
- **GitHub API**: the app reads `requirements.txt`, the CI workflow (to get the Python version) and the `.py` files from `TRIAGE_REPO` at its base branch. No checkout is needed.
- **UptimeRobot** (free): pings `/healthz` every 5 minutes so Render never sleeps. `/healthz` doesn't touch the database, so Neon can still sleep.

All secrets are Render environment variables. None of them are in git.

---

## Why this choice (free tiers checked 18 Oct 2026)

| Host | Free tier | Sleep / cold start | Persistent disk | Notes |
|---|---|---|---|---|
| **Render** | 750 instance-hours/month | sleeps after **15 min** idle; wake-up takes **~1 min** | no | No card needed. Builds the Dockerfile from GitHub. A pinger keeps it awake (31 days × 24 h = 744 h, under 750). |
| Koyeb | 1 instance, 512 MB, **0.1 vCPU** | sleeps after **1 h** idle; wakes in ~1–5 s | no (no volumes on the free instance) | Fastest wake-up, but very little CPU, and it may ask for a card to verify you. |
| Hugging Face Spaces | 2 vCPU, 16 GB | pauses after **48 h** idle; restarting is slow | no (persistent storage is paid) | Shows the app inside an iframe on huggingface.co, which clashes with this app's clickjacking and cookie protections. |
| Fly.io | none for new accounts (short trial) | – | volumes are paid | Not free. |

None of the free hosts has a persistent disk, so the state goes to **Neon free Postgres**: 0.5 GB per project and 100 compute-hours/month. It sleeps after 5 min idle and wakes in under a second on the next query.

Sources: [Render free tier](https://render.com/docs/free), [Render changelog](https://render.com/changelog/free-web-services-now-remain-active-while-receiving-websocket-messages), [Koyeb instances](https://www.koyeb.com/docs/reference/instances), [Koyeb scale to zero](https://www.koyeb.com/docs/run-and-scale/scale-to-zero), [HF Spaces overview](https://huggingface.co/docs/hub/spaces-overview), [HF Space runtime](https://huggingface.co/docs/huggingface_hub/en/package_reference/space_runtime.md), [Fly.io pricing (third-party summary)](https://temps.sh/blog/fly-io-pricing-2026), [Neon plans](https://neon.com/pricing), [Neon free-plan limits](https://neon.com/faqs/free-plan-limits-and-quotas).

---

## Steps

### 0. Before you start
- Your local tests pass: `.venv/bin/python -m pytest -q`
- The CLI dependencies are installed (they now include `psycopg`):
  `uv pip install --python .venv/bin/python -r requirements-dev.txt`

### 1. Neon: create the database (~3 min)
1. Sign up at https://neon.com (GitHub login is fine). Free plan, no card needed.
2. **Create project**: name `dep-triage`, Postgres 17, region **AWS Asia Pacific (Singapore)** (same region as Render below).
3. Dashboard → **Connect**. Turn **Connection pooling OFF** (use the direct connection) and copy the connection string. It looks like:
   `postgresql://neondb_owner:XXXX@ep-xxxx.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require`
4. Keep it private. This is your `DATABASE_URL`.

### 2. Copy your local history into Neon (~1 min)
This keeps PRs #1–#3, their CI history and the stored scan run, so TC1–TC4 show PASS from the first page load. It only adds rows; nothing in Neon is changed or deleted, and running it twice is safe.
```bash
cd ~/dep-triage-agent
.venv/bin/python -m triage db-copy triage.db 'postgresql://...your Neon URL...'
```
Expected output: `actions: 3 new of 3`, `ci_observations: N new of N`, `scan_runs: 1 new of 1`, …

### 3. GitHub: publish the repo (public) (~1 min)
`.env` and `*.db` are gitignored, and the history was checked for tokens on 18 Oct 2026. Before pushing, run `git status` and make sure no `.env` file is listed.
```bash
cd ~/dep-triage-agent
gh repo create angelina10504/dep-triage-agent --public --source . --remote origin --push
```

### 4. GitHub: a token for the server (~2 min)
Create a separate token for the deployed app, so you can revoke it on its own.
https://github.com/settings/personal-access-tokens/new → **Fine-grained token**
- Repository access: **Only select repositories → `angelina10504/dep-triage-demo`**
- Permissions: **Contents: Read and write**, **Pull requests: Read and write**, **Actions: Read**, **Commit statuses: Read** (Metadata: Read is added automatically)
- Expiry: after the hackathon judging ends

### 5. Render: deploy (~5 min, first build ~3–4 min)
1. Sign up at https://render.com with GitHub. No card is needed for the free plan.
2. **New → Blueprint** → pick `angelina10504/dep-triage-agent`. Render reads `render.yaml`: a free Docker web service `dep-triage` in Singapore with health check `/healthz`.
3. It asks for the secret values (`sync: false`):
   | Key | Value |
   |---|---|
   | `DATABASE_URL` | the Neon URL from step 1 |
   | `GITHUB_TOKEN` | the token from step 4 |
   | `GROQ_API_KEY` | your Groq key |
   | `APP_PASSWORD` | a strong password; you type it to Run scan / Approve / Refresh CI |

   `APP_SECRET` is generated by Render. `TRIAGE_REPO` is preset. `HOST=0.0.0.0`, `PORT`, `COOKIE_SECURE=1` and `FORWARDED_ALLOW_IPS` come from the Dockerfile.
4. **Apply**. Wait for **Live**. Your URL is `https://dep-triage.onrender.com` (Render adds a suffix if that name is taken; the dashboard shows the real URL).

*Without the Blueprint:* New → Web Service → the repo → Language **Docker**, Instance **Free**, Region **Singapore**, Advanced → Health Check Path `/healthz`, then add the 5 variables above, plus `APP_SECRET` (`python -c "import secrets; print(secrets.token_hex(32))"`) and `TRIAGE_REPO=angelina10504/dep-triage-demo`.

### 6. Keep it awake for the organizer (~2 min)
https://uptimerobot.com (free) → **New monitor** → HTTP(s) → URL `https://<your-app>.onrender.com/healthz` → interval **5 minutes**.
This uses ~744 of the 750 free hours, so keep it as the only free Render service running all month. Neon still sleeps, because `/healthz` never opens a database connection.

### 7. Check it works (~3 min)
1. `https://<your-app>.onrender.com/healthz` → `{"ok":true}`
2. `/` → the triage table: requests PR #3 (+1 earlier), Werkzeug PR #2 failing (red), "Showing stored run …"
3. `/test-cases` → TC1–TC4 all **PASS**
4. **Log in to act** → your name + `APP_PASSWORD` → tick **dry run** → **Run scan**. The progress lines should start with `collect: 4 dependencies from angelina10504/dep-triage-demo@main:requirements.txt (GitHub API)`.
5. **Refresh CI** → the Werkzeug row gets a diagnosis.
6. Restart test: Render dashboard → **Manual Deploy → Restart service**, then reload `/`. Everything is still there, because it's all in Neon.

Send the organizer the `/` and `/test-cases` links. Viewing needs no login.

---

## Operating notes
- **Secrets:** change one in Render → Environment, and Render restarts the service. If a token leaks, revoke it on GitHub or Groq first.
- **Logs:** Render dashboard → Logs. Failed jobs also show their error on `/jobs/<id>`.
- **Redeploys:** every push to `main` redeploys (`autoDeploy: true`). A run paused at approval survives, because its LangGraph checkpoint is in Neon. A job that was running during a restart is shown as `interrupted`; start it again.
- **Local CLI against the deployed state** (optional): `--db "$DATABASE_URL" --checkpoints "$DATABASE_URL"`.
- **Costs:** everything above is $0. If Render's 750 hours run out, the service is suspended until the next month. It doesn't start billing.
