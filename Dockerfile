# Web UI image (Render free web service). All secrets come from the host's env vars:
# GITHUB_TOKEN, GROQ_API_KEY, APP_PASSWORD, APP_SECRET, DATABASE_URL. Nothing is baked in.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HOST=0.0.0.0 \
    PORT=8000 \
    COOKIE_SECURE=1 \
    FORWARDED_ALLOW_IPS=*

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY triage ./triage
COPY evidence ./evidence
COPY docs ./docs

RUN useradd --create-home --uid 10001 app && chown -R app /app
USER app

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('PORT', '8000'), timeout=4)"

# --host/--port default to $HOST/$PORT (Render sets PORT)
CMD ["python", "-m", "triage", "web"]
