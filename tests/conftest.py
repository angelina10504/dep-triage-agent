"""Shared fixtures. `db_target` gives each test a fresh database: a SQLite file, and -
when a Postgres is available - a fresh Postgres database too, so the deployed
(Neon) code path is tested with the same tests.

Postgres comes from TEST_DATABASE_URL (any server you can CREATE DATABASE on) or,
for local runs, the `pgserver` package (a real Postgres binary in a temp dir).
"""
import os
import uuid

import pytest


@pytest.fixture(scope="session")
def pg_admin_url(tmp_path_factory):
    url = os.environ.get("TEST_DATABASE_URL")
    if url:
        return url
    try:
        import pgserver
    except ImportError:
        return None
    srv = pgserver.get_server(str(tmp_path_factory.mktemp("pg")), cleanup_mode="stop")
    return srv.get_uri()


def _with_db(url: str, name: str) -> str:
    base, sep, query = url.partition("?")
    return base.rsplit("/", 1)[0] + "/" + name + (sep + query if sep else "")


@pytest.fixture(params=["sqlite", "postgres"])
def db_target(request, tmp_path, pg_admin_url):
    if request.param == "sqlite":
        yield str(tmp_path / "t.db")
        return
    if not pg_admin_url:
        pytest.skip("no Postgres (set TEST_DATABASE_URL or pip install pgserver)")
    import psycopg
    name = f"t_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(pg_admin_url, autocommit=True) as c:
        c.execute(f"CREATE DATABASE {name}")
    yield _with_db(pg_admin_url, name)
    with psycopg.connect(pg_admin_url, autocommit=True) as c:
        c.execute(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)")
