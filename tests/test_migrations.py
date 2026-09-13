"""Schema drift is the failure mode that bites hardest on deploy.

A model gains a column, ``create_all`` silently does nothing to an existing
table, and the service starts fine until someone refreshes a token. These tests
pin the repair path.
"""

from __future__ import annotations

import sqlite3

from sqlalchemy import inspect, text

from gyra_user import migrate
from gyra_user.db import init_engine


def _legacy_database(path) -> str:
    """A database created by an older build: refresh_tokens has no client_id."""
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(64), fullname VARCHAR(128), email VARCHAR(255),
            email_verified BOOLEAN, avatar VARCHAR(512), password_hash VARCHAR(255),
            oauth_provider VARCHAR(32), oauth_id VARCHAR(128), unionid VARCHAR(128),
            role VARCHAR(32), is_active BOOLEAN, is_pending BOOLEAN,
            department_1 VARCHAR(128), department_2 VARCHAR(128),
            last_login_at DATETIME, last_login_ip VARCHAR(64), login_count INTEGER,
            gmt_create DATETIME, gmt_modify DATETIME);
        CREATE TABLE refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jti VARCHAR(64), user_id INTEGER, token_hash VARCHAR(128),
            family VARCHAR(64), expires_at DATETIME, revoked_at DATETIME,
            replaced_by VARCHAR(64), user_agent VARCHAR(255), ip VARCHAR(64),
            gmt_create DATETIME);
        """
    )
    conn.commit()
    conn.close()
    return f"sqlite:///{path}"


def test_ensure_schema_adds_missing_column(tmp_path):
    url = _legacy_database(tmp_path / "legacy.db")
    engine = init_engine(url, create_tables=False)

    changes = migrate.ensure_schema(engine)

    columns = {c["name"] for c in inspect(engine).get_columns("refresh_tokens")}
    assert "client_id" in columns
    assert any("refresh_tokens.client_id" in c for c in changes)


def test_ensure_schema_is_idempotent(tmp_path):
    url = _legacy_database(tmp_path / "legacy.db")
    engine = init_engine(url, create_tables=False)

    migrate.ensure_schema(engine)
    assert migrate.ensure_schema(engine) == []


def test_ensure_schema_creates_missing_tables(tmp_path):
    url = _legacy_database(tmp_path / "legacy.db")
    engine = init_engine(url, create_tables=False)

    migrate.ensure_schema(engine)

    tables = set(inspect(engine).get_table_names())
    # Tables added by the OIDC work must appear on an old database.
    assert {"oauth_clients", "oauth_authorization_codes", "oauth_consents"} <= tables


def test_run_upgrade_on_fresh_database(tmp_path):
    url = f"sqlite:///{tmp_path / 'fresh.db'}"
    init_engine(url, create_tables=False)

    changes, revision = migrate.run(url)

    assert revision  # stamped at a real revision, not empty
    assert migrate.current(url) == revision
    engine = init_engine(url, create_tables=False)
    tables = set(inspect(engine).get_table_names())
    assert "users" in tables and "oauth_clients" in tables
    assert any("stamped" in c for c in changes)


def test_run_upgrade_repairs_then_stamps(tmp_path):
    url = _legacy_database(tmp_path / "legacy.db")
    init_engine(url, create_tables=False)

    _changes, revision = migrate.run(url)

    assert revision
    engine = init_engine(url, create_tables=False)
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT version_num FROM alembic_version")).all()
    assert rows == [(revision,)]
    columns = {c["name"] for c in inspect(engine).get_columns("refresh_tokens")}
    assert "client_id" in columns


def test_run_upgrade_is_repeatable(tmp_path):
    url = f"sqlite:///{tmp_path / 'fresh.db'}"
    init_engine(url, create_tables=False)
    _changes, revision = migrate.run(url)

    changes, same = migrate.run(url)

    assert same == revision
    assert changes == []


def test_project_root_finds_alembic_ini():
    root = migrate.project_root()
    assert (root / "alembic.ini").is_file()
    assert (root / "migrations").is_dir()
