"""Schema bootstrap and Alembic migration helpers.

Two things live here:

``ensure_schema``
    Bring an *existing* database up to the shape the current models expect:
    create missing tables, add missing columns. This repairs databases that
    predate Alembic (they were created with ``create_all`` and can silently
    drift — e.g. a column added to a model never reaches an old SQLite file).

``upgrade`` / ``stamp``
    Hand over to Alembic for everything after the baseline.

The upgrade path used by :func:`run` is therefore safe in both directions:

* fresh database → create everything → stamp baseline → no pending revisions
* legacy database → repair drift → stamp baseline → apply later revisions
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, List, Tuple

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect, text

from gyra_user.db import Base, get_engine

logger = logging.getLogger(__name__)

VERSION_TABLE = "alembic_version"


def project_root() -> Path:
    """Locate the directory holding ``alembic.ini``.

    Works both from a source checkout (``src/gyra_user/migrate.py``) and from a
    wheel installed into site-packages — in the latter case the files are
    shipped next to the venv in the container image.
    """
    override = os.environ.get("GYRA_USER_PROJECT_ROOT")
    if override:
        return Path(override).resolve()
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / "alembic.ini").is_file() and (
            candidate / "migrations"
        ).is_dir():
            return candidate
    raise RuntimeError(
        "cannot locate alembic.ini; set GYRA_USER_PROJECT_ROOT to the project root"
    )


def _alembic_config(database_url: str) -> Config:
    root = project_root()
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "migrations"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


def ensure_schema(engine: Engine) -> List[str]:
    """Create missing tables and add missing columns. Returns a change log."""
    from gyra_user import models  # noqa: F401  (registers every table)

    changes: List[str] = []
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    missing_tables = [
        table
        for table in Base.metadata.sorted_tables
        if table.name not in existing_tables
    ]
    if missing_tables:
        Base.metadata.create_all(engine, tables=missing_tables, checkfirst=True)
        changes.extend(f"created table {t.name}" for t in missing_tables)

    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue
        existing_columns = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in existing_columns:
                continue
            # SQLite only supports ADD COLUMN for nullable / defaulted columns.
            _add_column(engine, table.name, column)
            changes.append(f"added column {table.name}.{column.name}")

    return changes


def _add_column(engine: Engine, table: str, column: Any) -> None:
    server_default = ""
    if column.server_default is not None:
        default = getattr(column.server_default, "arg", "")
        server_default = f" DEFAULT {default!r}"
    elif column.default is not None:
        arg = getattr(column.default, "arg", None)
        if arg is not None and not callable(arg):
            server_default = f" DEFAULT {arg!r}"
    elif column.nullable is False:
        raise RuntimeError(
            f"cannot add NOT NULL column {table}.{column.name} without a default; "
            "write an Alembic revision instead"
        )

    compiled = column.type.compile(engine.dialect)
    stmt = f"ALTER TABLE {table} ADD COLUMN {column.name} {compiled}{server_default}"
    with engine.begin() as conn:
        conn.execute(text(stmt))


def _current_revision(engine: Engine) -> str | None:
    inspector = inspect(engine)
    if VERSION_TABLE not in inspector.get_table_names():
        return None
    with engine.connect() as conn:
        row = conn.execute(text(f"SELECT version_num FROM {VERSION_TABLE}")).first()
    return row[0] if row else None


def _head_revision(cfg: Config) -> str:
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(cfg)
    heads = script.get_heads()
    return heads[0] if heads else ""


def run(database_url: str, revision: str = "head") -> Tuple[List[str], str]:
    """Repair drift if needed, then apply migrations up to ``revision``."""
    engine = get_engine(database_url)
    changes = ensure_schema(engine)
    cfg = _alembic_config(database_url)

    stamped = _current_revision(engine)
    if stamped is None:
        head = _head_revision(cfg)
        if head:
            command.stamp(cfg, head)
            changes.append(f"stamped baseline {head}")
    command.upgrade(cfg, revision)
    return changes, _current_revision(engine) or ""


def stamp(database_url: str, revision: str = "head") -> None:
    from gyra_user import models  # noqa: F401

    engine = get_engine(database_url)
    Base.metadata.create_all(engine, checkfirst=True)
    command.stamp(_alembic_config(database_url), revision)


def current(database_url: str) -> str:
    engine = get_engine(database_url)
    return _current_revision(engine) or "(not stamped)"


def history(database_url: str) -> List[str]:
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(_alembic_config(database_url))
    return [
        f"{r.revision} -> {r.down_revision or ''}  {r.doc}"
        for r in script.walk_revisions()
    ]


__all__ = ["current", "ensure_schema", "history", "run", "stamp"]
