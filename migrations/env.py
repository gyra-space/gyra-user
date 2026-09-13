"""Alembic environment for gyra-user.

The database URL comes from gyra-user's own settings layer so that migrations,
the CLI and the running service always agree on which database they touch::

    uv run gyra-user db upgrade          # apply all pending revisions
    uv run alembic revision --autogenerate -m "add foo"
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from gyra_user import models  # noqa: F401  (registers every table)
from gyra_user.config import load_settings
from gyra_user.db import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

# The URL may already have been injected by gyra_user.migrate (which knows the
# caller's settings). Only fall back to the ambient config when it is absent —
# otherwise every migration would silently target the default database.
if not config.get_main_option("sqlalchemy.url"):
    config.set_main_option(
        "sqlalchemy.url", load_settings().resolved_database_url()
    )


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it (``--sql``)."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        # SQLite cannot ALTER in place; batch mode recreates the table.
        render_as_batch=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
