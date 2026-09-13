"""SQLAlchemy engine / session management (SQLite by default)."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

_engine: Optional[Engine] = None
_session_factory: Optional[sessionmaker[Session]] = None


class Base(DeclarativeBase):
    """Declarative base for all gyra-user models."""


def get_engine(database_url: Optional[str] = None, echo: bool = False) -> Engine:
    """Return a process-wide engine, creating it on first use."""
    global _engine
    if database_url is not None or _engine is None:
        if database_url is None:
            raise RuntimeError("database_url is required for the first get_engine call")
        _engine = _create_engine(database_url, echo=echo)
    return _engine


def _create_engine(database_url: str, echo: bool = False) -> Engine:
    kwargs: dict = {"echo": echo, "future": True}
    if database_url.startswith("sqlite"):
        # FastAPI serves requests in a threadpool; the same connection may be
        # handed to different threads, so disable SQLite's same-thread check.
        kwargs["connect_args"] = {"check_same_thread": False}
    engine = create_engine(database_url, **kwargs)

    if database_url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _connection_record):  # noqa: ANN001
            cursor = dbapi_connection.cursor()
            # Wait instead of failing instantly when another worker holds the
            # write lock — with several gunicorn workers this is routine.
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.execute("PRAGMA foreign_keys=ON")
            try:
                cursor.execute("PRAGMA journal_mode=WAL")
            except Exception:  # noqa: BLE001 - see below
                # Switching journal mode needs a brief exclusive lock. With
                # multiple workers booting at once the loser gets "database is
                # locked"; that is harmless because WAL is a persistent
                # property of the file — whoever wins sets it for everyone.
                pass
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    return engine


def init_engine(
    database_url: str, echo: bool = False, create_tables: bool = True
) -> Engine:
    """Create (or replace) the global engine and optionally create tables."""
    global _engine, _session_factory
    _engine = _create_engine(database_url, echo=echo)
    _session_factory = sessionmaker(
        bind=_engine, autoflush=False, autocommit=False, expire_on_commit=False
    )
    if create_tables:
        init_db()
    return _engine


def init_db(max_attempts: int = 3) -> None:
    """Create all tables declared on :class:`Base`.

    ``create_all`` is *not* race safe: two processes can both see a missing
    table and both try to create it. That happens for real when uvicorn/gunicorn
    boots several workers at once, so a lost race is retried rather than raised.
    """
    from time import sleep

    from sqlalchemy.exc import OperationalError, ProgrammingError

    from gyra_user import models  # noqa: F401  (import registers the models)

    engine = get_engine()
    for attempt in range(max_attempts):
        try:
            Base.metadata.create_all(engine)
            return
        except (OperationalError, ProgrammingError) as exc:
            if "already exists" not in str(exc).lower() or attempt == max_attempts - 1:
                raise
            # A concurrent worker created it first; retry for the remainder.
            sleep(0.1 * (attempt + 1))


def drop_db() -> None:
    from gyra_user import models  # noqa: F401

    Base.metadata.drop_all(get_engine())


def get_session_factory() -> sessionmaker[Session]:
    global _session_factory
    if _session_factory is None:
        raise RuntimeError("Call init_engine() before using the session factory")
    return _session_factory


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope for scripts and CLI commands."""
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


__all__ = [
    "Base",
    "drop_db",
    "get_db",
    "get_engine",
    "get_session_factory",
    "init_db",
    "init_engine",
    "session_scope",
]
