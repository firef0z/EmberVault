"""Database engine and session management for EmberVault."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.config import DatabaseSettings


def create_engine_from_url(database_url: str, **kwargs: Any) -> Engine:
    """Create a SQLAlchemy Engine for a given database connection URL."""
    engine_kwargs: dict[str, Any] = {
        "pool_pre_ping": True,
    }
    # For SQLite (in-memory or file testing), disable pool_pre_ping or configure accordingly
    if database_url.startswith("sqlite"):
        engine_kwargs.pop("pool_pre_ping", None)

    engine_kwargs.update(kwargs)
    return create_engine(database_url, **engine_kwargs)


def create_engine_from_settings(settings: DatabaseSettings | None = None, **kwargs: Any) -> Engine:
    """Create a SQLAlchemy Engine resolving connection parameters from DatabaseSettings."""
    if settings is None:
        settings = DatabaseSettings.load()
    return create_engine_from_url(settings.resolved_database_url, **kwargs)


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a thread-safe sessionmaker factory bound to the given engine."""
    return sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )


@contextmanager
def get_session(
    session_factory: sessionmaker[Session],
) -> Generator[Session, None, None]:
    """Transactional context manager for database sessions."""
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
