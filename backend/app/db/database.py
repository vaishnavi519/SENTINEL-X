"""
SENTINEL-X — Database Session Management
==========================================
Provides an async SQLAlchemy engine and session factory backed by SQLite.

Tables are created automatically on first startup (create_all).
For production use, migrate to Alembic-managed migrations.

Usage:
    from app.db.database import get_db_session

    async with get_db_session() as session:
        session.add(some_model)
        await session.commit()
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


def _create_engine():
    settings = get_settings()
    return create_async_engine(
        settings.database_url,
        echo=settings.debug,        # Log SQL when debug=True
        future=True,
        connect_args={"check_same_thread": False},  # Required for SQLite
    )


# Module-level engine — created once
_engine = None
_session_factory = None


def get_engine():
    """Get (or lazily create) the async engine."""
    global _engine
    if _engine is None:
        _engine = _create_engine()
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Get (or lazily create) the session factory."""
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )
    return _session_factory


@asynccontextmanager
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager that yields a database session.

    Automatically commits on success and rolls back on exception.

    Example:
        async with get_db_session() as session:
            session.add(record)
            await session.commit()
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def create_all_tables() -> None:
    """
    Create all database tables defined in ORM models.
    Called once at application startup.
    """
    # Import all models to ensure they are registered with Base.metadata
    import app.models.audit  # noqa: F401

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_engine() -> None:
    """Dispose the engine. Called at application shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
