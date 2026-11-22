"""Engine and session lifecycle."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Annotated, Any

from fastapi import Depends, Request
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


def create_db_engine(url: str) -> Engine:
    kwargs: dict[str, Any] = {"pool_pre_ping": True}
    is_sqlite = url.startswith("sqlite")
    if is_sqlite:
        kwargs["connect_args"] = {"check_same_thread": False}
        if url in ("sqlite://", "sqlite:///:memory:"):
            kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)
    if is_sqlite:

        @event.listens_for(engine, "connect")
        def _enable_sqlite_fks(dbapi_connection: Any, _record: Any) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def make_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def get_db(request: Request) -> Iterator[Session]:
    """One session per request. Handlers commit explicitly; anything else rolls back."""
    session: Session = request.app.state.sessionmaker()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


DbSession = Annotated[Session, Depends(get_db)]
