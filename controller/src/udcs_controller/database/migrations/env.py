"""Alembic environment. Uses a caller-supplied connection when present."""

from __future__ import annotations

from alembic import context
from sqlalchemy.engine import Connection

import udcs_controller.database.registry  # noqa: F401  (populates metadata)
from udcs_controller.database.base import Base
from udcs_controller.database.session import create_db_engine

target_metadata = Base.metadata


def _configure_and_run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=connection.dialect.name == "sqlite",
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_online() -> None:
    connection = context.config.attributes.get("connection")
    if connection is not None:
        _configure_and_run(connection)
        return
    url = context.config.get_main_option("sqlalchemy.url")
    if not url:
        raise RuntimeError("no database connection or sqlalchemy.url configured")
    engine = create_db_engine(url)
    try:
        with engine.connect() as conn:
            _configure_and_run(conn)
            conn.commit()
    finally:
        engine.dispose()


def run_offline() -> None:
    context.configure(
        url=context.config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_offline()
else:
    run_online()
