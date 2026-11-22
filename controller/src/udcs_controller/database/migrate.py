"""Programmatic Alembic entry points (no alembic.ini needed at runtime)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def alembic_config(database_url: str | None = None) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS_DIR))
    if database_url is not None:
        cfg.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return cfg


def upgrade_to_head(engine: Engine) -> None:
    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "head")
