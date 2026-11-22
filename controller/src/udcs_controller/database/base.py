"""Declarative base, portable column types and naming conventions."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import JSON, DateTime, Enum, MetaData, TypeDecorator
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


JSONType = JSON().with_variant(JSONB(), "postgresql")


class UTCDateTime(TypeDecorator[datetime]):
    """timestamptz on PostgreSQL; guarantees aware-UTC values on every backend.

    Naive datetimes are rejected on write: they are almost always a bug.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime passed to a UTCDateTime column")
        return value.astimezone(UTC)

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:  # SQLite stores no offset; we only ever write UTC
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


def str_enum(enum_cls: type[StrEnum], name: str) -> Enum:
    """VARCHAR + CHECK constraint storing enum *values* (portable, easy to extend)."""
    return Enum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=32,
        values_callable=lambda members: [m.value for m in members],
        validate_strings=True,
    )


def utcnow() -> datetime:
    return datetime.now(UTC)
