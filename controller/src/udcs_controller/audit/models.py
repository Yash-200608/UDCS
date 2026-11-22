from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from udcs_controller.database.base import Base, JSONType, UTCDateTime, str_enum


class ActorType(StrEnum):
    USER = "user"
    NODE = "node"
    ANONYMOUS = "anonymous"
    SYSTEM = "system"


class AuditEvent(Base):
    """Append-only. No foreign keys, so history survives deletion of its subjects."""

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True)
    actor_type: Mapped[ActorType] = mapped_column(str_enum(ActorType, "audit_actor_type"))
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
