from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Boolean, ForeignKey, Integer, String, Uuid, false
from sqlalchemy.orm import Mapped, mapped_column, relationship

from udcs_controller.database.base import Base, JSONType, UTCDateTime, str_enum
from udcs_shared.agent_api import NodeAdminState


class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128))
    hostname: Mapped[str] = mapped_column(String(255))
    lab: Mapped[str] = mapped_column(String(128), default="", index=True)
    admin_state: Mapped[NodeAdminState] = mapped_column(
        str_enum(NodeAdminState, "node_admin_state"), index=True
    )
    # Unique per node. Rotation is two-phase: `pending_credential_hash` becomes the
    # credential on its first successful use, so a lost rotation response can't
    # lock the node out.
    # Set by an administrator only. A node runs user code only if this is true AND it
    # reports a verified AppContainer AND it offers user code itself (ADR 0003).
    user_code_allowed: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    credential_hash: Mapped[str] = mapped_column(String(64), unique=True)
    pending_credential_hash: Mapped[str | None] = mapped_column(
        String(64), unique=True, nullable=True
    )
    credential_issued_at: Mapped[datetime] = mapped_column(UTCDateTime())
    enrollment_key_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("enrollment_keys.id", ondelete="SET NULL"), nullable=True
    )
    enrolled_at: Mapped[datetime] = mapped_column(UTCDateTime())
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_seen_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    agent_version: Mapped[str] = mapped_column(String(32))
    protocol_version: Mapped[int] = mapped_column(Integer)
    inventory_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    latest_telemetry: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)

    inventory: Mapped[HardwareInventoryRecord | None] = relationship(
        cascade="all, delete-orphan", lazy="selectin", uselist=False
    )


class HardwareInventoryRecord(Base):
    __tablename__ = "hardware_inventories"

    node_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("nodes.id", ondelete="CASCADE"), primary_key=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64))
    inventory: Mapped[dict[str, Any]] = mapped_column(JSONType)
    logical_cores: Mapped[int] = mapped_column(Integer)
    memory_total_bytes: Mapped[int] = mapped_column(BigInteger)
    gpu_count: Mapped[int] = mapped_column(Integer)
    gpu_memory_total_bytes: Mapped[int] = mapped_column(BigInteger)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime())


class EnrollmentKey(Base):
    """A lab-scoped deployment secret. It can *create* nodes; it is never a node identity.

    Bounded by expiry and a use count, revocable at any time. Revoking a key does
    not affect nodes already enrolled with it (each has its own credential).
    """

    __tablename__ = "enrollment_keys"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    lab: Mapped[str] = mapped_column(String(128))
    note: Mapped[str] = mapped_column(String(256), default="")
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    max_uses: Mapped[int] = mapped_column(Integer)
    use_count: Mapped[int] = mapped_column(Integer, default=0)
    auto_approve: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
