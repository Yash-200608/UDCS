"""Job queue tables. All scheduling state lives here, so a controller restart loses nothing."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, Float, ForeignKey, Index, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from udcs_controller.database.base import Base, JSONType, UTCDateTime, str_enum
from udcs_shared.jobs import JobState
from udcs_shared.protection import WorkloadClass


class Job(Base):
    __tablename__ = "jobs"
    __table_args__ = (Index("ix_jobs_state_priority_queued_at", "state", "priority", "queued_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(128), default="")
    kind: Mapped[WorkloadClass] = mapped_column(str_enum(WorkloadClass, "job_kind"))
    total_units: Mapped[int] = mapped_column(Integer)
    memory_mb: Mapped[int] = mapped_column(Integer)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    state: Mapped[JobState] = mapped_column(str_enum(JobState, "job_state"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime())
    queued_at: Mapped[datetime] = mapped_column(UTCDateTime())
    # `attempt` is the fencing token: it increases on every assignment, and a report
    # carrying an older value is stale.
    attempt: Mapped[int] = mapped_column(Integer, default=0)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    requeues: Mapped[int] = mapped_column(Integer, default=0)
    node_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("nodes.id", ondelete="SET NULL"), nullable=True, index=True
    )
    assigned_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    units_done: Mapped[int] = mapped_column(Integer, default=0)
    local_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cpu_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    memory_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONType, nullable=True)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)


class JobLog(Base):
    __tablename__ = "job_logs"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), index=True)
    at: Mapped[datetime] = mapped_column(UTCDateTime())
    attempt: Mapped[int] = mapped_column(Integer)
    source: Mapped[str] = mapped_column(String(16))  # "controller" | "agent"
    message: Mapped[str] = mapped_column(String(200))
