from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from udcs_shared.jobs import MAX_TOTAL_UNITS, JobResult, JobState
from udcs_shared.protection import WorkloadClass


class JobCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(default="", max_length=128)
    kind: WorkloadClass = Field(description="catalog workload, or a package's resource class")
    total_units: int | None = Field(
        default=None, ge=1, le=MAX_TOTAL_UNITS, description="catalog jobs only (required there)"
    )
    memory_mb: int = Field(default=256, ge=16, le=4096)
    priority: int = Field(default=0, ge=0, le=100, description="above 0 requires manage_jobs")
    package: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
        description="a registered user-code package; refused while user code is disabled",
    )


class JobOut(BaseModel):
    id: uuid.UUID
    name: str
    owner_id: uuid.UUID
    kind: WorkloadClass
    total_units: int
    memory_mb: int
    priority: int
    state: JobState
    local_state: str | None = Field(description="as the node's governor sees it (e.g. paused)")
    progress: float = Field(ge=0, le=1)
    units_done: int
    attempt: int
    failures: int
    requeues: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    cpu_seconds: float
    memory_bytes: int
    error: str | None
    exit_code: int | None = Field(default=None, description="package jobs: the process exit code")
    node_id: uuid.UUID | None = Field(default=None, description="shown only to manage_jobs")
    package: str | None = Field(default=None, description="user-code package digest, if any")


class JobLogOut(BaseModel):
    id: int = Field(description="increasing; pass the last one as ?after= to page or follow")
    at: datetime
    attempt: int
    source: str
    message: str


class JobResultOut(BaseModel):
    job_id: uuid.UUID
    result: JobResult
    verified: bool = Field(description="checksum matched the closed form for total_units")
