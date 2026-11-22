"""Job contracts shared by the controller, the scheduler and the node agent.

Execution model (Milestone 2, catalog phase):
- Only workloads from the built-in catalog run (the cpu / memory / disk / gpu
  synthetic workloads). No user-supplied code is accepted until an isolation model
  is approved (decision D-3).
- The agent *pulls* work. It asks for jobs only when its local protection envelope
  allows that workload class, and the governor can still throttle, pause or evict
  any job afterwards. The controller never pushes work past local protection.
- Each assignment carries an `attempt`, a fencing token. A report for an older
  attempt is stale and ignored, and the agent is told to cancel it.
- A lease that is not renewed (node offline, agent lost the job) is requeued.
  Delivery is at-least-once, and only the current attempt's result is accepted.
"""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from udcs_shared.protection import WorkloadClass

MAX_TOTAL_UNITS = 10_000_000
MAX_REPORTS_PER_SYNC = 64
MAX_LOG_LINES_PER_REPORT = 50
MAX_ASSIGNMENTS_PER_SYNC = 8


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class JobState(StrEnum):
    QUEUED = "queued"
    ASSIGNED = "assigned"  # claimed by a node; not yet confirmed running there
    RUNNING = "running"  # the node reports it (it may be locally paused or throttled)
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_JOB_STATES = frozenset({JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELLED})


class LocalJobState(StrEnum):
    """What the agent's workload manager says. The governor decides these, not the controller."""

    WAITING = "waiting"
    RUNNING = "running"
    THROTTLED = "throttled"
    PAUSED = "paused"
    CHECKPOINTING = "checkpointing"
    EVICTED = "evicted"
    COMPLETED = "completed"
    FAILED = "failed"


class JobSpec(_Contract):
    """A catalog workload. Fields are bounded, so no spec can describe unbounded work."""

    kind: WorkloadClass
    total_units: int = Field(ge=1, le=MAX_TOTAL_UNITS, description="units of ~50 ms of work")
    memory_mb: int = Field(default=256, ge=16, le=4096, description="memory-class buffer size")


class JobResult(_Contract):
    """Produced by the catalog workload. `checksum` = sum of i*i for every unit index i
    processed. A lost or duplicated unit across checkpoint/resume changes it.
    It detects bugs, not a malicious node: a node can compute it without doing the work."""

    units: int = Field(ge=0, le=MAX_TOTAL_UNITS)
    checksum: str = Field(pattern=r"^[0-9]{1,30}$")


def expected_checksum(units: int) -> int:
    """Closed form of sum(i*i for i in range(units)), so the controller checks it in O(1)."""
    n = units
    return (n - 1) * n * (2 * n - 1) // 6 if n > 0 else 0


class JobLogLine(_Contract):
    age_seconds: float = Field(ge=0, le=86_400, description="how long ago, on the agent's clock")
    message: str = Field(min_length=1, max_length=200)


class AgentJobReport(_Contract):
    job_id: UUID
    attempt: int = Field(ge=1)
    state: LocalJobState
    units_done: int = Field(ge=0, le=MAX_TOTAL_UNITS)
    cpu_seconds: float = Field(default=0, ge=0)
    memory_bytes: int = Field(default=0, ge=0)
    result: JobResult | None = None
    error: str | None = Field(default=None, max_length=300)
    logs: list[JobLogLine] = Field(default_factory=list, max_length=MAX_LOG_LINES_PER_REPORT)


class NodeJobCapacity(_Contract):
    """The agent's offer for *new* work, derived from its current protection envelope."""

    accept: bool
    slots: int = Field(ge=0, le=MAX_ASSIGNMENTS_PER_SYNC)
    kinds: list[WorkloadClass] = Field(default_factory=list, max_length=4)
    memory_available_mb: int = Field(ge=0, le=10_000_000)
    reason: str = Field(default="", max_length=64, description="why nothing is accepted")


class JobSyncRequest(_Contract):
    protocol_version: int = Field(ge=1, le=1000)
    reports: list[AgentJobReport] = Field(default_factory=list, max_length=MAX_REPORTS_PER_SYNC)
    capacity: NodeJobCapacity


class JobAssignment(_Contract):
    job_id: UUID
    attempt: int = Field(ge=1)
    spec: JobSpec


class JobSyncResponse(_Contract):
    assignments: list[JobAssignment] = Field(
        default_factory=list, max_length=MAX_ASSIGNMENTS_PER_SYNC
    )
    cancel: list[UUID] = Field(
        default_factory=list, max_length=MAX_REPORTS_PER_SYNC, description="stop and discard"
    )
    acknowledged: list[UUID] = Field(
        default_factory=list,
        max_length=MAX_REPORTS_PER_SYNC,
        description="terminal reports the controller has recorded; the agent may clean up",
    )
    lease_seconds: int = Field(ge=10, le=3600)
