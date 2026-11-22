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
MAX_CHECKPOINT_BYTES = 1 * 2**20  # one atomic upload; larger state needs chunking (future)


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
    package: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
        description="user-code package digest (ADR 0002); `kind` is then its resource class",
    )


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
    user_code: bool = Field(
        default=False, description="the node accepts user-code packages (off until ADR gates pass)"
    )


class JobSyncRequest(_Contract):
    protocol_version: int = Field(ge=1, le=1000)
    reports: list[AgentJobReport] = Field(default_factory=list, max_length=MAX_REPORTS_PER_SYNC)
    capacity: NodeJobCapacity


class CheckpointRef(_Contract):
    """A centrally stored checkpoint the new assignee should resume from."""

    version: int = Field(ge=1, description="increases with every accepted upload")
    units_done: int = Field(ge=0, le=MAX_TOTAL_UNITS)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=1, le=MAX_CHECKPOINT_BYTES)


class JobAssignment(_Contract):
    job_id: UUID
    attempt: int = Field(ge=1)
    spec: JobSpec
    checkpoint: CheckpointRef | None = Field(
        default=None, description="resume from this; download it before starting"
    )


class CheckpointUpload(_Contract):
    """Uploaded by the node holding the current attempt. Atomic: the controller stores it
    only if the hash matches and it passes validation, so a truncated or interrupted
    upload can never replace the previous good version."""

    attempt: int = Field(ge=1)
    version: int = Field(ge=1, description="the uploader's own counter; must increase")
    units_done: int = Field(ge=0, le=MAX_TOTAL_UNITS)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    payload_b64: str = Field(min_length=4, max_length=(MAX_CHECKPOINT_BYTES * 4) // 3 + 8)


class CheckpointDownload(_Contract):
    version: int = Field(ge=1)
    units_done: int = Field(ge=0, le=MAX_TOTAL_UNITS)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    payload_b64: str


def validate_catalog_checkpoint(payload: bytes, *, units_done: int, total_units: int) -> str | None:
    """None if `payload` is a consistent catalog checkpoint for `units_done`, else why not.
    The catalog workload checkpoints {"units_done", "checksum"}, where checksum is the sum
    of i*i over the units done so far. It must equal the closed form for that prefix."""
    import json

    try:
        data = json.loads(payload.decode("utf-8"))
        done, checksum = int(data["units_done"]), int(data.get("checksum", -1))
    except (ValueError, KeyError, TypeError, UnicodeDecodeError, AttributeError):
        return "checkpoint is not valid catalog JSON"
    if done != units_done:
        return f"checkpoint says {done} units, upload claims {units_done}"
    if not 0 <= done <= total_units:
        return f"checkpoint units {done} outside 0..{total_units}"
    if checksum != expected_checksum(done):
        return "checkpoint checksum does not match its unit count"
    return None


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
