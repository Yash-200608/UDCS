"""Job contracts shared by the controller, the scheduler and the node agent.

Two kinds of job share this contract:
- catalog jobs: the built-in cpu / memory / disk / gpu synthetic workloads, measured
  in work units and verified by a closed-form checksum;
- package jobs (ADR 0002/0003): a researcher's registered package, run in AppContainer.
  They have no units and no checksum. Their result is the process exit code and an
  output manifest whose files were uploaded, hash-verified, by the executing attempt.
  User-code execution is disabled by default (controller flag, agent constant, and an
  administrator-set per-node eligibility flag).
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

    STAGING = "staging"  # package jobs: fetching and verifying the package before it runs
    UPLOADING = "uploading"  # package jobs: process tree gone, outputs being uploaded
    WAITING = "waiting"
    RUNNING = "running"
    THROTTLED = "throttled"
    PAUSED = "paused"
    CHECKPOINTING = "checkpointing"
    EVICTED = "evicted"
    COMPLETED = "completed"
    FAILED = "failed"


class FailureKind(StrEnum):
    """Who a failure belongs to, which decides whether it is retried."""

    INFRASTRUCTURE = "infrastructure"  # node, staging, isolation, transfer: retried elsewhere
    WORKLOAD = "workload"  # the package itself (exit code, limits): final, never retried


class PackageRunLimits(_Contract):
    """Effective limits for one package run: the package's own, capped by the
    controller's policy. The node enforces them; the controller re-checks outputs."""

    max_runtime_seconds: int = Field(ge=1, le=7 * 86_400)
    max_output_bytes: int = Field(ge=0)
    max_output_files: int = Field(ge=0)
    max_output_entries: int = Field(ge=1)
    max_output_depth: int = Field(ge=1)


class JobSpec(_Contract):
    """A catalog workload or a package run. Fields are bounded, so no spec can describe
    unbounded work. For package jobs `total_units` is 1 and carries no meaning."""

    kind: WorkloadClass
    total_units: int = Field(ge=1, le=MAX_TOTAL_UNITS, description="units of ~50 ms of work")
    memory_mb: int = Field(default=256, ge=16, le=4096, description="memory-class buffer size")
    package: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
        description="user-code package digest (ADR 0002); `kind` is then its resource class",
    )
    limits: PackageRunLimits | None = Field(default=None, description="package jobs only")


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


class PackageResult(_Contract):
    """How a package run ended, reported once its whole process tree has exited and
    its outputs are uploaded. `outputs_sha256` names the exact output manifest the node
    reported for this attempt, so a report cannot point at another attempt's outputs."""

    exit_code: int | None = Field(ge=-(2**31), le=2**32 - 1, description="None: killed by UDCS")
    outputs_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    files: int = Field(default=0, ge=0)
    bytes: int = Field(default=0, ge=0)
    reason: str = Field(default="", max_length=200, description="e.g. runtime limit exceeded")


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
    package_result: PackageResult | None = None
    failure: FailureKind = FailureKind.INFRASTRUCTURE
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
    python: str | None = Field(
        default=None, pattern=r"^3\.[0-9]{1,2}$", description="interpreter packages would run on"
    )
    platform: str | None = Field(
        default=None, pattern=r"^[a-z0-9_]{1,32}$", description="e.g. win_amd64"
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
