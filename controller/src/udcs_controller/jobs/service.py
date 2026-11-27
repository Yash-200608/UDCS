"""Job lifecycle and the pull-based scheduler. Callers commit.

State machine (controller view):
    queued -> assigned -> running -> succeeded | failed
       ^          |           |
       +----------+-----------+   requeue: lease lost, agent lost the job,
                                  node left ACTIVE, or a retryable failure
    any non-terminal -> cancelled (user or admin)

Invariants:
- `attempt` (the fencing token) increases on every assignment. A report for any
  other attempt, or from a node the job is not assigned to, changes nothing and
  the node is told to cancel it.
- Every scheduling fact is in the database. A controller restart loses nothing,
  and leases are not reaped until one lease period after start, so nodes that kept
  working through a controller outage can renew first.
- The node decides how much new work it will take (`NodeJobCapacity`, derived from
  its local protection envelope). The scheduler only chooses *which* jobs fit that offer.

Concurrency (PostgreSQL; SQLite serializes writers and ignores row locks):
- Every read-modify-write of a job row locks it (`FOR UPDATE`), so a node's report,
  another node's lease reaper and a user's cancel cannot overwrite each other.
- The reaper and candidate selection use `SKIP LOCKED`: they never wait on a row
  another sync holds. Claimers therefore cannot deadlock, and two nodes never pick
  the same candidate.
- The claim UPDATE keeps `WHERE state = 'queued'` as a second, independent guard.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import uuid
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import func, select, true, update
from sqlalchemy.orm import Session

from udcs_controller.auth.models import User
from udcs_controller.config import Settings
from udcs_controller.jobs.models import Job, JobCheckpoint, JobLog
from udcs_controller.nodes.models import Node
from udcs_controller.nodes.service import check_protocol
from udcs_shared.agent_api import NodeAdminState
from udcs_shared.jobs import (
    MAX_ASSIGNMENTS_PER_SYNC,
    MAX_CHECKPOINT_BYTES,
    TERMINAL_JOB_STATES,
    AgentJobReport,
    CheckpointRef,
    CheckpointUpload,
    FailureKind,
    JobAssignment,
    JobResult,
    JobSpec,
    JobState,
    JobSyncRequest,
    JobSyncResponse,
    LocalJobState,
    PackageRunLimits,
    expected_checksum,
    validate_catalog_checkpoint,
)
from udcs_shared.packages import OutputManifest, PackageManifest
from udcs_shared.protection import WorkloadClass

logger = logging.getLogger(__name__)

ACTIVE_JOB_STATES = (JobState.ASSIGNED, JobState.RUNNING)
_CANDIDATE_WINDOW = 200


class JobRejected(Exception):
    pass


class InvalidJobTransition(Exception):
    pass


# -- logs ----------------------------------------------------------------------------------


def add_log(db: Session, job: Job, message: str, *, at: datetime, source: str = "controller"):
    db.add(JobLog(job_id=job.id, at=at, attempt=job.attempt, source=source, message=message[:200]))


def _log_count(db: Session, job: Job) -> int:
    return db.scalar(select(func.count()).select_from(JobLog).where(JobLog.job_id == job.id)) or 0


# -- user operations -----------------------------------------------------------------------


def submit_job(
    db: Session,
    *,
    owner: User,
    spec: JobSpec,
    name: str,
    priority: int,
    now: datetime,
    settings: Settings,
    package_digest: str | None = None,
    run_limits: PackageRunLimits | None = None,
) -> Job:
    active = db.scalar(
        select(func.count())
        .select_from(Job)
        .where(Job.owner_id == owner.id, Job.state.not_in(list(TERMINAL_JOB_STATES)))
    )
    if (active or 0) >= settings.max_active_jobs_per_user:
        raise JobRejected(f"at most {settings.max_active_jobs_per_user} unfinished jobs per user")
    job = Job(
        owner_id=owner.id,
        package_digest=package_digest,
        run_limits=run_limits.model_dump(mode="json") if run_limits is not None else None,
        name=name,
        kind=spec.kind,
        total_units=spec.total_units,
        memory_mb=spec.memory_mb,
        priority=priority,
        state=JobState.QUEUED,
        created_at=now,
        updated_at=now,
        queued_at=now,
        attempt=0,
        failures=0,
        requeues=0,
        units_done=0,
        cpu_seconds=0.0,
        memory_bytes=0,
    )
    db.add(job)
    db.flush()
    if package_digest:
        add_log(db, job, f"submitted: package {package_digest[:12]} ({spec.kind.value})", at=now)
    else:
        add_log(db, job, f"submitted: {spec.kind.value} x {spec.total_units} units", at=now)
    return job


def cancel_job(db: Session, job: Job, *, now: datetime, reason: str) -> None:
    if job.state in TERMINAL_JOB_STATES:
        raise InvalidJobTransition(f"job is already {job.state.value}")
    # The node (if any) learns on its next sync: its report no longer matches a live
    # assignment, so it is told to cancel and discard the workload.
    _finish(db, job, JobState.CANCELLED, now=now)
    add_log(db, job, f"cancelled: {reason}", at=now)


def spec_of(job: Job) -> JobSpec:
    return JobSpec(
        kind=job.kind,
        total_units=job.total_units,
        memory_mb=job.memory_mb,
        package=job.package_digest,
        limits=PackageRunLimits.model_validate(job.run_limits) if job.run_limits else None,
    )


# -- transitions ---------------------------------------------------------------------------


def _drop_checkpoint(db: Session, job: Job) -> None:
    checkpoint = db.get(JobCheckpoint, job.id)
    if checkpoint is not None:
        db.delete(checkpoint)
        db.flush()  # later lookups in this transaction must not see it


def _finish(
    db: Session, job: Job, state: JobState, *, now: datetime, error: str | None = None
) -> None:
    _drop_checkpoint(db, job)  # a finished job never resumes; free the storage
    job.state = state
    job.finished_at = now
    job.updated_at = now
    job.lease_expires_at = None
    if error is not None:
        job.error = error[:300]


def _requeue(db: Session, job: Job, *, now: datetime, reason: str, settings: Settings) -> None:
    """Back to the queue, keeping its original queue position. Progress is kept if a
    checkpoint reached the controller; only work after the last upload is repeated."""
    job.requeues += 1
    if job.requeues > settings.job_max_requeues:
        _finish(db, job, JobState.FAILED, now=now, error=f"requeued too often (last: {reason})")
        add_log(db, job, f"failed: requeued too often ({reason})", at=now)
        return
    job.state = JobState.QUEUED
    job.node_id = None
    job.lease_expires_at = None
    job.assigned_at = None
    checkpoint = db.get(JobCheckpoint, job.id)
    job.units_done = checkpoint.units_done if checkpoint is not None else 0
    job.local_state = None
    job.cpu_seconds = 0.0
    job.memory_bytes = 0
    job.updated_at = now
    resume = f"; resumes from checkpoint at {checkpoint.units_done} units" if checkpoint else ""
    add_log(db, job, f"requeued: {reason}{resume}", at=now)


def _record_failure(
    db: Session, job: Job, *, now: datetime, error: str, settings: Settings
) -> None:
    job.failures += 1
    job.error = error[:300]
    if job.failures >= settings.job_max_failures:
        _finish(db, job, JobState.FAILED, now=now)
        add_log(db, job, f"failed: {error}", at=now)
        return
    add_log(db, job, f"attempt {job.attempt} failed: {error}", at=now)
    _drop_checkpoint(db, job)  # the failed run's state may be the cause: retry clean
    job.requeues -= 1  # a retry after a failure is counted as a failure, not a requeue
    _requeue(db, job, now=now, reason="retry after failure", settings=settings)


def verify_result(job: Job, result: JobResult | None) -> str | None:
    """None if the result is acceptable, otherwise why not."""
    if result is None:
        return "completed without a result"
    if result.units != job.total_units:
        return f"result covers {result.units} of {job.total_units} units"
    if int(result.checksum) != expected_checksum(job.total_units):
        return "result checksum does not match (lost or repeated units)"
    return None


def reap_expired_leases(
    db: Session, *, now: datetime, settings: Settings, controller_started_at: datetime
) -> int:
    if now - controller_started_at < settings.job_lease:
        return 0  # just restarted: give nodes one lease period to renew first
    expired = db.scalars(
        select(Job)
        .where(Job.state.in_(ACTIVE_JOB_STATES), Job.lease_expires_at < now)
        .with_for_update(skip_locked=True)  # a row being renewed right now is not expired
    ).all()
    for job in expired:
        _requeue(db, job, now=now, reason="lease expired (node unreachable)", settings=settings)
    if expired:
        logger.info("requeued jobs with expired leases", extra={"count": len(expired)})
    return len(expired)


# -- the agent sync ------------------------------------------------------------------------


def _apply_report(
    db: Session,
    job: Job,
    report: AgentJobReport,
    *,
    now: datetime,
    settings: Settings,
    log_room: int,
) -> bool:
    """Apply a report from the job's current assignment. Returns True when it is terminal."""
    for line in report.logs[: max(0, log_room)]:
        add_log(
            db,
            job,
            line.message,
            at=now - timedelta(seconds=line.age_seconds),
            source="agent",
        )
    # Monotonic: a resumed attempt reports 0 until its workload has started.
    job.units_done = max(job.units_done, min(report.units_done, job.total_units))
    # The process is gone by the time it reports completion (0 s): keep the highest
    # value seen for this attempt. Reset on requeue.
    job.cpu_seconds = max(job.cpu_seconds, report.cpu_seconds)
    job.memory_bytes = report.memory_bytes
    job.local_state = report.state.value
    job.updated_at = now
    job.lease_expires_at = now + settings.job_lease

    if job.package_digest is not None:
        return _apply_package_report(db, job, report, now=now, settings=settings)
    if report.state == LocalJobState.COMPLETED:
        problem = verify_result(job, report.result)
        if problem is None:
            job.result = report.result.model_dump(mode="json") if report.result else None
            job.units_done = job.total_units
            _finish(db, job, JobState.SUCCEEDED, now=now)
            add_log(db, job, "succeeded: result verified", at=now)
        else:
            _record_failure(db, job, now=now, error=problem, settings=settings)
        return True
    if report.state == LocalJobState.FAILED:
        _record_failure(
            db, job, now=now, error=report.error or "workload failed on the node", settings=settings
        )
        return True
    if job.state == JobState.ASSIGNED and report.state != LocalJobState.WAITING:
        job.state = JobState.RUNNING
        job.started_at = job.started_at or now
        add_log(db, job, "running on node", at=now)
    return False


_STARTED = (
    LocalJobState.RUNNING,
    LocalJobState.THROTTLED,
    LocalJobState.PAUSED,
    LocalJobState.CHECKPOINTING,
    LocalJobState.EVICTED,
    LocalJobState.UPLOADING,
)


def verify_package_result(job: Job, report: AgentJobReport) -> str | None:
    """None if a COMPLETED package report is acceptable. The outputs it names must be
    exactly the manifest this attempt reported (and whose blobs this attempt uploaded,
    checked by record_outputs), so no report can claim another attempt's outputs."""
    result = report.package_result
    if result is None:
        return "completed without a package result"
    if result.exit_code is None:
        return "completed without an exit code"
    manifest = job.output_manifest
    current = manifest if manifest and manifest.get("attempt") == report.attempt else None
    if current is None:
        if result.outputs_sha256 is not None or result.files:
            return "the outputs it names were never reported by this attempt"
        return None  # a run that wrote nothing
    if OutputManifest.model_validate(current).digest() != result.outputs_sha256:
        return "the result names different outputs than this attempt reported"
    return None


def _apply_package_report(
    db: Session, job: Job, report: AgentJobReport, *, now: datetime, settings: Settings
) -> bool:
    """Package jobs: no units, no checksum. Success means exit code 0 and verified
    outputs. A workload failure (non-zero exit, a limit) is final: re-running the same
    package elsewhere would fail the same way. Infrastructure failures are retried."""
    if report.state == LocalJobState.COMPLETED:
        problem = verify_package_result(job, report)
        if problem is not None:
            _record_failure(db, job, now=now, error=problem, settings=settings)
            return True
        job.exit_code = report.package_result.exit_code
        if job.exit_code == 0:
            job.units_done = job.total_units
            _finish(db, job, JobState.SUCCEEDED, now=now)
            add_log(db, job, "succeeded: exit code 0, outputs verified", at=now)
        else:
            _finish(db, job, JobState.FAILED, now=now, error=f"exited with code {job.exit_code}")
            add_log(db, job, f"failed: exited with code {job.exit_code} (not retried)", at=now)
        return True
    if report.state == LocalJobState.FAILED:
        error = report.error or "package failed on the node"
        if report.failure == FailureKind.WORKLOAD:
            if report.package_result is not None:
                job.exit_code = report.package_result.exit_code
            _finish(db, job, JobState.FAILED, now=now, error=error)
            add_log(db, job, f"failed: {error} (not retried)", at=now)
        else:
            _record_failure(db, job, now=now, error=error, settings=settings)
        return True
    if job.state == JobState.ASSIGNED and report.state in _STARTED:
        job.state = JobState.RUNNING
        job.started_at = job.started_at or now
        add_log(db, job, "running on node", at=now)
    return False


def sync_node_jobs(
    db: Session,
    node: Node,
    request: JobSyncRequest,
    *,
    now: datetime,
    settings: Settings,
    controller_started_at: datetime,
) -> JobSyncResponse:
    check_protocol(request.protocol_version)
    cancel: list[uuid.UUID] = []
    acknowledged: list[uuid.UUID] = []
    reported: set[uuid.UUID] = set()
    node_active = node.admin_state == NodeAdminState.ACTIVE

    for report in request.reports:
        reported.add(report.job_id)
        job = db.get(Job, report.job_id, with_for_update=True)
        current = (
            job is not None
            and job.node_id == node.id
            and job.attempt == report.attempt
            and job.state in ACTIVE_JOB_STATES
        )
        if not current:
            already_recorded = (
                job is not None
                and job.node_id == node.id
                and job.attempt == report.attempt
                and job.state in TERMINAL_JOB_STATES
                and job.state != JobState.CANCELLED
                and report.state in (LocalJobState.COMPLETED, LocalJobState.FAILED)
            )
            (acknowledged if already_recorded else cancel).append(report.job_id)
            continue
        assert job is not None
        if not node_active:
            _requeue(
                db, job, now=now, reason=f"node is {node.admin_state.value}", settings=settings
            )
            cancel.append(job.id)
            continue
        room = settings.job_log_lines_max - _log_count(db, job)
        if _apply_report(db, job, report, now=now, settings=settings, log_room=room):
            acknowledged.append(job.id)

    # Assigned here but not reported: the agent never received the assignment (lost
    # response) or lost the job itself. Requeue now rather than wait for the lease.
    for job in db.scalars(
        select(Job)
        .where(Job.node_id == node.id, Job.state.in_(ACTIVE_JOB_STATES))
        .with_for_update()
    ).all():
        if job.id not in reported:
            _requeue(db, job, now=now, reason="node no longer has this job", settings=settings)

    reap_expired_leases(db, now=now, settings=settings, controller_started_at=controller_started_at)

    assignments: list[JobAssignment] = []
    capacity = request.capacity
    if node_active and capacity.accept and capacity.slots > 0 and capacity.kinds:
        assignments = _assign(db, node, request, now=now, settings=settings)
    return JobSyncResponse(
        assignments=assignments,
        cancel=cancel,
        acknowledged=acknowledged,
        lease_seconds=settings.job_lease_seconds,
    )


def _node_has_gpu(node: Node) -> bool:
    return node.inventory is not None and node.inventory.gpu_count > 0


def node_verified_appcontainer(node: Node) -> bool:
    """The node itself measured a working AppContainer (a real launch, not presence)."""
    if node.inventory is None:
        return False
    for item in node.inventory.inventory.get("isolation", []) or []:
        if item.get("name") == "appcontainer" and item.get("available") and item.get("verified"):
            return True
    return False


def package_mismatch(db: Session, node: Node, capacity, job: Job) -> str | None:
    """Why this node must not receive this package job, or None if it may. Checked
    before the claim, so an incompatible node never holds the job (ADR 0003)."""
    if not node.user_code_allowed:
        return "node not eligible for user code (administrator setting)"
    if not node_verified_appcontainer(node):
        return "node has no verified AppContainer isolation"
    if not capacity.user_code:
        return "node does not offer user code"
    from udcs_controller.packages.models import Package

    package = db.get(Package, job.package_digest)
    if package is None:
        return "package missing"
    manifest = PackageManifest.model_validate(package.manifest)
    if capacity.python != manifest.python:
        return f"needs Python {manifest.python}, node offers {capacity.python}"
    if manifest.environment:
        env = db.get(Package, manifest.environment)
        if env is None or env.approved_at is None:
            return "environment no longer approved"
        env_manifest = PackageManifest.model_validate(env.manifest)
        if env_manifest.platform != capacity.platform:
            return f"environment is built for {env_manifest.platform}, node is {capacity.platform}"
        if env_manifest.python != capacity.python:
            return f"environment needs Python {env_manifest.python}"
    return None


def _assign(
    db: Session, node: Node, request: JobSyncRequest, *, now: datetime, settings: Settings
) -> list[JobAssignment]:
    capacity = request.capacity
    kinds = set(capacity.kinds)
    if not _node_has_gpu(node):
        kinds.discard(WorkloadClass.GPU)  # never trust an offer the inventory cannot back
    if not kinds:
        return []
    candidates = db.scalars(
        select(Job)
        .where(Job.state == JobState.QUEUED, Job.kind.in_(sorted(kinds)))
        # User code goes only to nodes that explicitly offer it (none do yet: ADR 0001 gates).
        # User-code jobs need both the controller's kill switch and the node's own
        # flag; either one off means only catalog jobs are handed out.
        .where(
            true()
            if settings.user_code_enabled and capacity.user_code
            else Job.package_digest.is_(None)
        )
        .order_by(Job.priority.desc(), Job.queued_at.asc())
        .limit(_CANDIDATE_WINDOW)
        .with_for_update(skip_locked=True)  # concurrent syncs see disjoint candidates
    ).all()
    if not candidates:
        return []
    # Fair share across users: among equal priorities, users with fewer jobs already
    # running go first. A GPU node takes GPU work first, because only GPU nodes can.
    running_by_owner = Counter(
        dict(
            db.execute(
                select(Job.owner_id, func.count())
                .where(Job.state.in_(ACTIVE_JOB_STATES))
                .group_by(Job.owner_id)
            ).all()
        )
    )
    has_gpu = WorkloadClass.GPU in kinds
    candidates = sorted(
        candidates,
        key=lambda j: (
            -j.priority,
            0 if (has_gpu and j.kind == WorkloadClass.GPU) else 1,
            running_by_owner[j.owner_id],
            j.queued_at,
        ),
    )
    memory_left = capacity.memory_available_mb
    slots = min(capacity.slots, MAX_ASSIGNMENTS_PER_SYNC)
    assigned: list[JobAssignment] = []
    for job in candidates:
        if len(assigned) >= slots:
            break
        need = job.memory_mb if job.kind == WorkloadClass.MEMORY or job.package_digest else 64
        if need > memory_left:
            continue
        if job.package_digest is not None and package_mismatch(db, node, capacity, job):
            continue  # left queued for a node that fits; never claimed by this one
        # Atomic claim: two nodes syncing at once can never both get this job.
        claimed = db.execute(
            update(Job)
            .where(Job.id == job.id, Job.state == JobState.QUEUED)
            .values(
                state=JobState.ASSIGNED,
                node_id=node.id,
                attempt=Job.attempt + 1,
                assigned_at=now,
                lease_expires_at=now + settings.job_lease,
                updated_at=now,
                error=None,
            )
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            continue
        db.refresh(job)
        memory_left -= need
        running_by_owner[job.owner_id] += 1
        ref = _checkpoint_ref(db, job)
        resume = f", resume from {ref.units_done} units" if ref else ""
        add_log(db, job, f"assigned (attempt {job.attempt}{resume})", at=now)
        assigned.append(
            JobAssignment(job_id=job.id, attempt=job.attempt, spec=spec_of(job), checkpoint=ref)
        )
    return assigned


# -- central checkpoints ---------------------------------------------------------------------


class CheckpointRejected(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def _checkpoint_ref(db: Session, job: Job) -> CheckpointRef | None:
    checkpoint = db.get(JobCheckpoint, job.id)
    if checkpoint is None:
        return None
    return CheckpointRef(
        version=checkpoint.version,
        units_done=checkpoint.units_done,
        sha256=checkpoint.sha256,
        size=checkpoint.size,
    )


def _current_assignment(db: Session, node: Node, job_id: uuid.UUID, attempt: int) -> Job:
    job = db.get(Job, job_id, with_for_update=True)  # serializes uploads and requeues
    if (
        job is None
        or job.node_id != node.id
        or job.attempt != attempt
        or job.state not in ACTIVE_JOB_STATES
    ):
        # Fencing, as for reports: only the current attempt on its own node counts.
        raise CheckpointRejected(409, "not the current assignment of this job")
    return job


def store_checkpoint(
    db: Session, node: Node, job_id: uuid.UUID, upload: CheckpointUpload, *, now: datetime
) -> JobCheckpoint:
    """Validate, then atomically replace the job's checkpoint. Nothing is stored unless the
    whole payload arrived intact and is consistent, so the previous version survives any
    interrupted or corrupted upload."""
    job = _current_assignment(db, node, job_id, upload.attempt)
    try:
        payload = base64.b64decode(upload.payload_b64, validate=True)
    except (binascii.Error, ValueError):
        raise CheckpointRejected(422, "payload is not valid base64") from None
    if not payload or len(payload) > MAX_CHECKPOINT_BYTES:
        raise CheckpointRejected(422, "payload size out of bounds")
    if hashlib.sha256(payload).hexdigest() != upload.sha256:
        raise CheckpointRejected(422, "sha256 mismatch: truncated or corrupted upload")
    if job.package_digest is not None:
        # Package checkpoints are opaque bytes the package wrote itself (state/
        # checkpoint.bin). Integrity is the hash; their meaning belongs to the package.
        if upload.units_done != 0:
            raise CheckpointRejected(422, "package checkpoints carry no unit count")
        problem = None
    else:
        problem = validate_catalog_checkpoint(
            payload, units_done=upload.units_done, total_units=job.total_units
        )
    if problem is not None:
        raise CheckpointRejected(422, problem)

    existing = db.get(JobCheckpoint, job.id)
    if existing is not None:
        if (
            existing.attempt == upload.attempt
            and existing.uploader_version == upload.version
            and existing.sha256 == upload.sha256
        ):
            return existing  # a retried upload whose response was lost: idempotent
        if upload.units_done < existing.units_done:
            raise CheckpointRejected(409, "stale: older than the stored checkpoint")
        if existing.attempt == upload.attempt and upload.version <= existing.uploader_version:
            raise CheckpointRejected(409, "stale: version not newer than the stored one")
        existing.version += 1
        record = existing
    else:
        record = JobCheckpoint(job_id=job.id, version=1)
        db.add(record)
    record.attempt = upload.attempt
    record.node_id = node.id
    record.uploader_version = upload.version
    record.units_done = upload.units_done
    record.sha256 = upload.sha256
    record.size = len(payload)
    record.payload = payload
    record.created_at = now
    job.units_done = max(job.units_done, upload.units_done)
    db.flush()
    return record


def checkpoint_for_assignee(
    db: Session, node: Node, job_id: uuid.UUID, attempt: int
) -> JobCheckpoint:
    _current_assignment(db, node, job_id, attempt)
    checkpoint = db.get(JobCheckpoint, job_id)
    if checkpoint is None:
        raise CheckpointRejected(404, "no checkpoint stored for this job")
    return checkpoint
