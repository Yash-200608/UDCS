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

import logging
import uuid
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from udcs_controller.auth.models import User
from udcs_controller.config import Settings
from udcs_controller.jobs.models import Job, JobLog
from udcs_controller.nodes.models import Node
from udcs_controller.nodes.service import check_protocol
from udcs_shared.agent_api import NodeAdminState
from udcs_shared.jobs import (
    MAX_ASSIGNMENTS_PER_SYNC,
    TERMINAL_JOB_STATES,
    AgentJobReport,
    JobAssignment,
    JobResult,
    JobSpec,
    JobState,
    JobSyncRequest,
    JobSyncResponse,
    LocalJobState,
    expected_checksum,
)
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
    add_log(db, job, f"submitted: {spec.kind.value} x {spec.total_units} units", at=now)
    return job


def cancel_job(db: Session, job: Job, *, now: datetime, reason: str) -> None:
    if job.state in TERMINAL_JOB_STATES:
        raise InvalidJobTransition(f"job is already {job.state.value}")
    # The node (if any) learns on its next sync: its report no longer matches a live
    # assignment, so it is told to cancel and discard the workload.
    _finish(job, JobState.CANCELLED, now=now)
    add_log(db, job, f"cancelled: {reason}", at=now)


def spec_of(job: Job) -> JobSpec:
    return JobSpec(kind=job.kind, total_units=job.total_units, memory_mb=job.memory_mb)


# -- transitions ---------------------------------------------------------------------------


def _finish(job: Job, state: JobState, *, now: datetime, error: str | None = None) -> None:
    job.state = state
    job.finished_at = now
    job.updated_at = now
    job.lease_expires_at = None
    if error is not None:
        job.error = error[:300]


def _requeue(db: Session, job: Job, *, now: datetime, reason: str, settings: Settings) -> None:
    """Back to the queue, keeping its original queue position. Progress was local to the
    node that lost it, so it restarts from zero (checkpoints do not migrate yet)."""
    job.requeues += 1
    if job.requeues > settings.job_max_requeues:
        _finish(job, JobState.FAILED, now=now, error=f"requeued too often (last: {reason})")
        add_log(db, job, f"failed: requeued too often ({reason})", at=now)
        return
    job.state = JobState.QUEUED
    job.node_id = None
    job.lease_expires_at = None
    job.assigned_at = None
    job.units_done = 0
    job.local_state = None
    job.cpu_seconds = 0.0
    job.memory_bytes = 0
    job.updated_at = now
    add_log(db, job, f"requeued: {reason}", at=now)


def _record_failure(
    db: Session, job: Job, *, now: datetime, error: str, settings: Settings
) -> None:
    job.failures += 1
    job.error = error[:300]
    if job.failures >= settings.job_max_failures:
        _finish(job, JobState.FAILED, now=now)
        add_log(db, job, f"failed: {error}", at=now)
        return
    add_log(db, job, f"attempt {job.attempt} failed: {error}", at=now)
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
    job.units_done = min(report.units_done, job.total_units)
    # The process is gone by the time it reports completion (0 s): keep the highest
    # value seen for this attempt. Reset on requeue.
    job.cpu_seconds = max(job.cpu_seconds, report.cpu_seconds)
    job.memory_bytes = report.memory_bytes
    job.local_state = report.state.value
    job.updated_at = now
    job.lease_expires_at = now + settings.job_lease

    if report.state == LocalJobState.COMPLETED:
        problem = verify_result(job, report.result)
        if problem is None:
            job.result = report.result.model_dump(mode="json") if report.result else None
            job.units_done = job.total_units
            _finish(job, JobState.SUCCEEDED, now=now)
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
        need = job.memory_mb if job.kind == WorkloadClass.MEMORY else 64
        if need > memory_left:
            continue
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
        add_log(db, job, f"assigned (attempt {job.attempt})", at=now)
        assigned.append(JobAssignment(job_id=job.id, attempt=job.attempt, spec=spec_of(job)))
    return assigned
