"""User-facing job endpoints: submit, list, inspect, cancel, logs, result."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select

from udcs_controller.audit.models import ActorType
from udcs_controller.audit.service import record_event
from udcs_controller.auth.deps import AuthContext, require
from udcs_controller.auth.permissions import Permission, has_permission
from udcs_controller.core.request_context import Now
from udcs_controller.database.session import DbSession
from udcs_controller.jobs import service
from udcs_controller.jobs.models import Job, JobLog
from udcs_controller.jobs.schemas import JobCreate, JobLogOut, JobOut, JobResultOut
from udcs_shared.jobs import JobResult, JobSpec, JobState

router = APIRouter(prefix="/jobs", tags=["jobs"])

SubmitJobs = Annotated[AuthContext, Depends(require(Permission.SUBMIT_JOBS))]


def _manager(auth: AuthContext) -> bool:
    return has_permission(auth.user.role, Permission.MANAGE_JOBS)


def _visible_job(db: DbSession, auth: AuthContext, job_id: uuid.UUID) -> Job:
    job = db.get(Job, job_id)
    # Someone else's job is reported as missing, not forbidden: no existence oracle.
    if job is None or (job.owner_id != auth.user.id and not _manager(auth)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="job not found")
    return job


def _reap(request: Request, db: DbSession, now) -> None:
    service.reap_expired_leases(
        db,
        now=now,
        settings=request.app.state.settings,
        controller_started_at=request.app.state.started_at,
    )


def to_out(job: Job, *, show_node: bool) -> JobOut:
    return JobOut(
        id=job.id,
        name=job.name,
        owner_id=job.owner_id,
        kind=job.kind,
        total_units=job.total_units,
        memory_mb=job.memory_mb,
        priority=job.priority,
        state=job.state,
        local_state=job.local_state,
        progress=min(1.0, job.units_done / job.total_units),
        units_done=job.units_done,
        attempt=job.attempt,
        failures=job.failures,
        requeues=job.requeues,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        cpu_seconds=job.cpu_seconds,
        memory_bytes=job.memory_bytes,
        error=job.error,
        node_id=job.node_id if show_node else None,
    )


@router.post("", response_model=JobOut, status_code=status.HTTP_201_CREATED)
def submit(body: JobCreate, auth: SubmitJobs, request: Request, db: DbSession, now: Now) -> JobOut:
    if body.priority > 0 and not _manager(auth):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="priority requires manage_jobs")
    try:
        job = service.submit_job(
            db,
            owner=auth.user,
            spec=JobSpec(kind=body.kind, total_units=body.total_units, memory_mb=body.memory_mb),
            name=body.name,
            priority=body.priority,
            now=now,
            settings=request.app.state.settings,
        )
    except service.JobRejected as exc:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from None
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="job.submitted",
        target_type="job",
        target_id=str(job.id),
        details={"kind": job.kind.value, "total_units": job.total_units},
    )
    db.commit()
    return to_out(job, show_node=_manager(auth))


@router.get("", response_model=list[JobOut])
def list_jobs(
    auth: SubmitJobs,
    request: Request,
    db: DbSession,
    now: Now,
    state: JobState | None = None,
    all_users: Annotated[bool, Query(alias="all")] = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[JobOut]:
    _reap(request, db, now)
    db.commit()
    query = select(Job).order_by(Job.created_at.desc(), Job.id.desc()).limit(limit)
    if not (all_users and _manager(auth)):
        query = query.where(Job.owner_id == auth.user.id)
    if state is not None:
        query = query.where(Job.state == state)
    return [to_out(j, show_node=_manager(auth)) for j in db.scalars(query)]


@router.get("/{job_id}", response_model=JobOut)
def get_job(job_id: uuid.UUID, auth: SubmitJobs, request: Request, db: DbSession, now: Now):
    _reap(request, db, now)
    db.commit()
    return to_out(_visible_job(db, auth, job_id), show_node=_manager(auth))


@router.post("/{job_id}/cancel", response_model=JobOut)
def cancel(job_id: uuid.UUID, auth: SubmitJobs, request: Request, db: DbSession, now: Now):
    job = _visible_job(db, auth, job_id)
    db.refresh(job, with_for_update=True)  # a concurrent node report must not undo this
    try:
        service.cancel_job(db, job, now=now, reason=f"by {auth.user.username}")
    except service.InvalidJobTransition as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="job.cancelled",
        target_type="job",
        target_id=str(job.id),
    )
    db.commit()
    return to_out(job, show_node=_manager(auth))


@router.get("/{job_id}/logs", response_model=list[JobLogOut])
def logs(
    job_id: uuid.UUID,
    auth: SubmitJobs,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> list[JobLogOut]:
    job = _visible_job(db, auth, job_id)
    rows = db.scalars(
        select(JobLog).where(JobLog.job_id == job.id).order_by(JobLog.id.asc()).limit(limit)
    )
    return [JobLogOut(at=r.at, attempt=r.attempt, source=r.source, message=r.message) for r in rows]


@router.get("/{job_id}/result", response_model=JobResultOut)
def result(job_id: uuid.UUID, auth: SubmitJobs, db: DbSession) -> JobResultOut:
    job = _visible_job(db, auth, job_id)
    if job.state != JobState.SUCCEEDED or job.result is None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"no result: job is {job.state.value}")
    parsed = JobResult.model_validate(job.result)
    return JobResultOut(
        job_id=job.id, result=parsed, verified=service.verify_result(job, parsed) is None
    )
