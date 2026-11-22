"""Agent-facing job endpoint: one reconciling round trip per sync."""

from __future__ import annotations

import base64
import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, Response, status

from udcs_controller.core.request_context import Now
from udcs_controller.database.session import DbSession
from udcs_controller.jobs import service
from udcs_controller.nodes.deps import CurrentNode
from udcs_controller.nodes.service import UnsupportedProtocol
from udcs_shared.jobs import CheckpointDownload, CheckpointUpload, JobSyncRequest, JobSyncResponse

router = APIRouter(prefix="/agent", tags=["agent"])


@router.post("/jobs/sync", response_model=JobSyncResponse)
def sync_jobs(
    body: JobSyncRequest, node: CurrentNode, request: Request, db: DbSession, now: Now
) -> JobSyncResponse:
    """The agent reports every job it holds and offers capacity. The response says which
    jobs to start, which to cancel, and which terminal reports were recorded.
    Idempotent: replaying the same request after a lost response is safe."""
    try:
        response = service.sync_node_jobs(
            db,
            node,
            body,
            now=now,
            settings=request.app.state.settings,
            controller_started_at=request.app.state.started_at,
        )
    except UnsupportedProtocol as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None
    db.commit()
    return response


@router.put("/jobs/{job_id}/checkpoint", status_code=status.HTTP_204_NO_CONTENT)
def put_checkpoint(
    job_id: uuid.UUID, body: CheckpointUpload, node: CurrentNode, db: DbSession, now: Now
) -> Response:
    """Store this job's checkpoint centrally (current attempt only; atomic; validated)."""
    try:
        service.store_checkpoint(db, node, job_id, body, now=now)
    except service.CheckpointRejected as exc:
        db.rollback()
        raise HTTPException(exc.status_code, detail=exc.detail) from None
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/jobs/{job_id}/checkpoint", response_model=CheckpointDownload)
def get_checkpoint(
    job_id: uuid.UUID,
    node: CurrentNode,
    db: DbSession,
    attempt: Annotated[int, Query(ge=1)],
) -> CheckpointDownload:
    """For the node that now holds the job: the checkpoint to resume from."""
    try:
        checkpoint = service.checkpoint_for_assignee(db, node, job_id, attempt)
    except service.CheckpointRejected as exc:
        db.rollback()
        raise HTTPException(exc.status_code, detail=exc.detail) from None
    db.commit()
    return CheckpointDownload(
        version=checkpoint.version,
        units_done=checkpoint.units_done,
        sha256=checkpoint.sha256,
        payload_b64=base64.b64encode(checkpoint.payload).decode("ascii"),
    )
