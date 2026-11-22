"""Agent-facing job endpoint: one reconciling round trip per sync."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from udcs_controller.core.request_context import Now
from udcs_controller.database.session import DbSession
from udcs_controller.jobs import service
from udcs_controller.nodes.deps import CurrentNode
from udcs_controller.nodes.service import UnsupportedProtocol
from udcs_shared.jobs import JobSyncRequest, JobSyncResponse

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
