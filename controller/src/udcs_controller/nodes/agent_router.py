"""Endpoints called by node agents."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request, Response, status

from udcs_controller.audit.models import ActorType
from udcs_controller.audit.service import record_event
from udcs_controller.core.request_context import Now, client_ip
from udcs_controller.database.session import DbSession
from udcs_controller.nodes import service
from udcs_controller.nodes.deps import CurrentNode
from udcs_shared.agent_api import (
    EnrollRequest,
    EnrollResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    InventoryUpdate,
    RotateCredentialResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agent", tags=["agent"])


@router.post("/enroll", response_model=EnrollResponse, status_code=status.HTTP_201_CREATED)
def enroll(body: EnrollRequest, request: Request, db: DbSession, now: Now) -> EnrollResponse:
    ip = client_ip(request)
    if not request.app.state.enroll_limiter.allow(f"enroll|{ip}"):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many enrollment attempts; try again later",
            headers={"Retry-After": "60"},
        )
    try:
        node, credential, token = service.enroll_node(db, body, now=now, client_ip=ip)
    except service.UnsupportedProtocol as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None
    except service.EnrollmentRejected:
        db.rollback()
        record_event(
            db,
            request,
            now=now,
            actor_type=ActorType.ANONYMOUS,
            action="node.enroll_rejected",
            details={"hostname": body.inventory.os.hostname},
        )
        db.commit()
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="invalid, expired or already-used enrollment token",
        ) from None

    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.NODE,
        actor_id=node.id,
        action="node.enrolled",
        target_type="node",
        target_id=str(node.id),
        details={
            "hostname": node.hostname,
            "enrollment_key_id": str(token.id),
            "lab": token.lab,
            "admin_state": node.admin_state.value,
            "gpu_count": len(body.inventory.gpus),
        },
    )
    db.commit()
    logger.info("node enrolled", extra={"node_id": str(node.id), "hostname": node.hostname})
    return EnrollResponse(
        node_id=node.id,
        node_credential=credential,
        heartbeat_interval_seconds=request.app.state.settings.heartbeat_interval_seconds,
        admin_state=node.admin_state,
    )


@router.post("/heartbeat", response_model=HeartbeatResponse)
def heartbeat(
    body: HeartbeatRequest, node: CurrentNode, request: Request, db: DbSession, now: Now
) -> HeartbeatResponse:
    try:
        response = service.record_heartbeat(
            db,
            node,
            body,
            now=now,
            client_ip=client_ip(request),
            settings=request.app.state.settings,
        )
    except service.UnsupportedProtocol as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc)) from None
    db.commit()
    return response


@router.put("/inventory", status_code=status.HTTP_204_NO_CONTENT)
def put_inventory(
    body: InventoryUpdate, node: CurrentNode, request: Request, db: DbSession, now: Now
) -> Response:
    changed = service.store_inventory(db, node, body.inventory, now=now)
    if changed:
        record_event(
            db,
            request,
            now=now,
            actor_type=ActorType.NODE,
            actor_id=node.id,
            action="node.inventory_changed",
            target_type="node",
            target_id=str(node.id),
            details={"gpu_count": len(body.inventory.gpus)},
        )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/credential/rotate", response_model=RotateCredentialResponse)
def rotate_credential(
    node: CurrentNode, request: Request, db: DbSession, now: Now
) -> RotateCredentialResponse:
    """Two-phase: the current credential keeps working until the new one is first used."""
    credential = service.begin_credential_rotation(node)
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.NODE,
        actor_id=node.id,
        action="node.credential_rotation_started",
        target_type="node",
        target_id=str(node.id),
    )
    db.commit()
    return RotateCredentialResponse(node_credential=credential)
