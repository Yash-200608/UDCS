"""User-facing node registry, enrollment-key and capacity endpoints."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select

from udcs_controller.audit.models import ActorType
from udcs_controller.audit.service import record_event
from udcs_controller.auth.deps import AuthContext, require
from udcs_controller.auth.permissions import Permission
from udcs_controller.core.request_context import Now
from udcs_controller.database.session import DbSession
from udcs_controller.nodes import service
from udcs_controller.nodes.models import EnrollmentKey, Node
from udcs_controller.nodes.schemas import (
    EnrollmentKeyCreate,
    EnrollmentKeyCreated,
    EnrollmentKeyOut,
    NodeOut,
    NodeStateUpdate,
    NodeUserCodeUpdate,
    ResourceSummary,
)
from udcs_shared.exposure import ExposureReport

router = APIRouter(tags=["nodes"])

ViewNodes = Annotated[AuthContext, Depends(require(Permission.VIEW_NODES))]
ManageNodes = Annotated[AuthContext, Depends(require(Permission.MANAGE_NODES))]
ManageEnrollment = Annotated[AuthContext, Depends(require(Permission.MANAGE_ENROLLMENT))]


def _get_node(db: DbSession, node_id: uuid.UUID) -> Node:
    node = db.get(Node, node_id)
    if node is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="node not found")
    return node


@router.get("/resources/summary", response_model=ResourceSummary)
def resources_summary(
    auth: Annotated[AuthContext, Depends(require(Permission.VIEW_RESOURCE_SUMMARY))],
    request: Request,
    db: DbSession,
    now: Now,
) -> ResourceSummary:
    return service.resource_summary(db, now=now, settings=request.app.state.settings)


# -- lab-scoped enrollment keys -----------------------------------------------------------------


@router.post(
    "/admin/enrollment-keys",
    response_model=EnrollmentKeyCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_enrollment_key(
    body: EnrollmentKeyCreate, auth: ManageEnrollment, request: Request, db: DbSession, now: Now
) -> EnrollmentKeyCreated:
    settings = request.app.state.settings
    if body.ttl_minutes > settings.enrollment_key_max_ttl_minutes:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"ttl_minutes exceeds the configured maximum of "
            f"{settings.enrollment_key_max_ttl_minutes}",
        )
    if body.max_uses > settings.enrollment_key_max_uses:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"max_uses exceeds the configured maximum of {settings.enrollment_key_max_uses}",
        )
    record, secret = service.create_enrollment_key(
        db,
        created_by=auth.user,
        lab=body.lab,
        ttl=timedelta(minutes=body.ttl_minutes),
        max_uses=body.max_uses,
        auto_approve=body.auto_approve,
        note=body.note,
        now=now,
    )
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="enrollment_key.created",
        target_type="enrollment_key",
        target_id=str(record.id),
        details={
            "lab": body.lab,
            "ttl_minutes": body.ttl_minutes,
            "max_uses": body.max_uses,
            "auto_approve": body.auto_approve,
        },
    )
    db.commit()
    return EnrollmentKeyCreated(**EnrollmentKeyOut.model_validate(record).model_dump(), key=secret)


@router.get("/admin/enrollment-keys", response_model=list[EnrollmentKeyOut])
def list_enrollment_keys(auth: ManageEnrollment, db: DbSession) -> list[EnrollmentKeyOut]:
    keys = db.scalars(select(EnrollmentKey).order_by(EnrollmentKey.created_at.desc())).all()
    return [EnrollmentKeyOut.model_validate(k) for k in keys]


@router.post("/admin/enrollment-keys/{key_id}/revoke", response_model=EnrollmentKeyOut)
def revoke_enrollment_key(
    key_id: uuid.UUID, auth: ManageEnrollment, request: Request, db: DbSession, now: Now
) -> EnrollmentKeyOut:
    key = db.get(EnrollmentKey, key_id)
    if key is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="enrollment key not found")
    service.revoke_enrollment_key(key, now=now)
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="enrollment_key.revoked",
        target_type="enrollment_key",
        target_id=str(key.id),
        details={"lab": key.lab},
    )
    db.commit()
    return EnrollmentKeyOut.model_validate(key)


# -- nodes -------------------------------------------------------------------------------------


@router.get("/admin/nodes", response_model=list[NodeOut])
def list_nodes(auth: ViewNodes, request: Request, db: DbSession, now: Now) -> list[NodeOut]:
    settings = request.app.state.settings
    nodes = db.scalars(select(Node).order_by(Node.name)).all()
    return [service.to_out(n, now=now, settings=settings) for n in nodes]


@router.get("/admin/nodes/{node_id}", response_model=NodeOut)
def get_node(
    node_id: uuid.UUID, auth: ViewNodes, request: Request, db: DbSession, now: Now
) -> NodeOut:
    return service.to_out(_get_node(db, node_id), now=now, settings=request.app.state.settings)


@router.post("/admin/nodes/{node_id}/approve", response_model=NodeOut)
def approve_node(
    node_id: uuid.UUID, auth: ManageNodes, request: Request, db: DbSession, now: Now
) -> NodeOut:
    node = _get_node(db, node_id)
    try:
        service.approve_node(node, approver=auth.user, now=now)
    except service.InvalidStateTransition as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="node.approved",
        target_type="node",
        target_id=str(node.id),
        details={"lab": node.lab, "hostname": node.hostname},
    )
    db.commit()
    return service.to_out(node, now=now, settings=request.app.state.settings)


@router.post("/admin/nodes/{node_id}/state", response_model=NodeOut)
def set_node_state(
    node_id: uuid.UUID,
    body: NodeStateUpdate,
    auth: ManageNodes,
    request: Request,
    db: DbSession,
    now: Now,
) -> NodeOut:
    node = _get_node(db, node_id)
    previous = node.admin_state
    try:
        service.set_admin_state(node, body.admin_state)
    except service.InvalidStateTransition as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc)) from None
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="node.state_changed",
        target_type="node",
        target_id=str(node.id),
        details={"from": previous.value, "to": body.admin_state.value},
    )
    db.commit()
    return service.to_out(node, now=now, settings=request.app.state.settings)


@router.post("/admin/nodes/{node_id}/exposure-audits", status_code=status.HTTP_201_CREATED)
def upload_exposure_audit(
    node_id: uuid.UUID,
    body: ExposureReport,
    auth: ManageNodes,
    request: Request,
    db: DbSession,
    now: Now,
) -> dict:
    """Record an AppContainer exposure report for this node (ADR 0003 procedure, step 2).
    The controller judges it again; the report's own verdict is not used."""
    node = _get_node(db, node_id)
    try:
        audit = service.record_exposure_audit(db, node, body, by=auth.user, now=now)
    except service.EligibilityRefused as exc:
        raise HTTPException(exc.status_code, detail=exc.detail) from None
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="node.exposure_audit_recorded",
        target_type="node",
        target_id=str(node.id),
        details={
            "audit_id": str(audit.id),
            "sha256": audit.sha256,
            "passed": audit.passed,
            "image": audit.image,
            "runner": audit.runner,
            "violations": audit.summary.get("violation_count", 0),
        },
    )
    db.commit()
    return {"id": str(audit.id), "sha256": audit.sha256, **audit.summary}


@router.get("/admin/nodes/{node_id}/exposure-audits")
def list_exposure_audits(node_id: uuid.UUID, auth: ManageNodes, db: DbSession) -> list[dict]:
    from sqlalchemy import select

    from udcs_controller.nodes.models import NodeExposureAudit

    _get_node(db, node_id)
    rows = db.scalars(
        select(NodeExposureAudit)
        .where(NodeExposureAudit.node_id == node_id)
        .order_by(NodeExposureAudit.uploaded_at.desc())
        .limit(50)
    )
    return [
        {
            "id": str(a.id),
            "sha256": a.sha256,
            "uploaded_at": a.uploaded_at.isoformat(),
            "generated_at": a.generated_at.isoformat(),
            **a.summary,
        }
        for a in rows
    ]


@router.post("/admin/nodes/{node_id}/user-code", response_model=NodeOut)
def set_node_user_code(
    node_id: uuid.UUID,
    body: NodeUserCodeUpdate,
    auth: ManageNodes,
    request: Request,
    db: DbSession,
    now: Now,
) -> NodeOut:
    """Grant or revoke user-code eligibility (ADR 0003 procedure). A grant needs an
    ACTIVE node, a verified AppContainer and a passing, recent, SYSTEM-context exposure
    audit of the node's current OS image; it is then bound to that image. A revoke is
    always accepted and takes effect at the node's next sync (running package jobs are
    requeued elsewhere and the node is told to cancel). Both are audited with a reason."""
    node = _get_node(db, node_id)
    previous = node.user_code_allowed
    details: dict = {"from": previous, "to": body.allowed, "reason": body.reason}
    if body.allowed:
        try:
            audit = service.grant_user_code(
                db, node, by=auth.user, now=now, settings=request.app.state.settings
            )
        except service.EligibilityRefused as exc:
            record_event(
                db,
                request,
                now=now,
                actor_type=ActorType.USER,
                actor_id=auth.user.id,
                action="node.user_code_refused",
                target_type="node",
                target_id=str(node.id),
                details={**details, "refused": exc.detail},
            )
            db.commit()
            raise HTTPException(exc.status_code, detail=exc.detail) from None
        details.update(
            audit_id=str(audit.id), audit_sha256=audit.sha256, image=node.user_code_image
        )
    else:
        service.revoke_user_code(node)
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="node.user_code_changed",
        target_type="node",
        target_id=str(node.id),
        details=details,
    )
    db.commit()
    return service.to_out(node, now=now, settings=request.app.state.settings)


@router.post("/admin/nodes/{node_id}/revoke", response_model=NodeOut)
def revoke_node(
    node_id: uuid.UUID, auth: ManageNodes, request: Request, db: DbSession, now: Now
) -> NodeOut:
    node = _get_node(db, node_id)
    service.revoke_node(node, now=now)
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="node.revoked",
        target_type="node",
        target_id=str(node.id),
    )
    db.commit()
    return service.to_out(node, now=now, settings=request.app.state.settings)
