from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from udcs_controller.audit.models import ActorType, AuditEvent
from udcs_controller.auth.deps import AuthContext, require
from udcs_controller.auth.permissions import Permission
from udcs_controller.database.session import DbSession

router = APIRouter(tags=["audit"])


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    actor_type: ActorType
    actor_id: uuid.UUID | None
    action: str
    target_type: str | None
    target_id: str | None
    details: dict[str, Any]
    client_ip: str | None
    request_id: str | None


@router.get("/admin/audit-events", response_model=list[AuditEventOut])
def list_audit_events(
    auth: Annotated[AuthContext, Depends(require(Permission.VIEW_AUDIT))],
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    action: Annotated[str | None, Query(max_length=64)] = None,
) -> list[AuditEventOut]:
    # The id tie-break makes the order deterministic across databases when timestamps are
    # equal. It is not chronological within a tie; a strict sequence column is a design
    # decision that is still open (see DEVELOPMENT_STATUS.md).
    query = (
        select(AuditEvent).order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(limit)
    )
    if action is not None:
        query = query.where(AuditEvent.action == action)
    return [AuditEventOut.model_validate(e) for e in db.scalars(query)]
