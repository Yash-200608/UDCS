from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from udcs_controller.audit.models import ActorType, AuditEvent
from udcs_controller.core.request_context import client_ip
from udcs_shared.logs import request_id_var


def record_event(
    db: Session,
    request: Request | None,
    *,
    now: datetime,
    actor_type: ActorType,
    action: str,
    actor_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Add an audit event to the current transaction. Never put secrets in `details`."""
    event = AuditEvent(
        created_at=now,
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details or {},
        client_ip=client_ip(request) if request is not None else None,
        request_id=request_id_var.get(),
    )
    db.add(event)
    return event
