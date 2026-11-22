"""Authentication for agent-facing routes (node credentials only)."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from udcs_controller.audit.models import ActorType
from udcs_controller.audit.service import record_event
from udcs_controller.auth.deps import BearerCredentials, unauthorized
from udcs_controller.core.request_context import Now
from udcs_controller.database.session import DbSession
from udcs_controller.nodes.models import Node
from udcs_controller.nodes.service import authenticate_node
from udcs_shared.agent_api import NodeAdminState


def get_current_node(
    credentials: BearerCredentials, request: Request, db: DbSession, now: Now
) -> Node:
    if credentials is None:
        raise unauthorized()
    result = authenticate_node(db, credentials.credentials, now=now)
    if result is None:
        raise unauthorized("invalid node credential")
    node, rotated = result
    if node.admin_state == NodeAdminState.REVOKED:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="node has been revoked")
    if rotated:
        # The previous credential stops working from this moment.
        record_event(
            db,
            request,
            now=now,
            actor_type=ActorType.NODE,
            actor_id=node.id,
            action="node.credential_rotated",
            target_type="node",
            target_id=str(node.id),
        )
        db.commit()
    return node


CurrentNode = Annotated[Node, Depends(get_current_node)]
