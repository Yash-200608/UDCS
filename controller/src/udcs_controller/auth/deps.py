"""Authentication and authorization dependencies for user-facing routes."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from udcs_controller.auth.models import User
from udcs_controller.auth.permissions import Permission, has_permission
from udcs_controller.auth.service import resolve_session
from udcs_controller.core.request_context import Now
from udcs_controller.database.session import DbSession

bearer_scheme = HTTPBearer(auto_error=False)
BearerCredentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)]


@dataclass(frozen=True)
class AuthContext:
    user: User
    session_id: uuid.UUID


def unauthorized(detail: str = "not authenticated") -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, detail=detail, headers={"WWW-Authenticate": "Bearer"}
    )


def get_auth_context(credentials: BearerCredentials, db: DbSession, now: Now) -> AuthContext:
    if credentials is None:
        raise unauthorized()
    resolved = resolve_session(db, credentials.credentials, now=now)
    if resolved is None:
        raise unauthorized("invalid or expired session")
    auth_session, user = resolved
    return AuthContext(user=user, session_id=auth_session.id)


CurrentAuth = Annotated[AuthContext, Depends(get_auth_context)]


def require(permission: Permission) -> Callable[[AuthContext], AuthContext]:
    """Route dependency: authenticated *and* holding `permission`."""

    def dependency(auth: CurrentAuth) -> AuthContext:
        if not has_permission(auth.user.role, permission):
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="insufficient permissions")
        return auth

    return dependency
