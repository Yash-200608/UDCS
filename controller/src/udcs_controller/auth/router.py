from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select

from udcs_controller.audit.models import ActorType
from udcs_controller.audit.service import record_event
from udcs_controller.auth import service
from udcs_controller.auth.deps import AuthContext, CurrentAuth, require
from udcs_controller.auth.models import AuthSession, User
from udcs_controller.auth.permissions import Permission, Role
from udcs_controller.auth.schemas import (
    LoginRequest,
    LoginResponse,
    UserCreate,
    UserOut,
    UserUpdate,
)
from udcs_controller.core.request_context import Now, client_ip
from udcs_controller.database.session import DbSession

router = APIRouter(tags=["auth"])

UserAdmin = Annotated[AuthContext, Depends(require(Permission.MANAGE_USERS))]


@router.post("/auth/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request, db: DbSession, now: Now) -> LoginResponse:
    settings = request.app.state.settings
    username = service.normalize_username(body.username)
    if not request.app.state.login_limiter.allow(f"{client_ip(request)}|{username}"):
        record_event(
            db,
            request,
            now=now,
            actor_type=ActorType.ANONYMOUS,
            action="auth.login_rate_limited",
            details={"username": username[:64]},
        )
        db.commit()
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many login attempts; try again later",
            headers={"Retry-After": "60"},
        )

    user = service.authenticate(db, body.username, body.password)
    if user is None:
        record_event(
            db,
            request,
            now=now,
            actor_type=ActorType.ANONYMOUS,
            action="auth.login_failed",
            details={"username": username[:64]},
        )
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid username or password")

    auth_session, token = service.create_session(
        db, user, now=now, ttl=settings.session_ttl, client_ip=client_ip(request)
    )
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=user.id,
        action="auth.login_succeeded",
    )
    db.commit()
    return LoginResponse(
        access_token=token, expires_at=auth_session.expires_at, user=UserOut.model_validate(user)
    )


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(auth: CurrentAuth, request: Request, db: DbSession, now: Now) -> Response:
    auth_session = db.get(AuthSession, auth.session_id)
    if auth_session is not None and auth_session.revoked_at is None:
        auth_session.revoked_at = now
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="auth.logout",
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/auth/me", response_model=UserOut)
def me(auth: CurrentAuth) -> UserOut:
    return UserOut.model_validate(auth.user)


@router.post("/admin/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate, auth: UserAdmin, request: Request, db: DbSession, now: Now
) -> UserOut:
    try:
        user = service.create_user(
            db,
            username=body.username,
            display_name=body.display_name,
            password=body.password,
            role=body.role,
        )
    except service.UsernameTaken:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="username already exists") from None
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="user.created",
        target_type="user",
        target_id=str(user.id),
        details={"username": user.username, "role": user.role.value},
    )
    db.commit()
    return UserOut.model_validate(user)


@router.get("/admin/users", response_model=list[UserOut])
def list_users(auth: UserAdmin, db: DbSession) -> list[UserOut]:
    users = db.scalars(select(User).order_by(User.username)).all()
    return [UserOut.model_validate(u) for u in users]


@router.patch("/admin/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    auth: UserAdmin,
    request: Request,
    db: DbSession,
    now: Now,
) -> UserOut:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user not found")
    if user.id == auth.user.id and (
        (body.role is not None and body.role != Role.ADMIN) or body.is_active is False
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail="you cannot remove your own admin access"
        )
    changes = body.model_dump(exclude_none=True)
    for field, value in changes.items():
        setattr(user, field, value)
    if body.is_active is False:
        service.revoke_user_sessions(db, user.id, now=now)
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="user.updated",
        target_type="user",
        target_id=str(user.id),
        details={k: (v.value if isinstance(v, Role) else v) for k, v in changes.items()},
    )
    db.commit()
    return UserOut.model_validate(user)
