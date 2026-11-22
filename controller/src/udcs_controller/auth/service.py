"""User and session business logic. Callers own the transaction (commit)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from udcs_controller.auth.models import AuthSession, User
from udcs_controller.auth.permissions import Role
from udcs_controller.core import security
from udcs_shared.agent_api import SESSION_TOKEN_PREFIX


class UsernameTaken(Exception):
    pass


def normalize_username(username: str) -> str:
    return username.strip().lower()


def create_user(
    db: Session, *, username: str, display_name: str, password: str, role: Role
) -> User:
    username = normalize_username(username)
    if db.scalar(select(User.id).where(User.username == username)) is not None:
        raise UsernameTaken(username)
    user = User(
        username=username,
        display_name=display_name,
        password_hash=security.hash_password(password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.flush()
    return user


def authenticate(db: Session, username: str, password: str) -> User | None:
    user = db.scalar(select(User).where(User.username == normalize_username(username)))
    if user is None:
        security.burn_password_check(password)
        return None
    if not security.verify_password(user.password_hash, password):
        return None
    if not user.is_active:
        return None
    if security.password_needs_rehash(user.password_hash):
        user.password_hash = security.hash_password(password)
    return user


def create_session(
    db: Session, user: User, *, now: datetime, ttl: timedelta, client_ip: str | None
) -> tuple[AuthSession, str]:
    token = security.generate_token(SESSION_TOKEN_PREFIX)
    auth_session = AuthSession(
        user_id=user.id,
        token_hash=security.hash_token(token),
        created_at=now,
        expires_at=now + ttl,
        client_ip=client_ip,
    )
    db.add(auth_session)
    db.flush()
    return auth_session, token


def resolve_session(db: Session, token: str, *, now: datetime) -> tuple[AuthSession, User] | None:
    if not token.startswith(SESSION_TOKEN_PREFIX):
        return None
    auth_session = db.scalar(
        select(AuthSession).where(AuthSession.token_hash == security.hash_token(token))
    )
    if auth_session is None or auth_session.revoked_at is not None:
        return None
    if auth_session.expires_at <= now:
        return None
    user = db.get(User, auth_session.user_id)
    if user is None or not user.is_active:
        return None
    return auth_session, user


def revoke_user_sessions(db: Session, user_id: uuid.UUID, *, now: datetime) -> None:
    db.execute(
        update(AuthSession)
        .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=now)
    )
