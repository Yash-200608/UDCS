from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from udcs_controller.auth.permissions import Role

USERNAME_PATTERN = r"^[a-z0-9][a-z0-9._-]{2,63}$"
MIN_PASSWORD_LENGTH = 12


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(_In):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    display_name: str
    role: Role
    is_active: bool
    created_at: datetime


class LoginResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 (OAuth token type)
    expires_at: datetime
    user: UserOut


class UserCreate(_In):
    username: str = Field(pattern=USERNAME_PATTERN)
    display_name: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=256)
    role: Role = Role.STUDENT


class UserUpdate(_In):
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    role: Role | None = None
    is_active: bool | None = None
