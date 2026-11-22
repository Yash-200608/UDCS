"""Controller configuration, read from `UDCS_*` environment variables.

There are deliberately no defaults for deployment-specific values (database
URL): a controller that silently starts against the wrong database is worse
than one that refuses to start.
"""

from __future__ import annotations

from datetime import timedelta

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from udcs_shared.agent_api import MAX_HEARTBEAT_SECONDS, MIN_HEARTBEAT_SECONDS


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="UDCS_", extra="ignore")

    database_url: str = Field(
        repr=False,
        description="SQLAlchemy URL, e.g. postgresql+psycopg://udcs@db-host/udcs",
    )
    heartbeat_interval_seconds: int = Field(
        default=15, ge=MIN_HEARTBEAT_SECONDS, le=MAX_HEARTBEAT_SECONDS
    )
    offline_after_missed_heartbeats: int = Field(default=3, ge=2, le=20)
    session_ttl_minutes: int = Field(default=12 * 60, ge=5, le=7 * 24 * 60)
    enrollment_key_max_ttl_minutes: int = Field(default=14 * 24 * 60, ge=5, le=90 * 24 * 60)
    enrollment_key_max_uses: int = Field(default=500, ge=1, le=100_000)
    node_credential_max_age_days: int = Field(default=30, ge=1, le=365)
    protection_policy_version: int = Field(default=1, ge=1)
    login_attempts_per_minute: int = Field(default=10, ge=1, le=10_000)
    enroll_attempts_per_minute: int = Field(default=10, ge=1, le=10_000)
    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR)$")
    log_json: bool = True

    @property
    def offline_after(self) -> timedelta:
        return timedelta(
            seconds=self.heartbeat_interval_seconds * self.offline_after_missed_heartbeats
        )

    @property
    def session_ttl(self) -> timedelta:
        return timedelta(minutes=self.session_ttl_minutes)
