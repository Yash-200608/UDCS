from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from udcs_shared.agent_api import NodeAdminState
from udcs_shared.hardware import HardwareInventory
from udcs_shared.telemetry import TelemetrySnapshot


class Connectivity(StrEnum):
    ONLINE = "online"
    OFFLINE = "offline"


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


LAB_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$"


class EnrollmentKeyCreate(_In):
    lab: str = Field(pattern=LAB_PATTERN, description="e.g. 'CS Lab B'")
    ttl_minutes: int = Field(default=24 * 60, ge=5, le=90 * 24 * 60)
    max_uses: int = Field(default=50, ge=1, le=100_000)
    auto_approve: bool = Field(default=False, description="skip pending approval for this key")
    note: str = Field(default="", max_length=256)


class EnrollmentKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    lab: str
    note: str
    created_at: datetime
    expires_at: datetime
    max_uses: int
    use_count: int
    auto_approve: bool
    revoked_at: datetime | None
    last_used_at: datetime | None


class EnrollmentKeyCreated(EnrollmentKeyOut):
    key: str = Field(description="Shown once; only its hash is stored")


class NodeStateUpdate(_In):
    admin_state: Literal[NodeAdminState.ACTIVE, NodeAdminState.MAINTENANCE]


class NodeOut(BaseModel):
    id: uuid.UUID
    name: str
    hostname: str
    lab: str
    admin_state: NodeAdminState
    connectivity: Connectivity
    schedulable: bool = Field(description="active and online")
    enrolled_at: datetime
    approved_at: datetime | None
    revoked_at: datetime | None
    credential_issued_at: datetime
    credential_rotation_pending: bool
    last_heartbeat_at: datetime | None
    last_seen_ip: str | None
    agent_version: str
    protocol_version: int
    inventory: HardwareInventory | None
    inventory_updated_at: datetime | None
    latest_telemetry: TelemetrySnapshot | None
    user_code_allowed: bool = Field(
        default=False, description="administrator-set eligibility to run user packages"
    )
    user_code_ready: bool = Field(
        default=False, description="eligible AND reports a verified AppContainer"
    )


class NodeUserCodeUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str = Field(min_length=3, max_length=200, description="recorded in the audit log")


class GpuModelSummary(BaseModel):
    name: str
    memory_total_bytes: int | None
    compute_capability: str | None
    count: int


class ResourceSummary(BaseModel):
    generated_at: datetime
    online_nodes: int
    offline_nodes: int
    maintenance_nodes: int
    pending_nodes: int
    total_logical_cores: int
    total_memory_bytes: int
    available_memory_bytes: int
    gpu_count: int
    gpu_memory_total_bytes: int
    gpu_models: list[GpuModelSummary]
