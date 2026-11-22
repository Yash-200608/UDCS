"""Request/response contracts for the agent-facing controller API.

Protocol version 2 (Milestone 1.5): split host/UDCS telemetry, coarse
interactive state, controller-supplied protection policy, pending-node
approval, lab-scoped enrollment keys and node credential rotation.
"""

from __future__ import annotations

from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from udcs_shared.hardware import HardwareInventory
from udcs_shared.protection import ProtectionPolicy
from udcs_shared.telemetry import TelemetrySnapshot

PROTOCOL_VERSION = 2

ENROLLMENT_KEY_PREFIX = "udcs_e_"
ENROLLMENT_TOKEN_PREFIX = ENROLLMENT_KEY_PREFIX  # backwards-compatible name
NODE_CREDENTIAL_PREFIX = "udcs_n_"
SESSION_TOKEN_PREFIX = "udcs_s_"  # noqa: S105 (prefix, not a secret)

MIN_HEARTBEAT_SECONDS = 5
MAX_HEARTBEAT_SECONDS = 300


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class NodeAdminState(StrEnum):
    PENDING = "pending"  # enrolled with a lab key, awaiting admin approval: never schedulable
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    REVOKED = "revoked"


class EnrollRequest(_Contract):
    enrollment_token: str = Field(
        min_length=20, max_length=200, description="a lab-scoped enrollment key"
    )
    protocol_version: int = Field(ge=1, le=1000)
    inventory: HardwareInventory
    requested_name: str | None = Field(default=None, min_length=1, max_length=128)


class EnrollResponse(_Contract):
    node_id: UUID
    node_credential: str = Field(
        min_length=20, max_length=200, description="unique to this node; the enrollment key is not"
    )
    heartbeat_interval_seconds: int = Field(ge=MIN_HEARTBEAT_SECONDS, le=MAX_HEARTBEAT_SECONDS)
    admin_state: NodeAdminState = NodeAdminState.ACTIVE


class HeartbeatRequest(_Contract):
    protocol_version: int = Field(ge=1, le=1000)
    telemetry: TelemetrySnapshot
    inventory_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class HeartbeatResponse(_Contract):
    heartbeat_interval_seconds: int = Field(ge=MIN_HEARTBEAT_SECONDS, le=MAX_HEARTBEAT_SECONDS)
    inventory_required: bool
    admin_state: NodeAdminState
    protection_policy: ProtectionPolicy | None = Field(
        default=None, description="merged with the agent's local floor; the stricter value wins"
    )
    rotate_credential: bool = Field(default=False, description="controller asks for rotation")


class InventoryUpdate(_Contract):
    inventory: HardwareInventory


class RotateCredentialResponse(_Contract):
    """The new credential becomes the only valid one on its first successful use."""

    node_credential: str = Field(min_length=20, max_length=200)
