"""Point-in-time resource telemetry sent with every heartbeat."""

from __future__ import annotations

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from udcs_shared.protection import GpuUsageSplit, InteractiveState, ProtectionStatus, UsageSplit


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class GpuTelemetry(_Contract):
    index: int = Field(ge=0, le=255)
    utilization_percent: float | None = Field(default=None, ge=0, le=100)
    memory_used_bytes: int | None = Field(default=None, ge=0, le=1 << 44)
    memory_total_bytes: int | None = Field(default=None, ge=0, le=1 << 44)
    temperature_c: float | None = Field(default=None, ge=-50, le=150)
    power_watts: float | None = Field(default=None, ge=0, le=5000)


class ResourceUsage(_Contract):
    """Host usage split into UDCS-attributed and everything else.

    'non_udcs' covers the student *and* the OS and unrelated services; the agent
    never claims to know which of those it is.
    """

    cpu_percent: UsageSplit
    memory_bytes: UsageSplit
    disk_busy_percent: float | None = Field(
        default=None, ge=0, le=100, description="host-wide; not attributable"
    )
    udcs_disk_bytes_per_second: float = Field(default=0, ge=0)
    hard_faults_per_second: float | None = Field(default=None, ge=0)
    gpus: list[GpuUsageSplit] = Field(default_factory=list, max_length=16)


class TelemetrySnapshot(_Contract):
    collected_at: AwareDatetime = Field(description="Agent clock; informational only")
    cpu_percent: float = Field(ge=0, le=100, description="total host CPU")
    memory_total_bytes: int = Field(ge=0, le=1 << 50)
    memory_available_bytes: int = Field(ge=0, le=1 << 50)
    disk_free_bytes: int | None = Field(default=None, ge=0, le=1 << 60)
    uptime_seconds: float = Field(ge=0, le=10 * 365 * 86400)
    interactive_state: InteractiveState = Field(
        default=InteractiveState.ACTIVE,
        description="coarse presence only; raw input timing never leaves the machine",
    )
    usage: ResourceUsage | None = None
    protection: ProtectionStatus | None = None
    gpus: list[GpuTelemetry] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def _available_within_total(self) -> TelemetrySnapshot:
        if self.memory_available_bytes > self.memory_total_bytes:
            raise ValueError("memory_available_bytes exceeds memory_total_bytes")
        for gpu in self.gpus:
            if (
                gpu.memory_used_bytes is not None
                and gpu.memory_total_bytes is not None
                and gpu.memory_used_bytes > gpu.memory_total_bytes
            ):
                raise ValueError(f"gpu {gpu.index}: memory_used_bytes exceeds memory_total_bytes")
        return self
