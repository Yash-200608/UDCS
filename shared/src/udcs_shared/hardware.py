"""Hardware inventory reported by a node agent.

Inventory is relatively static (it changes when hardware or drivers change),
so it is sent on startup and whenever its fingerprint changes, not on every
heartbeat. GPU fields are optional because NVML legitimately reports
"Not Supported" for many fields on consumer cards.
"""

from __future__ import annotations

import hashlib
import json
from ipaddress import IPv4Address

from pydantic import BaseModel, ConfigDict, Field


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class OsInfo(_Contract):
    system: str = Field(max_length=64, description="e.g. 'Windows', 'Linux'")
    release: str = Field(max_length=64)
    version: str = Field(max_length=256)
    hostname: str = Field(max_length=255)


class CpuInfo(_Contract):
    model: str = Field(max_length=256)
    architecture: str = Field(max_length=64)
    physical_cores: int | None = Field(default=None, ge=1, le=4096)
    logical_cores: int = Field(ge=1, le=8192)
    max_frequency_mhz: float | None = Field(default=None, gt=0, le=20_000)


class MemoryInfo(_Contract):
    total_bytes: int = Field(ge=0, le=1 << 50)


class DiskInfo(_Contract):
    mountpoint: str = Field(max_length=512)
    filesystem: str = Field(max_length=64)
    total_bytes: int = Field(ge=0, le=1 << 60)


class NetworkInterfaceInfo(_Contract):
    name: str = Field(max_length=256)
    is_up: bool
    speed_mbps: int | None = Field(default=None, ge=1, le=10_000_000)
    mtu: int | None = Field(default=None, ge=1, le=1 << 20)
    ipv4_addresses: list[IPv4Address] = Field(default_factory=list, max_length=16)


class GpuInfo(_Contract):
    index: int = Field(ge=0, le=255)
    vendor: str = Field(max_length=32, description="Currently always 'nvidia'")
    name: str = Field(max_length=256)
    uuid: str | None = Field(default=None, max_length=128)
    pci_bus_id: str | None = Field(default=None, max_length=64)
    memory_total_bytes: int | None = Field(default=None, ge=0, le=1 << 44)
    compute_capability: str | None = Field(
        default=None, pattern=r"^\d{1,2}\.\d{1,2}$", description="CUDA compute capability"
    )
    driver_version: str | None = Field(default=None, max_length=32)
    cuda_driver_version: str | None = Field(
        default=None,
        pattern=r"^\d{1,3}\.\d{1,3}$",
        description="Max CUDA version the driver supports",
    )


class HardwareInventory(_Contract):
    agent_version: str = Field(max_length=32)
    os: OsInfo
    cpu: CpuInfo
    memory: MemoryInfo
    disks: list[DiskInfo] = Field(default_factory=list, max_length=64)
    network_interfaces: list[NetworkInterfaceInfo] = Field(default_factory=list, max_length=64)
    gpus: list[GpuInfo] = Field(default_factory=list, max_length=32)
    gpu_discovery_error: str | None = Field(
        default=None,
        max_length=512,
        description="Why GPU discovery failed or found nothing, if it did (e.g. NVML missing)",
    )

    def fingerprint(self) -> str:
        """Stable SHA-256 over the canonical JSON form.

        Both sides compute this independently; the controller never trusts a
        fingerprint it did not compute itself.
        """
        canonical = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()
