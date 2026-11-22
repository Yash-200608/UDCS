from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from udcs_shared.agent_api import HeartbeatRequest
from udcs_shared.hardware import CpuInfo, GpuInfo, HardwareInventory, MemoryInfo, OsInfo
from udcs_shared.telemetry import GpuTelemetry, TelemetrySnapshot


def _inventory(**overrides) -> HardwareInventory:
    fields = {
        "agent_version": "0.1.0",
        "os": OsInfo(system="Windows", release="11", version="10.0.22000", hostname="lab-01"),
        "cpu": CpuInfo(model="i5", architecture="AMD64", physical_cores=4, logical_cores=4),
        "memory": MemoryInfo(total_bytes=16 * 2**30),
        "gpus": [GpuInfo(index=0, vendor="nvidia", name="GT 730", compute_capability="3.5")],
    }
    fields.update(overrides)
    return HardwareInventory(**fields)


def test_fingerprint_is_stable_and_content_sensitive():
    assert _inventory().fingerprint() == _inventory().fingerprint()
    assert _inventory().fingerprint() != _inventory(memory=MemoryInfo(total_bytes=1)).fingerprint()


def test_fingerprint_survives_json_round_trip():
    inv = _inventory()
    assert (
        HardwareInventory.model_validate_json(inv.model_dump_json()).fingerprint()
        == inv.fingerprint()
    )


def test_unknown_fields_are_rejected():
    with pytest.raises(ValidationError):
        HardwareInventory.model_validate({**_inventory().model_dump(), "is_admin": True})


def test_compute_capability_format_enforced():
    with pytest.raises(ValidationError):
        GpuInfo(index=0, vendor="nvidia", name="x", compute_capability="sm_86")


def _telemetry(**overrides) -> TelemetrySnapshot:
    fields = {
        "collected_at": datetime(2026, 1, 1, tzinfo=UTC),
        "cpu_percent": 10.0,
        "memory_total_bytes": 100,
        "memory_available_bytes": 50,
        "uptime_seconds": 1.0,
    }
    fields.update(overrides)
    return TelemetrySnapshot(**fields)


@pytest.mark.parametrize(
    "overrides",
    [
        {"cpu_percent": 101},
        {"cpu_percent": -1},
        {"memory_available_bytes": 101},
        {"collected_at": datetime(2026, 1, 1)},  # naive timestamps are rejected
        {"gpus": [GpuTelemetry(index=0, memory_used_bytes=2, memory_total_bytes=1)]},
    ],
)
def test_telemetry_bounds(overrides):
    with pytest.raises(ValidationError):
        _telemetry(**overrides)


def test_heartbeat_requires_hex_fingerprint():
    with pytest.raises(ValidationError):
        HeartbeatRequest(protocol_version=1, telemetry=_telemetry(), inventory_fingerprint="abc")
