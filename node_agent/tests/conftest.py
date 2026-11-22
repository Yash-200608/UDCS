from __future__ import annotations

import types
from types import SimpleNamespace

import pytest

from udcs_shared.hardware import CpuInfo, HardwareInventory, MemoryInfo, OsInfo


class FakeNVMLError(Exception):
    pass


def _fake_pynvml(
    *, utilization_supported: bool = False, count_fails: bool = False, init_fails: bool = False
) -> types.ModuleType:
    """A stand-in for `pynvml` modelled on a real GeForce GT 730 (driver 456.71)."""
    module = types.ModuleType("pynvml")
    module.NVMLError = FakeNVMLError
    module.NVML_TEMPERATURE_GPU = 0

    def not_supported(*_args):
        raise FakeNVMLError("Not Supported")

    def init():
        if init_fails:
            raise FakeNVMLError("Driver Not Loaded")

    module.nvmlInit = init
    module.nvmlShutdown = lambda: None
    module.nvmlDeviceGetCount = not_supported if count_fails else (lambda: 1)
    module.nvmlDeviceGetHandleByIndex = lambda index: f"handle-{index}"
    module.nvmlDeviceGetName = lambda _h: b"GeForce GT 730"
    module.nvmlSystemGetDriverVersion = lambda: "456.71"
    module.nvmlSystemGetCudaDriverVersion = lambda: 11010
    module.nvmlDeviceGetMemoryInfo = lambda _h: SimpleNamespace(total=2 * 2**30, used=500 * 2**20)
    module.nvmlDeviceGetCudaComputeCapability = lambda _h: (3, 5)
    module.nvmlDeviceGetPciInfo = lambda _h: SimpleNamespace(busId=b"00000000:01:00.0")
    module.nvmlDeviceGetUUID = lambda _h: "GPU-90259302"
    module.nvmlDeviceGetUtilizationRates = (
        (lambda _h: SimpleNamespace(gpu=37)) if utilization_supported else not_supported
    )
    module.nvmlDeviceGetTemperature = lambda _h, _sensor: 52
    module.nvmlDeviceGetPowerUsage = not_supported
    return module


@pytest.fixture
def fake_pynvml():
    return _fake_pynvml


@pytest.fixture
def make_inventory():
    def _make(memory_gib: int = 16) -> HardwareInventory:
        return HardwareInventory(
            agent_version="0.1.0",
            os=OsInfo(system="Windows", release="11", version="10.0", hostname="lab-01"),
            cpu=CpuInfo(model="i5", architecture="AMD64", logical_cores=4),
            memory=MemoryInfo(total_bytes=memory_gib * 2**30),
        )

    return _make
