import shutil
import subprocess
from pathlib import Path

import psutil
import pytest

from udcs_agent.discovery import collect_inventory
from udcs_agent.discovery.nvidia import Nvml
from udcs_agent.monitoring.telemetry import TelemetryCollector


def _loader(module):
    return lambda: module


def test_unsupported_nvml_fields_become_none(fake_pynvml):
    nvml = Nvml(loader=_loader(fake_pynvml(utilization_supported=False)))
    nvml.ensure_started()
    [gpu] = nvml.gpu_inventory()
    assert gpu.name == "GeForce GT 730"
    assert gpu.compute_capability == "3.5"
    assert gpu.cuda_driver_version == "11.1"
    assert gpu.memory_total_bytes == 2 * 2**30
    [sample] = nvml.gpu_telemetry()
    assert sample.utilization_percent is None and sample.power_watts is None
    assert sample.temperature_c == 52.0 and sample.memory_used_bytes == 500 * 2**20


def test_supported_utilization_is_reported(fake_pynvml):
    nvml = Nvml(loader=_loader(fake_pynvml(utilization_supported=True)))
    nvml.ensure_started()
    assert nvml.gpu_telemetry()[0].utilization_percent == 37.0


def test_missing_binding_yields_cpu_only_inventory():
    def missing():
        raise ImportError("no pynvml")

    nvml = Nvml(loader=missing)
    inventory = collect_inventory(nvml)
    assert inventory.gpus == []
    assert inventory.gpu_discovery_error == "nvidia-ml-py is not installed"


def test_driver_not_loaded_is_reported_not_raised(fake_pynvml):
    nvml = Nvml(loader=_loader(fake_pynvml(init_fails=True)))
    inventory = collect_inventory(nvml)
    assert inventory.gpus == []
    assert "Driver Not Loaded" in inventory.gpu_discovery_error


def test_nvml_failure_mid_run_triggers_reinit(fake_pynvml):
    broken = fake_pynvml(count_fails=True)
    modules = iter([broken, fake_pynvml()])
    nvml = Nvml(loader=lambda: next(modules))
    nvml.ensure_started()
    assert nvml.gpu_telemetry() == []
    assert not nvml.available and nvml.error == "NVML stopped responding"
    nvml.ensure_started()
    assert len(nvml.gpu_inventory()) == 1


@pytest.mark.hardware
def test_real_machine_inventory():
    with Nvml() as nvml:
        inventory = collect_inventory(nvml)
        again = collect_inventory(nvml)
    assert inventory.cpu.logical_cores == psutil.cpu_count(logical=True)
    assert inventory.memory.total_bytes == psutil.virtual_memory().total
    assert inventory.disks, "expected at least one disk"
    assert inventory.fingerprint() == again.fingerprint()

    smi = shutil.which("nvidia-smi")
    if smi:
        names = subprocess.run(  # noqa: S603  (fixed argv, no shell)
            [smi, "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout.split("\n")
        assert [g.name for g in inventory.gpus] == [n.strip() for n in names if n.strip()]
    else:
        assert inventory.gpus == [] and inventory.gpu_discovery_error


@pytest.mark.hardware
def test_real_machine_telemetry(tmp_path: Path):
    with Nvml() as nvml:
        snapshot = TelemetryCollector(nvml, tmp_path).collect()
        gpu_count = len(nvml.gpu_inventory())
    assert 0 < snapshot.memory_available_bytes <= snapshot.memory_total_bytes
    assert snapshot.disk_free_bytes and snapshot.disk_free_bytes > 0
    assert len(snapshot.gpus) == gpu_count


def test_binding_newer_than_driver_is_treated_as_unsupported(fake_pynvml):
    """nvidia-ml-py raises NVMLLibraryMismatchError (not an NVMLError subclass) on old drivers."""
    module = fake_pynvml()

    class NVMLLibraryMismatchError(Exception):
        pass

    def mismatch(*_args):
        raise NVMLLibraryMismatchError("binding newer than nvml.dll")

    module.NVMLLibraryMismatchError = NVMLLibraryMismatchError
    module.nvmlDeviceGetMemoryInfo = mismatch
    nvml = Nvml(loader=_loader(module))
    nvml.ensure_started()
    [gpu] = nvml.gpu_inventory()
    assert gpu.memory_total_bytes is None and gpu.name == "GeForce GT 730"


@pytest.mark.hardware
def test_real_driver_mismatching_calls_do_not_crash():
    with Nvml() as nvml:
        if not nvml.available:
            pytest.skip("no NVIDIA driver on this machine")
        handle = nvml._handles()[0][1]
        # Raised NVMLLibraryMismatchError on driver 456.71 before the fix.
        nvml._call("nvmlDeviceGetComputeRunningProcesses", handle)
