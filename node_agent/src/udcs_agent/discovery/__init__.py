"""Hardware discovery: produces a validated `HardwareInventory`."""

from __future__ import annotations

from udcs_agent import __version__
from udcs_agent.discovery import system
from udcs_agent.discovery.nvidia import Nvml
from udcs_shared.hardware import HardwareInventory


def collect_inventory(nvml: Nvml) -> HardwareInventory:
    nvml.ensure_started()
    gpus = nvml.gpu_inventory()
    error = nvml.error
    if error is None and not gpus:
        error = "NVML reported no NVIDIA GPUs"
    return HardwareInventory(
        agent_version=__version__,
        os=system.discover_os(),
        cpu=system.discover_cpu(),
        memory=system.discover_memory(),
        disks=system.discover_disks(),
        network_interfaces=system.discover_network_interfaces(),
        gpus=gpus,
        gpu_discovery_error=error,
    )
