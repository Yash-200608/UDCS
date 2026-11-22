"""OS, CPU, memory, disk and network discovery (psutil + platform APIs)."""

from __future__ import annotations

import logging
import platform
import socket
import sys
from pathlib import Path

import psutil

from udcs_shared.hardware import CpuInfo, DiskInfo, MemoryInfo, NetworkInterfaceInfo, OsInfo

logger = logging.getLogger(__name__)

_MAX_DISKS = 64
_MAX_INTERFACES = 64


def _clip(value: str, limit: int) -> str:
    return value[:limit]


def discover_os() -> OsInfo:
    return OsInfo(
        system=_clip(platform.system() or "unknown", 64),
        release=_clip(platform.release() or "unknown", 64),
        version=_clip(platform.version() or "unknown", 256),
        hostname=_clip(socket.gethostname() or "unknown", 255),
    )


def _cpu_model() -> str:
    if sys.platform == "win32":
        try:
            import winreg

            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            )
            with key:
                value, _ = winreg.QueryValueEx(key, "ProcessorNameString")
                return str(value).strip()
        except OSError:
            logger.debug("CPU model not readable from registry", exc_info=True)
    elif sys.platform.startswith("linux"):
        try:
            for line in Path("/proc/cpuinfo").read_text().splitlines():
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
        except OSError:
            logger.debug("/proc/cpuinfo not readable", exc_info=True)
    return platform.processor() or "unknown"


def discover_cpu() -> CpuInfo:
    freq = psutil.cpu_freq()
    max_mhz = freq.max if freq and freq.max else (freq.current if freq and freq.current else None)
    return CpuInfo(
        model=_clip(_cpu_model(), 256),
        architecture=_clip(platform.machine() or "unknown", 64),
        physical_cores=psutil.cpu_count(logical=False),
        logical_cores=psutil.cpu_count(logical=True) or 1,
        max_frequency_mhz=max_mhz,
    )


def discover_memory() -> MemoryInfo:
    return MemoryInfo(total_bytes=psutil.virtual_memory().total)


def discover_disks() -> list[DiskInfo]:
    disks: list[DiskInfo] = []
    for partition in psutil.disk_partitions(all=False):
        if not partition.fstype or "cdrom" in partition.opts:
            continue
        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except OSError:  # e.g. card reader with no media
            continue
        disks.append(
            DiskInfo(
                mountpoint=_clip(partition.mountpoint, 512),
                filesystem=_clip(partition.fstype, 64),
                total_bytes=usage.total,
            )
        )
        if len(disks) >= _MAX_DISKS:
            break
    return disks


def discover_network_interfaces() -> list[NetworkInterfaceInfo]:
    stats = psutil.net_if_stats()
    addresses = psutil.net_if_addrs()
    interfaces: list[NetworkInterfaceInfo] = []
    for name, stat in stats.items():
        ipv4 = [a.address for a in addresses.get(name, []) if a.family == socket.AF_INET]
        if "loopback" in name.lower() or (ipv4 and all(ip.startswith("127.") for ip in ipv4)):
            continue
        interfaces.append(
            NetworkInterfaceInfo(
                name=_clip(name, 256),
                is_up=stat.isup,
                speed_mbps=stat.speed or None,
                mtu=stat.mtu or None,
                ipv4_addresses=ipv4[:16],
            )
        )
        if len(interfaces) >= _MAX_INTERFACES:
            break
    return interfaces
