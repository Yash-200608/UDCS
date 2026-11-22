"""Per-heartbeat resource telemetry."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import psutil

from udcs_agent.discovery.nvidia import Nvml
from udcs_shared.protection import InteractiveState, ProtectionStatus
from udcs_shared.telemetry import ResourceUsage, TelemetrySnapshot

GovernorView = Callable[[], tuple[InteractiveState, ResourceUsage | None, ProtectionStatus | None]]


class TelemetryCollector:
    def __init__(
        self,
        nvml: Nvml,
        disk_path: Path,
        *,
        governor: GovernorView | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._nvml = nvml
        self._disk_path = disk_path
        self._governor = governor
        self._clock = clock
        # psutil measures CPU% since the previous call; the first call is meaningless.
        psutil.cpu_percent(interval=None)

    def collect(self) -> TelemetrySnapshot:
        interactive, usage, protection = (
            self._governor() if self._governor else (InteractiveState.ACTIVE, None, None)
        )
        memory = psutil.virtual_memory()
        try:
            disk_free: int | None = psutil.disk_usage(str(self._disk_path)).free
        except OSError:
            disk_free = None
        return TelemetrySnapshot(
            collected_at=self._clock(),
            cpu_percent=min(100.0, max(0.0, psutil.cpu_percent(interval=None))),
            memory_total_bytes=memory.total,
            memory_available_bytes=min(memory.available, memory.total),
            disk_free_bytes=disk_free,
            uptime_seconds=max(0.0, time.time() - psutil.boot_time()),
            interactive_state=interactive,
            usage=usage,
            protection=protection,
            gpus=self._nvml.gpu_telemetry(),
        )
