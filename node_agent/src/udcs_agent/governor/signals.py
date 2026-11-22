"""Collect one assessment's signals and split host usage into UDCS vs non-UDCS.

UDCS-attributed = every process in a UDCS job + the agent itself. Everything
else is 'non_udcs' -- the student, but also Windows and unrelated services.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable

import psutil

from udcs_agent.governor.classifier import Signals
from udcs_agent.winplat import IS_WINDOWS
from udcs_agent.workloads.manager import UdcsUsage
from udcs_shared.protection import GpuUsageSplit, InteractiveState, UsageSplit
from udcs_shared.telemetry import ResourceUsage

logger = logging.getLogger(__name__)

_COUNTERS = {
    "gpu_engine": r"\GPU Engine(*)\Utilization Percentage",
    "gpu_memory": r"\GPU Process Memory(*)\Dedicated Usage",
    "disk_idle": r"\PhysicalDisk(_Total)\% Idle Time",
    "page_inputs": r"\Memory\Pages Input/sec",
}


class SignalCollector:
    def __init__(
        self,
        interactive: Callable[[], tuple[InteractiveState, bool]],
        *,
        clock: Callable[[], float] = time.monotonic,
        use_pdh: bool = IS_WINDOWS,
    ) -> None:
        self._interactive = interactive
        self._clock = clock
        self._agent = psutil.Process(os.getpid())
        self._cpus = psutil.cpu_count() or 1
        psutil.cpu_percent(interval=None)  # prime: CPU% is measured since the previous call
        self._pdh = None
        self.unavailable_counters: dict[str, str] = {}
        if use_pdh:
            from udcs_agent.winplat.pdh import PdhQuery

            self._pdh = PdhQuery(_COUNTERS)
            self.unavailable_counters = dict(self._pdh.unavailable)
            self._pdh.collect()
        self._primed_at = time.monotonic()
        self._prev: tuple[float, float, int, float] | None = None
        self._smoothed: float | None = None

    SMOOTHING_TAU_SECONDS = 2.0
    _prev_now: float | None = None
    _WARMUP_SECONDS = 0.5  # rate counters (CPU%, disk idle) need two spaced samples

    def _warm_up(self) -> None:
        remaining = self._WARMUP_SECONDS - (time.monotonic() - self._primed_at)
        if self._prev is None and remaining > 0:
            time.sleep(remaining)

    def collect(
        self, usage: UdcsUsage, *, maintenance: bool = False
    ) -> tuple[Signals, ResourceUsage]:
        now = self._clock()
        try:
            interactive, protected = self._interactive()
        except Exception:
            logger.exception("interactive state unavailable; assuming ACTIVE")
            interactive, protected = InteractiveState.ACTIVE, False
        try:
            return self._collect(now, usage, interactive, protected, maintenance)
        except (OSError, psutil.Error) as exc:
            logger.warning("signal collection failed: %s", exc)
            vm = psutil.virtual_memory()
            signals = Signals(
                cpu_total_percent=100.0,
                cpu_udcs_percent=0.0,
                memory_total_bytes=vm.total,
                memory_available_bytes=vm.available,
                memory_udcs_bytes=usage.private_bytes,
                interactive=interactive,
                maintenance=maintenance,
                collection_error=type(exc).__name__,
            )
            return signals, ResourceUsage(
                cpu_percent=UsageSplit(total=100.0, udcs=0.0, non_udcs=100.0),
                memory_bytes=UsageSplit(
                    total=vm.total - vm.available,
                    udcs=usage.private_bytes,
                    non_udcs=max(0, vm.total - vm.available - usage.private_bytes),
                ),
            )

    def _collect(
        self,
        now: float,
        usage: UdcsUsage,
        interactive: InteractiveState,
        protected: bool,
        maintenance: bool,
    ) -> tuple[Signals, ResourceUsage]:
        self._warm_up()
        cpu_total = psutil.cpu_percent(interval=None)
        times = self._agent.cpu_times()
        agent_cpu = times.user + times.system
        if self._prev is None:
            udcs_cpu, udcs_io_rate = 0.0, 0.0
        else:
            t0, cpu0, io0, agent0 = self._prev
            dt = max(now - t0, 1e-3)
            seconds = max(0.0, usage.cpu_seconds - cpu0) + max(0.0, agent_cpu - agent0)
            udcs_cpu = min(100.0, 100.0 * seconds / (dt * self._cpus))
            udcs_io_rate = max(0, usage.io_bytes - io0) / dt
        self._prev = (now, usage.cpu_seconds, usage.io_bytes, agent_cpu)
        # The two CPU figures come from different sources/intervals; keep them consistent.
        cpu_total = max(cpu_total, udcs_cpu)
        non_udcs = max(0.0, cpu_total - udcs_cpu)
        if self._smoothed is None or self._prev_now is None:
            self._smoothed = non_udcs
        else:  # EWMA with time constant TAU, robust to irregular tick spacing
            import math

            alpha = 1.0 - math.exp(-max(now - self._prev_now, 1e-3) / self.SMOOTHING_TAU_SECONDS)
            self._smoothed += alpha * (non_udcs - self._smoothed)
        self._prev_now = now

        vm = psutil.virtual_memory()
        udcs_memory = usage.private_bytes + self._agent.memory_info().rss
        used = vm.total - vm.available

        disk_busy = faults = None
        gpu_splits: list[GpuUsageSplit] = []
        gpu_other = gpu_udcs = None
        gpu_other_dedicated = None
        if self._pdh is not None:
            from udcs_agent.winplat.pdh import gpu_usage

            self._pdh.collect()
            idle = self._pdh.value("disk_idle")
            disk_busy = None if idle is None else max(0.0, min(100.0, 100.0 - idle))
            faults = self._pdh.value("page_inputs")
            if "gpu_engine" not in self.unavailable_counters:
                pids = set(usage.pids) | {self._agent.pid}
                engines = self._pdh.array("gpu_engine")
                memory = self._pdh.array("gpu_memory")
                adapters = gpu_usage(engines or [], memory or [], pids)
                for a in adapters:
                    gpu_splits.append(
                        GpuUsageSplit(
                            adapter=a.adapter,
                            utilization_percent=UsageSplit(
                                total=a.total_percent, udcs=a.udcs_percent, non_udcs=a.other_percent
                            ),
                            dedicated_memory_bytes=UsageSplit(
                                total=a.udcs_dedicated_bytes + a.other_dedicated_bytes,
                                udcs=a.udcs_dedicated_bytes,
                                non_udcs=a.other_dedicated_bytes,
                            ),
                        )
                    )
                # Which WDDM adapter UDCS work will use isn't known before it runs, so the
                # conservative reading is the busiest adapter. Once UDCS GPU work is
                # running, only the adapters it actually uses count.
                mine = [a for a in adapters if a.udcs_percent > 0 or a.udcs_dedicated_bytes > 0]
                pool = mine or adapters
                gpu_other = max((a.other_percent for a in pool), default=0.0)
                gpu_udcs = max((a.udcs_percent for a in adapters), default=0.0)
                gpu_other_dedicated = max((a.other_dedicated_bytes for a in pool), default=0)
                if engines is None:  # read failed: unknown, so assume demand
                    gpu_other = None

        signals = Signals(
            cpu_total_percent=cpu_total,
            cpu_udcs_percent=udcs_cpu,
            memory_total_bytes=vm.total,
            memory_available_bytes=vm.available,
            memory_udcs_bytes=udcs_memory,
            interactive=interactive,
            protected_presentation=protected,
            hard_faults_per_second=faults,
            disk_busy_percent=disk_busy,
            udcs_disk_bytes_per_second=udcs_io_rate,
            gpu_other_percent=gpu_other,
            gpu_udcs_percent=gpu_udcs,
            gpu_other_dedicated_bytes=gpu_other_dedicated,
            maintenance=maintenance,
            cpu_non_udcs_smoothed_percent=self._smoothed,
        )
        usage_report = ResourceUsage(
            cpu_percent=UsageSplit(
                total=cpu_total, udcs=udcs_cpu, non_udcs=max(0.0, cpu_total - udcs_cpu)
            ),
            memory_bytes=UsageSplit(
                total=used, udcs=min(udcs_memory, used), non_udcs=max(0, used - udcs_memory)
            ),
            disk_busy_percent=disk_busy,
            udcs_disk_bytes_per_second=udcs_io_rate,
            hard_faults_per_second=faults,
            gpus=gpu_splits[:16],
        )
        return signals, usage_report
