"""The governor loop: assess every ~1 s, decide locally, enforce on UDCS workloads."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from udcs_agent.governor.classifier import Assessment, Hysteresis, Signals, classify
from udcs_agent.governor.signals import SignalCollector
from udcs_agent.workloads.manager import WorkloadManager
from udcs_shared.protection import (
    InteractiveState,
    LevelEnvelope,
    ProtectionLevel,
    ProtectionPolicy,
    ProtectionStatus,
)
from udcs_shared.telemetry import ResourceUsage

logger = logging.getLogger(__name__)

MAX_CONSECUTIVE_TICK_FAILURES = 5
STATUS_WRITE_INTERVAL_SECONDS = 5.0


@dataclass(frozen=True)
class AdmissionView:
    level: ProtectionLevel
    reasons: frozenset[str]
    maintenance: bool
    envelope: LevelEnvelope
    memory_total_bytes: int
    udcs_memory_bytes: int


class Governor:
    def __init__(
        self,
        workloads: WorkloadManager,
        collector: SignalCollector,
        *,
        local_policy: ProtectionPolicy | None = None,
        clock: Callable[[], float] = time.monotonic,
        status_path: Path | None = None,
        maintenance_flag: Path | None = None,
    ) -> None:
        self.workloads = workloads
        self.collector = collector
        self._local_policy = local_policy or ProtectionPolicy()
        self._remote_policy: ProtectionPolicy | None = None
        self._clock = clock
        self._status_path = status_path
        self._maintenance_flag = maintenance_flag
        self._controller_maintenance = False
        self.hysteresis = Hysteresis(level_since=clock())
        self._lock = threading.Lock()
        self._last: tuple[Signals, ResourceUsage, Assessment, ProtectionLevel] | None = None
        self._overhead_ms = 0.0
        self._last_status_write = 0.0
        self._wake = threading.Event()
        self.ticks = 0

    def wake(self) -> None:
        """Assess now instead of at the next interval (session change, etc.)."""
        self._wake.set()

    # -- policy inputs -------------------------------------------------------------------------

    @property
    def policy(self) -> ProtectionPolicy:
        remote = self._remote_policy
        if remote is None:
            return self._local_policy
        return ProtectionPolicy.strictest(self._local_policy, remote)

    def set_remote_policy(self, policy: ProtectionPolicy | None) -> None:
        """Controller policy can only tighten the local floor, never loosen it."""
        self._remote_policy = policy

    def set_controller_maintenance(self, maintenance: bool) -> None:
        self._controller_maintenance = maintenance

    def admission_view(self) -> AdmissionView | None:
        """What the job-sync thread needs to decide how much *new* work to offer.
        None until the first assessment: no offer is made before the node has measured."""
        with self._lock:
            last = self._last
        if last is None:
            return None
        signals, usage, assessment, level = last
        maintenance = self._controller_maintenance or (
            self._maintenance_flag is not None and self._maintenance_flag.exists()
        )
        return AdmissionView(
            level=level,
            reasons=frozenset(assessment.reasons),
            maintenance=maintenance,
            envelope=self.policy.envelopes[level],
            memory_total_bytes=signals.memory_total_bytes,
            udcs_memory_bytes=int(usage.memory_bytes.udcs),
        )

    # -- the loop --------------------------------------------------------------------------------

    def tick(self) -> ProtectionLevel:
        started_cpu = time.thread_time()
        now = self._clock()
        policy = self.policy
        usage = self.workloads.usage()
        maintenance = self._controller_maintenance or (
            self._maintenance_flag is not None and self._maintenance_flag.exists()
        )
        signals, resource_usage = self.collector.collect(usage, maintenance=maintenance)
        latched = frozenset(self._last[2].reasons) if self._last is not None else frozenset()
        assessment = classify(signals, policy, latched)
        level = self.hysteresis.update(assessment, signals.interactive, now, policy)
        self.workloads.enforce(
            policy.envelopes[level], assessment, policy, signals.memory_total_bytes, usage
        )
        with self._lock:
            self._last = (signals, resource_usage, assessment, level)
        cost_ms = (time.thread_time() - started_cpu) * 1000
        self._overhead_ms = cost_ms if self.ticks == 0 else 0.9 * self._overhead_ms + 0.1 * cost_ms
        self.ticks += 1
        if (
            self._status_path is not None
            and now - self._last_status_write >= STATUS_WRITE_INTERVAL_SECONDS
        ):
            self._last_status_write = now
            self._write_status(now)
        return level

    def run(self, stop: threading.Event, on_fatal: Callable[[str], None]) -> None:
        """Runs until `stop` is set. Repeated tick failures are fatal by design: an agent
        that cannot protect the student must not keep workloads alive (they die with
        the process via kill-on-close, and the service manager restarts the agent)."""
        failures = 0
        while not stop.is_set():
            started = self._clock()
            try:
                self.tick()
                failures = 0
            except Exception:
                failures += 1
                logger.exception("governor tick failed (%d in a row)", failures)
                self.workloads.emergency_pause()
                if failures >= MAX_CONSECUTIVE_TICK_FAILURES:
                    on_fatal("governor cannot assess resources")
                    return
            interval = self.policy.assessment_interval_seconds
            self._wake.wait(max(0.05, interval - (self._clock() - started)))
            self._wake.clear()

    # -- outputs -----------------------------------------------------------------------------------

    def snapshot(self) -> tuple[InteractiveState, ResourceUsage | None, ProtectionStatus | None]:
        with self._lock:
            last = self._last
        if last is None:
            return InteractiveState.ACTIVE, None, None
        signals, usage, assessment, level = last
        counts = self.workloads.counts()
        status = ProtectionStatus(
            level=level,
            level_since_seconds=max(0.0, self._clock() - self.hysteresis.level_since),
            policy_version=self.policy.version,
            reasons=list(assessment.reasons)[:16],
            workloads_running=counts["running"],
            workloads_throttled=counts["throttled"],
            workloads_paused=counts["paused"],
            evictions_total=self.workloads.evictions_total,
            assessment_overhead_ms=round(self._overhead_ms, 3),
        )
        return signals.interactive, usage, status

    def _write_status(self, now: float) -> None:
        interactive, usage, status = self.snapshot()
        data = {
            "monotonic": now,
            "wall": time.time(),
            "pid": os.getpid(),
            "ticks": self.ticks,
            "interactive": interactive.value,
            "protection": status.model_dump(mode="json") if status else None,
            "usage": usage.model_dump(mode="json") if usage else None,
            "workloads": {k: v.value for k, v in self.workloads.states().items()},
            "unavailable_counters": self.collector.unavailable_counters,
        }
        tmp = self._status_path.with_suffix(".tmp")
        try:
            self._status_path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
            os.replace(tmp, self._status_path)
        except OSError:
            logger.warning("could not write governor status", exc_info=True)
