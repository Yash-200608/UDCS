"""Pure decision logic: signals + policy -> protection level, with hysteresis.

No I/O here, so every rule is unit-testable with synthetic signals.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from udcs_shared.protection import (
    InteractiveState,
    ProtectionLevel,
    ProtectionPolicy,
    stricter,
)


@dataclass(frozen=True)
class Signals:
    """One assessment's measurements. None = unavailable (treated conservatively)."""

    cpu_total_percent: float
    cpu_udcs_percent: float
    memory_total_bytes: int
    memory_available_bytes: int
    memory_udcs_bytes: int
    interactive: InteractiveState
    protected_presentation: bool = False  # full-screen / presentation mode (from helper)
    hard_faults_per_second: float | None = None
    disk_busy_percent: float | None = None
    udcs_disk_bytes_per_second: float = 0.0
    gpu_other_percent: float | None = None
    gpu_udcs_percent: float | None = None
    gpu_other_dedicated_bytes: int | None = None
    maintenance: bool = False
    collection_error: str | None = None
    # Exponentially smoothed non-UDCS CPU (tau ~2 s). None = no smoothing available yet.
    cpu_non_udcs_smoothed_percent: float | None = None

    @property
    def cpu_non_udcs_percent(self) -> float:
        return max(0.0, self.cpu_total_percent - self.cpu_udcs_percent)

    @property
    def memory_available_percent(self) -> float:
        if self.memory_total_bytes <= 0:
            return 0.0
        return 100.0 * self.memory_available_bytes / self.memory_total_bytes


@dataclass(frozen=True)
class Assessment:
    level: ProtectionLevel
    reasons: tuple[str, ...]
    memory_critical: bool = False
    disk_pressure: bool = False
    gpu_demand: bool = False


def classify(
    signals: Signals, policy: ProtectionPolicy, latched: frozenset[str] = frozenset()
) -> Assessment:
    """The level the evidence *right now* calls for (before hysteresis)."""
    reasons: list[str] = []
    # Order matters: each rule can only make the result stricter, never weaker.
    if signals.maintenance:
        return Assessment(
            ProtectionLevel.MAINTENANCE, ("maintenance",), disk_pressure=True, gpu_demand=True
        )
    if signals.collection_error:
        # Fail toward the student: if we can't see, assume pressure -- but never weaken a
        # stricter state we *can* still see (presentation mode).
        level = ProtectionLevel.CONSTRAINED
        error_reasons = ["signals_unavailable"]
        if signals.protected_presentation:
            level = ProtectionLevel.PROTECTED
            error_reasons.append("presentation")
        return Assessment(level, tuple(error_reasons), disk_pressure=True, gpu_demand=True)

    if signals.interactive == InteractiveState.NO_USER:
        level = ProtectionLevel.OPEN
    elif signals.interactive in (InteractiveState.LOCKED, InteractiveState.IDLE):
        level = ProtectionLevel.AWAY
        if signals.cpu_non_udcs_percent > policy.away_max_other_cpu_percent:
            level = ProtectionLevel.SHARED
            reasons.append("background_activity")
    else:
        level = ProtectionLevel.SHARED
        reasons.append("user_active")

    pressure = False
    # Threshold hysteresis: enter above `constrained`, leave only below `relax`. Decisions
    # use the smoothed value so 1-s spikes (antivirus scans, launches) neither trigger nor
    # reset relaxation; a severe instantaneous spike still acts at once.
    # `latched`: pressure reasons present in the previous assessment. The exit threshold
    # applies only to a pressure that was actually detected -- not to the cautious
    # start-up level, which would otherwise trap a node whose load sits between them.
    cpu_threshold = (
        policy.other_cpu_relax_percent
        if "cpu_pressure" in latched
        else policy.other_cpu_constrained_percent
    )
    smoothed = signals.cpu_non_udcs_smoothed_percent
    cpu_level = signals.cpu_non_udcs_percent if smoothed is None else smoothed
    if cpu_level > cpu_threshold or signals.cpu_non_udcs_percent > policy.other_cpu_severe_percent:
        pressure = True
        reasons.append("cpu_pressure")
    memory_threshold = policy.min_available_memory_percent + (
        policy.memory_relax_margin_percent if "memory_pressure" in latched else 0.0
    )
    if signals.memory_available_percent < memory_threshold:
        pressure = True
        reasons.append("memory_pressure")
    if (
        signals.hard_faults_per_second is not None
        and signals.hard_faults_per_second > policy.hard_faults_constrained_per_second
    ):
        pressure = True
        reasons.append("paging")
    if pressure:
        level = stricter(level, ProtectionLevel.CONSTRAINED)
    if signals.protected_presentation:
        level = stricter(level, ProtectionLevel.PROTECTED)
        reasons.append("presentation")

    memory_critical = signals.memory_available_percent < policy.critical_available_memory_percent
    if memory_critical:
        reasons.append("memory_critical")
    # Disk is protected for a student who is *using* the machine. (Host disk busy% can't be
    # attributed per process, so for an idle/locked session UDCS's own I/O would otherwise
    # read as pressure and make disk work flap.)
    using = signals.interactive == InteractiveState.ACTIVE
    disk_pressure = using and (
        signals.disk_busy_percent is None
        or signals.disk_busy_percent > policy.disk_busy_constrained_percent
    )
    if disk_pressure:
        reasons.append("disk_pressure")
    gpu_demand = signals.gpu_other_percent is None or (
        signals.gpu_other_percent > policy.other_gpu_busy_percent
    )
    if gpu_demand and signals.gpu_udcs_percent:
        reasons.append("gpu_demand")
    return Assessment(level, tuple(reasons), memory_critical, disk_pressure, gpu_demand)


@dataclass
class Hysteresis:
    """Escalate immediately; relax only after the calmer level has held steadily.

    Also: for `post_activity_grace_seconds` after a user becomes active (logon,
    unlock, return from idle), never go below SHARED -- the student is most likely
    to start something demanding right then.
    """

    level: ProtectionLevel = ProtectionLevel.CONSTRAINED  # start cautious
    level_since: float = 0.0
    _calm_candidate: ProtectionLevel | None = None
    _calm_since: float = 0.0
    _last_interactive: InteractiveState | None = None
    _active_since: float | None = None
    transitions: list[tuple[float, ProtectionLevel, tuple[str, ...]]] = field(default_factory=list)

    def update(
        self,
        assessment: Assessment,
        interactive: InteractiveState,
        now: float,
        policy: ProtectionPolicy,
    ) -> ProtectionLevel:
        if interactive == InteractiveState.ACTIVE and self._last_interactive not in (
            None,
            InteractiveState.ACTIVE,
        ):
            self._active_since = now
        self._last_interactive = interactive

        target = assessment.level
        if (
            self._active_since is not None
            and now - self._active_since < policy.post_activity_grace_seconds
        ):
            target = stricter(target, ProtectionLevel.SHARED)

        order = list(ProtectionLevel)
        if order.index(target) > order.index(self.level):  # stricter: act now
            self._switch(target, now, assessment.reasons)
        elif order.index(target) < order.index(self.level):  # calmer: wait
            # Relax to the *strictest* calmer level seen during the whole calm streak.
            if self._calm_candidate is None:
                self._calm_candidate, self._calm_since = target, now
            else:
                self._calm_candidate = stricter(self._calm_candidate, target)
            if now - self._calm_since >= policy.relax_after_seconds:
                self._switch(self._calm_candidate, now, assessment.reasons)
        else:
            self._calm_candidate = None
        return self.level

    def _switch(self, level: ProtectionLevel, now: float, reasons: tuple[str, ...]) -> None:
        if level != self.level:
            self.level = level
            self.level_since = now
            self.transitions.append((now, level, reasons))
            del self.transitions[:-200]
        self._calm_candidate = None
