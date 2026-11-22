"""Local resource protection: states, levels and the controller-supplied policy.

The controller ships a `ProtectionPolicy`; the agent enforces the *stricter* of
that policy and its local floor (`ProtectionPolicy.strictest`). The controller
can therefore never make a node less protective than its local configuration.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class InteractiveState(StrEnum):
    """Coarse, privacy-preserving presence. Never derived from content, only activity."""

    NO_USER = "no_user"  # nobody logged on interactively
    LOCKED = "locked"  # every interactive session is locked
    IDLE = "idle"  # unlocked, but no input for policy.idle_after_seconds (helper-confirmed)
    ACTIVE = "active"  # unlocked and in use -- also the fail-safe default


class ProtectionLevel(StrEnum):
    """How much the node may lend right now, from most to least generous."""

    OPEN = "open"  # no interactive user
    AWAY = "away"  # user locked/idle and the machine is quiet
    SHARED = "shared"  # user active, low non-UDCS pressure
    CONSTRAINED = "constrained"  # real resource pressure
    PROTECTED = "protected"  # full-screen/presentation, or policy says hands off
    MAINTENANCE = "maintenance"  # admin or local maintenance: lend nothing


LEVEL_ORDER: tuple[ProtectionLevel, ...] = tuple(ProtectionLevel)


def stricter(a: ProtectionLevel, b: ProtectionLevel) -> ProtectionLevel:
    return a if LEVEL_ORDER.index(a) >= LEVEL_ORDER.index(b) else b


class WorkloadClass(StrEnum):
    CPU = "cpu"  # compute-bound, cache-resident: protected well by priority + caps
    MEMORY = "memory"  # bandwidth-bound: priority does NOT protect the student (measured)
    DISK = "disk"  # I/O-bound: no per-job I/O rate control on Windows 10 1607+
    GPU = "gpu"  # CUDA: no MPS/MIG/TCC on GeForce; pause = stop submitting, evict = exit


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LevelEnvelope(_Contract):
    cpu_cap_percent: float = Field(ge=0, le=100, description="0 = pause CPU-class work")
    udcs_memory_budget_percent: float = Field(ge=0, le=90)
    allow_memory_class: bool
    allow_disk_class: bool
    allow_gpu_class: bool


def _default_envelopes() -> dict[ProtectionLevel, LevelEnvelope]:
    L = ProtectionLevel
    return {
        L.OPEN: LevelEnvelope(
            cpu_cap_percent=100,
            udcs_memory_budget_percent=60,
            allow_memory_class=True,
            allow_disk_class=True,
            allow_gpu_class=True,
        ),
        L.AWAY: LevelEnvelope(
            cpu_cap_percent=75,
            udcs_memory_budget_percent=50,
            allow_memory_class=True,
            allow_disk_class=True,
            allow_gpu_class=True,
        ),
        L.SHARED: LevelEnvelope(
            cpu_cap_percent=50,
            udcs_memory_budget_percent=25,
            allow_memory_class=False,
            allow_disk_class=False,
            allow_gpu_class=False,
        ),
        L.CONSTRAINED: LevelEnvelope(
            cpu_cap_percent=5,
            udcs_memory_budget_percent=10,
            allow_memory_class=False,
            allow_disk_class=False,
            allow_gpu_class=False,
        ),
        L.PROTECTED: LevelEnvelope(
            cpu_cap_percent=0,
            udcs_memory_budget_percent=10,
            allow_memory_class=False,
            allow_disk_class=False,
            allow_gpu_class=False,
        ),
        L.MAINTENANCE: LevelEnvelope(
            cpu_cap_percent=0,
            udcs_memory_budget_percent=0,
            allow_memory_class=False,
            allow_disk_class=False,
            allow_gpu_class=False,
        ),
    }


class ProtectionPolicy(_Contract):
    version: int = Field(default=1, ge=1)
    assessment_interval_seconds: float = Field(default=1.0, ge=0.5, le=2.0)
    idle_after_seconds: float = Field(default=300, ge=30, le=7200)
    relax_after_seconds: float = Field(
        default=30, ge=5, le=3600, description="a calmer level must hold this long"
    )
    post_activity_grace_seconds: float = Field(
        default=120, ge=0, le=3600, description="after logon/unlock, stay at SHARED or stricter"
    )
    other_cpu_constrained_percent: float = Field(
        default=50, ge=5, le=100, description="enter CONSTRAINED above this"
    )
    other_cpu_relax_percent: float = Field(
        default=35, ge=1, le=100, description="leave CONSTRAINED only below this"
    )
    other_cpu_severe_percent: float = Field(
        default=90, ge=10, le=100, description="instantaneous: act without smoothing"
    )
    memory_relax_margin_percent: float = Field(default=5, ge=0, le=30)
    away_max_other_cpu_percent: float = Field(default=20, ge=1, le=100)
    min_available_memory_percent: float = Field(default=20, ge=1, le=90)
    critical_available_memory_percent: float = Field(default=10, ge=1, le=90)
    hard_faults_constrained_per_second: float = Field(default=500, ge=10)
    disk_busy_constrained_percent: float = Field(default=60, ge=5, le=100)
    other_gpu_busy_percent: float = Field(default=10, ge=1, le=100)
    checkpoint_deadline_seconds: float = Field(default=30, ge=5, le=600)
    envelopes: dict[ProtectionLevel, LevelEnvelope] = Field(default_factory=_default_envelopes)

    @model_validator(mode="after")
    def _consistent(self) -> ProtectionPolicy:
        if self.other_cpu_relax_percent > self.other_cpu_constrained_percent:
            raise ValueError("cpu relax threshold must not exceed the constrained threshold")
        if self.critical_available_memory_percent > self.min_available_memory_percent:
            raise ValueError("critical memory threshold must not exceed the constrained threshold")
        missing = set(ProtectionLevel) - set(self.envelopes)
        if missing:
            raise ValueError(f"envelopes missing for {sorted(missing)}")
        return self

    @classmethod
    def strictest(cls, a: ProtectionPolicy, b: ProtectionPolicy) -> ProtectionPolicy:
        """Field-wise merge choosing whichever value protects the student more."""

        def env(level: ProtectionLevel) -> LevelEnvelope:
            x, y = a.envelopes[level], b.envelopes[level]
            return LevelEnvelope(
                cpu_cap_percent=min(x.cpu_cap_percent, y.cpu_cap_percent),
                udcs_memory_budget_percent=min(
                    x.udcs_memory_budget_percent, y.udcs_memory_budget_percent
                ),
                allow_memory_class=x.allow_memory_class and y.allow_memory_class,
                allow_disk_class=x.allow_disk_class and y.allow_disk_class,
                allow_gpu_class=x.allow_gpu_class and y.allow_gpu_class,
            )

        return cls(
            version=max(a.version, b.version),
            assessment_interval_seconds=min(
                a.assessment_interval_seconds, b.assessment_interval_seconds
            ),
            idle_after_seconds=max(a.idle_after_seconds, b.idle_after_seconds),
            relax_after_seconds=max(a.relax_after_seconds, b.relax_after_seconds),
            post_activity_grace_seconds=max(
                a.post_activity_grace_seconds, b.post_activity_grace_seconds
            ),
            other_cpu_constrained_percent=min(
                a.other_cpu_constrained_percent, b.other_cpu_constrained_percent
            ),
            # Lower exit threshold = must be calmer to relax = more protective.
            other_cpu_relax_percent=min(a.other_cpu_relax_percent, b.other_cpu_relax_percent),
            other_cpu_severe_percent=min(a.other_cpu_severe_percent, b.other_cpu_severe_percent),
            memory_relax_margin_percent=max(
                a.memory_relax_margin_percent, b.memory_relax_margin_percent
            ),
            away_max_other_cpu_percent=min(
                a.away_max_other_cpu_percent, b.away_max_other_cpu_percent
            ),
            min_available_memory_percent=max(
                a.min_available_memory_percent, b.min_available_memory_percent
            ),
            critical_available_memory_percent=max(
                a.critical_available_memory_percent, b.critical_available_memory_percent
            ),
            hard_faults_constrained_per_second=min(
                a.hard_faults_constrained_per_second, b.hard_faults_constrained_per_second
            ),
            disk_busy_constrained_percent=min(
                a.disk_busy_constrained_percent, b.disk_busy_constrained_percent
            ),
            other_gpu_busy_percent=min(a.other_gpu_busy_percent, b.other_gpu_busy_percent),
            checkpoint_deadline_seconds=min(
                a.checkpoint_deadline_seconds, b.checkpoint_deadline_seconds
            ),
            envelopes={level: env(level) for level in ProtectionLevel},
        )


class UsageSplit(_Contract):
    """total = udcs + non_udcs. 'non_udcs' is NOT 'the student': it includes the OS
    and unrelated background services."""

    total: float = Field(ge=0)
    udcs: float = Field(ge=0)
    non_udcs: float = Field(ge=0)


class GpuUsageSplit(_Contract):
    adapter: str = Field(max_length=64, description="WDDM adapter LUID")
    utilization_percent: UsageSplit
    dedicated_memory_bytes: UsageSplit


class ProtectionStatus(_Contract):
    level: ProtectionLevel
    level_since_seconds: float = Field(ge=0, description="seconds at the current level")
    policy_version: int = Field(ge=1)
    reasons: list[str] = Field(
        default_factory=list, max_length=16, description="coarse codes, e.g. 'memory_pressure'"
    )
    workloads_running: int = Field(default=0, ge=0)
    workloads_throttled: int = Field(default=0, ge=0)
    workloads_paused: int = Field(default=0, ge=0)
    evictions_total: int = Field(default=0, ge=0)
    assessment_overhead_ms: float = Field(default=0, ge=0, description="mean CPU ms per tick")
