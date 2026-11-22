r"""Milestone 1.5 acceptance benchmarks: foreground interference and response latency.

    uv run python tools/acceptance/m15_benchmarks.py OUT.json [--trials N]

Method (see docs/acceptance/milestone-1.5.md for the full write-up):
- Foreground benchmarks stand in for the student's work: cpu (1 thread), cpu_all (one
  process per core), memory (64 MiB copies), disk (16 MiB write+fsync+read), gpu (short
  CUDA kernels). Each sample = median of a short burst; each trial collects many samples.
- Conditions: A = no background; B = same-class synthetic background, UNMANAGED, normal
  priority (proves interference is real); C = the same background under the real
  governor, production default policy, real session state (the console is unlocked, so
  ACTIVE). Order A, B, C, A' per trial; A' checks drift.
- Slowdown = median(C)/median(A) - 1 (average over trials); worst case = p95(C)/median(A) - 1.
- Response latency: governor runs with injected presence; at t0 the "student arrives"
  (presence -> ACTIVE) or pressure appears (a non-UDCS CPU hog while LOCKED). We sample the
  workload's *job CPU accounting* every 50 ms and report when it actually drops to its new
  envelope -- measured effect, not the governor's own log.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import psutil

from udcs_agent.governor.engine import Governor
from udcs_agent.governor.interactive import HelperReports, InteractiveMonitor
from udcs_agent.governor.signals import SignalCollector
from udcs_agent.workloads.manager import WorkloadManager, WorkloadSpec
from udcs_shared.protection import InteractiveState, ProtectionLevel, ProtectionPolicy

PY = getattr(sys, "_base_executable", sys.executable)
SRC_PATHS = [p for p in sys.path if p and Path(p).is_dir()]
CPUS = psutil.cpu_count() or 1


# -- foreground benchmarks (the "student") -------------------------------------------------


def fg_cpu() -> float:
    t = time.perf_counter()
    s = 0
    for i in range(400_000):
        s += i * i
    return time.perf_counter() - t


_ALL_CORES = (
    "import time\nt=time.perf_counter()\ns=0\nfor i in range(1_500_000): s+=i*i\n"
    "print(time.perf_counter()-t)"
)


def fg_cpu_all() -> float:
    t = time.perf_counter()
    procs = [
        subprocess.Popen([PY, "-c", _ALL_CORES], stdout=subprocess.DEVNULL) for _ in range(CPUS)
    ]
    for p in procs:
        p.wait()
    return time.perf_counter() - t


_MEM = bytearray(64 * 2**20)


def fg_memory() -> float:
    t = time.perf_counter()
    bytes(_MEM)
    return time.perf_counter() - t


_DISK_DIR = Path(tempfile.mkdtemp(prefix="udcs-fg-"))
_BLOCK = os.urandom(16 * 2**20)


def fg_disk() -> float:
    path = _DISK_DIR / "fg.bin"
    t = time.perf_counter()
    with open(path, "wb") as f:
        f.write(_BLOCK)
        f.flush()
        os.fsync(f.fileno())
    with open(path, "rb") as f:
        f.read()
    return time.perf_counter() - t


class _GpuForeground:
    def __init__(self) -> None:
        from udcs_agent.workloads.cudadrv import CudaDevice

        self.device = CudaDevice(blocks=16, threads=128)
        self.iters = self.device.calibrate(0.005)

    def __call__(self) -> float:
        return self.device.run_kernel(self.iters)


FOREGROUND = {"cpu": fg_cpu, "cpu_all": fg_cpu_all, "memory": fg_memory, "disk": fg_disk}
BACKGROUND_KIND = {"cpu": "cpu", "cpu_all": "cpu", "memory": "memory", "disk": "disk", "gpu": "gpu"}


def sample(fn, seconds: float, burst: int) -> list[float]:
    out, end = [], time.monotonic() + seconds
    while time.monotonic() < end:
        out.append(statistics.median(fn() for _ in range(burst)))
    return out


# -- background helpers ----------------------------------------------------------------------


def _count(kind: str) -> int:
    return CPUS if kind == "cpu" else (3 if kind == "memory" else 1)


def unmanaged_background(kind: str, workdir: Path) -> list[subprocess.Popen]:
    code = (
        f"import sys; sys.path[:0] = {SRC_PATHS!r}; "
        "from udcs_agent.workloads.synthetic import main; sys.exit(main())"
    )
    procs = []
    for i in range(_count(kind)):
        d = workdir / f"unmanaged-{kind}-{i}"
        procs.append(
            subprocess.Popen(
                [PY, "-I", "-c", code, "--kind", kind, "--dir", str(d), "--memory-mb", "256"]
            )
        )
    return procs


class ManagedHarness:
    """Real governor + workload manager, production policy, optional presence override."""

    def __init__(self, workdir: Path, kind: str, presence: InteractiveState | None) -> None:
        self.presence = presence
        self.manager = WorkloadManager(workdir)
        for i in range(_count(kind)):
            self.manager.add(WorkloadSpec(id=f"{kind}{i}", kind=kind, memory_mb=256))
        monitor = InteractiveMonitor(HelperReports(), idle_after_seconds=lambda: 300)
        source = monitor if presence is None else (lambda: (self.presence, False))
        self.governor = Governor(
            self.manager, SignalCollector(source), local_policy=ProtectionPolicy()
        )
        self.stop = threading.Event()
        self.thread = threading.Thread(
            target=self.governor.run, args=(self.stop, lambda r: None), daemon=True
        )
        self.thread.start()

    def level(self) -> ProtectionLevel | None:
        status = self.governor.snapshot()[2]
        return status.level if status else None

    def wait_level(self, level: ProtectionLevel, timeout: float = 90.0) -> float:
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if self.level() == level:
                return time.monotonic() - start
            time.sleep(0.2)
        raise TimeoutError(f"level {level} not reached (at {self.level()})")

    def job_cpu_seconds(self) -> float:
        return self.manager.usage().cpu_seconds

    def close(self) -> None:
        self.stop.set()
        self.governor.wake()
        self.thread.join(5)
        self.manager.shutdown()


def _kill(procs: list[subprocess.Popen]) -> None:
    for p in procs:
        p.kill()
    for p in procs:
        p.wait()


# -- experiments ----------------------------------------------------------------------------------


def interference(cls: str, workdir: Path, trials: int, seconds: float) -> dict[str, object]:
    fg = _GpuForeground() if cls == "gpu" else FOREGROUND[cls]
    burst = 1 if cls in ("cpu_all", "disk") else 5
    kind = BACKGROUND_KIND[cls]
    a: list[float] = []
    b: list[float] = []
    c: list[float] = []
    a2: list[float] = []
    harness = ManagedHarness(workdir / f"managed-{cls}", kind, presence=None)
    try:
        harness.wait_level(ProtectionLevel.SHARED)  # steady state for a present student
        time.sleep(3)
        for t in range(trials):
            harness.manager.emergency_pause()  # A: no background at all
            a += sample(fg, seconds, burst)
            bg = unmanaged_background(kind, workdir / f"t{t}")  # B: unmanaged, NORMAL priority
            time.sleep(3 if kind == "gpu" else 1.5)
            b += sample(fg, seconds, burst)
            _kill(bg)
            harness.governor.wake()  # C: the governor's decision for a present student
            time.sleep(3)
            c += sample(fg, seconds, burst)
            harness.manager.emergency_pause()
            a2 += sample(fg, seconds, burst)
        states = {k: v.value for k, v in harness.manager.states().items()}
    finally:
        harness.close()
    base = statistics.median(a)

    def summary(xs: list[float]) -> dict[str, float]:
        xs = sorted(xs)
        p95 = xs[min(len(xs) - 1, int(0.95 * len(xs)))]
        return {
            "n": len(xs),
            "median_ms": round(statistics.median(xs) * 1000, 3),
            "p95_ms": round(p95 * 1000, 3),
            "max_ms": round(xs[-1] * 1000, 3),
            "slowdown_median_pct": round((statistics.median(xs) / base - 1) * 100, 1),
            "slowdown_p95_pct": round((p95 / base - 1) * 100, 1),
        }

    return {
        "baseline": summary(a),
        "unmanaged": summary(b),
        "managed": summary(c),
        "baseline_after": summary(a2),
        "managed_workload_states": states,
    }


def response(kind: str, trigger: str, workdir: Path, trials: int) -> dict[str, object]:
    """Time from trigger to the workload's measured CPU use dropping to its envelope."""
    arriving = trigger == "student_arrives"
    start_presence = InteractiveState.NO_USER if arriving else InteractiveState.LOCKED
    open_level = ProtectionLevel.OPEN if arriving else ProtectionLevel.AWAY
    harness = ManagedHarness(workdir / f"resp-{kind}-{trigger}", kind, presence=start_presence)
    results = []
    try:
        for _ in range(trials):
            harness.presence = start_presence
            harness.wait_level(open_level, timeout=240)  # 120 s grace + 30 s relax
            time.sleep(4)  # let the workload run at its full envelope
            hog: list[subprocess.Popen] = []
            t0 = time.monotonic()
            if arriving:
                harness.presence = InteractiveState.ACTIVE
                harness.governor.wake()  # what a WTS session-change notification triggers
                threshold = 0.55 if kind == "cpu" else 0.05  # SHARED: cpu cap 50%; others pause
            else:
                hog = unmanaged_background("cpu", workdir / "hog")  # non-UDCS pressure
                threshold = 0.10  # CONSTRAINED: cap 5% of the machine
            level_at = effect_at = None
            prev_cpu, prev_t = harness.job_cpu_seconds(), time.monotonic()
            while time.monotonic() - t0 < 15:
                time.sleep(0.05)
                now = time.monotonic()
                cpu = harness.job_cpu_seconds()
                share = (cpu - prev_cpu) / max(now - prev_t, 1e-3) / CPUS  # fraction of machine
                prev_cpu, prev_t = cpu, now
                if level_at is None and harness.level() in (
                    ProtectionLevel.SHARED,
                    ProtectionLevel.CONSTRAINED,
                ):
                    level_at = now - t0
                if level_at is not None and share <= threshold:
                    effect_at = now - t0
                    break
            _kill(hog)
            results.append({"decision_s": level_at, "effect_s": effect_at})
            harness.presence = start_presence
            time.sleep(1)
    finally:
        harness.close()
    effects = [r["effect_s"] for r in results if r["effect_s"] is not None]
    return {
        "kind": kind,
        "trigger": trigger,
        "trials": results,
        "effect_mean_s": round(statistics.mean(effects), 3) if effects else None,
        "effect_worst_s": round(max(effects), 3) if effects else None,
        "missed": sum(r["effect_s"] is None for r in results),
    }


def overhead(seconds: float = 30.0) -> dict[str, object]:
    """Governor cost with no workloads: CPU time per tick and process RSS."""
    with tempfile.TemporaryDirectory() as d:
        manager = WorkloadManager(Path(d))
        monitor = InteractiveMonitor(HelperReports(), idle_after_seconds=lambda: 300)
        governor = Governor(manager, SignalCollector(monitor))
        proc = psutil.Process()
        cpu0, t0 = proc.cpu_times(), time.monotonic()
        stop = threading.Event()
        thread = threading.Thread(target=governor.run, args=(stop, lambda r: None), daemon=True)
        thread.start()
        time.sleep(seconds)
        stop.set()
        governor.wake()
        thread.join(5)
        cpu1, elapsed = proc.cpu_times(), time.monotonic() - t0
        used = (cpu1.user + cpu1.system) - (cpu0.user + cpu0.system)
        return {
            "ticks": governor.ticks,
            "interval_s": 1.0,
            "process_cpu_percent_of_one_core": round(100 * used / elapsed, 3),
            "tick_cpu_ms_ema": round(governor.snapshot()[2].assessment_overhead_ms, 2),
            "rss_mib": round(proc.memory_info().rss / 2**20, 1),
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("out", type=Path)
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--seconds", type=float, default=4.0, help="per condition per trial")
    parser.add_argument(
        "--only", default="", help="comma list: overhead,cpu,cpu_all,memory,disk,gpu,response"
    )
    args = parser.parse_args()
    workdir = Path(tempfile.mkdtemp(prefix="udcs-bench-"))
    report: dict[str, object] = {
        "machine": {
            "cpu": platform.processor(),
            "logical_cpus": CPUS,
            "ram_gib": round(psutil.virtual_memory().total / 2**30, 1),
            "os": platform.platform(),
        },
        "policy": "ProtectionPolicy() defaults",
        "started": time.time(),
    }
    only = {x for x in args.only.split(",") if x}
    wanted = lambda name: not only or name in only  # noqa: E731
    if wanted("overhead"):
        report["overhead"] = overhead()
    print("overhead", report.get("overhead"), flush=True)
    interference_results: dict[str, object] = {}
    report["interference"] = interference_results
    for cls in [c for c in ("cpu", "cpu_all", "memory", "disk", "gpu") if wanted(c)]:
        try:
            interference_results[cls] = interference(cls, workdir, args.trials, args.seconds)
        except Exception as exc:  # noqa: BLE001 — record and continue with other classes
            interference_results[cls] = {"error": f"{type(exc).__name__}: {exc}"}
        print(cls, json.dumps(interference_results[cls])[:400], flush=True)
    responses: list[dict[str, object]] = []
    report["response"] = responses
    for kind, trigger in (
        []
        if not wanted("response")
        else (
            ("cpu", "student_arrives"),
            ("memory", "student_arrives"),
            ("disk", "student_arrives"),
            ("gpu", "student_arrives"),
            ("cpu", "pressure_while_locked"),
        )
    ):
        try:
            responses.append(response(kind, trigger, workdir, args.trials))
        except Exception as exc:  # noqa: BLE001
            responses.append(
                {"kind": kind, "trigger": trigger, "error": f"{type(exc).__name__}: {exc}"}
            )
        print("response", json.dumps(responses[-1])[:300], flush=True)
    report["finished"] = time.time()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
