# Milestone 1.5 Acceptance Report — Windows Background Service & Local Resource Protection

_2026-11-22. Raw data: `docs/acceptance/data/`. These are engineering targets measured on one machine, not universal guarantees._

## Verdict

**Not accepted yet.** All criteria that can be verified without administrator rights pass, but the service-level criteria have **not been run**, because they need an elevated shell:

- service start after reboot;
- crash recovery as a real service;
- E1 (whether CUDA works in session 0);
- service overhead;
- helper at logon.

They are scripted in `tools/acceptance/m15_service_acceptance.ps1`.

Status of the other gates:
- **PostgreSQL integration through CI:** passed on the feature branch. CI run 44985979000 migrated a clean PostgreSQL 16 database to head, and 57/57 controller and shared tests passed. Getting there exposed two real bugs, both now fixed: data loss in the 0002 downgrade on SQLite, and nondeterministic audit ordering.
- **Disk interference:** still open; the benchmark result is inconclusive.

**Milestone 1.5 is accepted only after the service script passes on a lab PC and the disk gate is closed.** The commit on `feature/udcs-background-agent-m15` is a development checkpoint, not an acceptance.

## Test configuration

| Item | Value |
|---|---|
| Machine | Intel i5-6500 (4C/4T), 24 GB RAM, GeForce GT 730 (CC 3.5, driver 456.71, CUDA 11.1) + Intel HD 530 |
| OS | Windows 11 Pro Education 22000 |
| Background noise | Windows Defender active (MsMpEng about 12% CPU while idle) |
| Policy | `ProtectionPolicy()` defaults, 1 s assessment |
| Presence | interference tests: the real console session (unlocked, so ACTIVE); response tests: injected |

## Method

Foreground benchmarks stand in for the student:

| Benchmark | What it does |
|---|---|
| CPU, 1 thread | a Python compute loop |
| CPU, all cores | 4 processes |
| Memory | 64 MiB copies |
| Disk | 16 MiB write + fsync + read |
| GPU | 5 ms CUDA kernels |

Each trial runs the conditions in the order A, B, C, A′:

- **A:** no background.
- **B:** a same-class synthetic background, unmanaged, at normal priority.
- **C:** the same background under the real governor.
- **A′:** no background again, to detect drift.

Slowdown is median(C) / median(A) − 1. Worst case is p95(C) / median(A) − 1, shown next to the baseline's own p95 (the noise floor).

Response latency is measured from the trigger until the workload's **job CPU accounting**, sampled every 50 ms, actually drops to its new envelope. It is the effect, not the governor's own log entry.

Tools: `tools/acceptance/m15_benchmarks.py`.

## B1 — foreground slowdown (target < 5%)

| Class | Unmanaged | Managed median | Managed p95 | Noise floor (baseline p95) | Result |
|---|---|---|---|---|---|
| CPU, 1 thread | +17.9% | **+1.3%** | +6.7% | +3.6% | median ✅; p95 3.1 points above the noise floor |
| CPU, all cores | +150% | **+0.1%** | +9.3% | +16.4% | ✅ (p95 within noise) |
| Memory | +184% | **+0.7%** | +17.3% | +13.5% | ✅ (UDCS memory work held while the student is active) |
| GPU | +801% | **0.0%** | +0.5% | +0.6% | ✅ |
| Disk (isolated run) | +48.9% | +7.7% | +974% | +139% | ⚠️ inconclusive: the UDCS disk work was held (`waiting`) throughout, so C contains no UDCS I/O; the disk benchmark itself is too noisy on this machine |

**An earlier run that was wrong, kept for honesty:** the first benchmark reported +33.5% for all-core CPU. It ran alongside a 30-agent review workflow, with Defender active. A 5-round interleaved re-test (`m15-cpu-all-cap-diagnosis.json`) put every condition within ±2% of baseline; the baseline itself varied by up to +22.5%.

## B2 — response within 2 s

| Trigger | Mean | Worst | Result |
|---|---|---|---|
| Non-UDCS CPU load appears while locked (CPU work capped to 5%) | 1.07 s | 1.14 s | ✅ (3 trials; a second run gave 1.13 / 1.22 s) |
| Student arrives: CPU work capped to 50% | 0.45 s | 0.52 s | ✅ |
| Student arrives: memory work paused | 0.20 s | 0.20 s | ✅ |
| Student arrives: disk work paused | 0.06 s | 0.09 s | ✅ |
| Student arrives: GPU work paused (cooperative) | 0.11 s | 0.11 s | ✅ |
| Pressure while locked (repeat run) | 1.20 s | 1.33 s | ✅ |

_3 trials each, 0 missed. "Student arrives" = a presence change delivered as a session-change wake-up, which is what the service receives from Windows._

## Other criteria

| Criterion | Evidence | Result |
|---|---|---|
| Local protection while the controller is unreachable | `tests/e2e/test_agent_app.py`: the governor keeps ticking and enforcing | ✅ |
| Fail closed when never confirmed by the controller | the same file: an enrolled, never-confirmed node lends nothing | ✅ |
| Graceful shutdown | agent stop < 5 s in the test; the target is < 2 s in the service | ⚠️ unmeasured in service |
| Workload state recovery | `test_workloads_windows.py`: checkpoint → evict → resume continues from the saved unit count; a restarted manager resumes from the registry | ✅ |
| Governor overhead | 1.97 ms CPU per tick, 0.21% of one core | ✅ |
| Service RSS ≤ 80 MiB | the benchmark process measured 124 MiB, but it loads the test tooling | ❓ unverified |
| Service start after reboot, crash recovery, session 0, no windows, helper at logon | `m15_service_acceptance.ps1` | ⏳ not run (needs admin) |
| E1: CUDA from the service vs a child worker vs a session worker | built into the service as a diagnostic; works as a normal user (child worker: 20 ms kernels) | ⏳ not run as SYSTEM |

## Hardware / driver support matrix

| GPU | Driver | Facts | UDCS status |
|---|---|---|---|
| GeForce GT 730 (Kepler, CC 3.5) | 456.71 / CUDA 11.1 | **[measured]** NVML discovery works (utilization and power *Not Supported*); the CUDA driver API runs a JIT-compiled PTX kernel in the user session; PDH per-process GPU counters work | CPU-only for real workloads. Current PyTorch requires CC ≥ 7.5 **[documented]**. Usable for synthetic validation only |
| RTX 3060 / 4060 Ti (CC 8.6 / 8.9) | not tested | — | eligible in principle; **needs E1 on real hardware** |

## Weaknesses found and fixed during acceptance

| Weakness | Fix |
|---|---|
| Time-only hysteresis, so Defender spikes kept the node constrained forever | smoothed signal plus separate enter (50%) and exit (35%) thresholds |
| Exit threshold applied to the cautious start-up level | the exit threshold applies only to pressure actually detected |
| 25 adversarial-review findings, 2 of them high-severity | all fixed (see `DEVELOPMENT_STATUS.md`) |
