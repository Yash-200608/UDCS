# Milestone 1.5 Acceptance Report — Windows Background Service & Local Resource Protection

_2026-11-22. Raw data: `docs/acceptance/data/`. These are engineering targets measured on one machine, not universal guarantees._

## Verdict

**Not accepted yet, but close.** The elevated service run (pass 1, 2026-11-22, `data/m15-service-acceptance.json`) passed every check:
- service start, LocalSystem in session 0, no visible windows;
- service overhead: 55.6 MiB RSS, 0.68% of one core;
- helper and presence;
- workload management and crash recovery as a real service;
- E1 (CUDA works in the service process and in its child worker);
- graceful stop in 0.27 s.

**Still open:** pass 2, *service start after a reboot*.

**2026-11-28: the pass-1 machine above (build 22000, GT 730) was retired.**
- Its pass 2 can never be recorded. Its pass-1 record stays unchanged as history.
- M1.5 will be re-run, pass 1 and then pass 2, on the newly designated acceptance machine (`data/machines/262cc47030b1/`: Windows 11 Home build 26300, i5-14400F, RTX 3060). Its results go to `data/machines/262cc47030b1/m15-service-acceptance.json`.
- **Pass 1 there: all 9 checks PASS** (2026-11-28, `data/machines/262cc47030b1/README.md`; an earlier version said 8, a miscount).
  - **Pass 2 for run 2: all 3 checks PASS** (2026-11-28 21:59): the service started on its own 132.2 s after boot, there were 0 SCM failures at the shutdown, and the helper started at logon. The shutdown defect is fixed. Cause confirmed from `agent.log`: at OS shutdown `ReportEvent` raised error 1717, which escaped `SvcDoRun`.
  - Run 2, after the shutdown-fix reinstall (c5dd16f), also recorded 9 passes, but its E1 child workers failed. That was a regression from the host-name redaction, now fixed. `e1_completed` only checks completion, and a stricter `e1_used_arrangements_ok` was added.
  - E1: CUDA works in the service process and in its child worker on the RTX 3060 (CC 8.6), as SYSTEM in session 0.
  - Service overhead passed with only a 0.5 MiB margin (79.5 of 80 MiB RSS).
  - **Pass 2, attempt 1: FAIL, caused by a harness defect.** Pass 2 read the delayed-auto-start service before the SCM started it, which it did on its own 136.8 s after boot. The harness is fixed; the attempt stays recorded.
  - **Shutdown defect found at the same reboot:** SCM event 7024, service-specific error 0x20000001, and no clean stop. Not yet diagnosed.
- A pass on that PC is evidence for one Home-edition machine, not proof of lab compatibility.

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
| Graceful shutdown | **service** stop 0.27 s, no workload processes left, registry state `waiting` (resumable) | ✅ (pass 1) |
| Workload state recovery | `test_workloads_windows.py`: checkpoint → evict → resume continues from the saved unit count; a restarted manager resumes from the registry | ✅ |
| Governor overhead | 1.97 ms CPU per tick, 0.21% of one core | ✅ |
| Service RSS ≤ 80 MiB | **the service process:** 55.6 MiB RSS, 44.2 MiB private, 0.68% of one core (workload jobs excluded) | ✅ |
| Service starts (installed), runs as LocalSystem in session 0, delayed auto-start, no visible windows | started in 1.9 s; first status after 6.4 s; 0 windowed processes | ✅ (pass 1) |
| Helper at logon / presence | the service saw `active` from the session helper; the level was `constrained` (`user_active`, `cpu_pressure`) while the script ran | ✅ (pass 1) |
| Workload managed by the service | the CPU validation workload ran `throttled` under `constrained` | ✅ |
| Crash recovery as a real service | service restarted after 6.1 s; the workload resumed after 1.1 s from its checkpoint (unit 314) | ✅ |
| **Service start after reboot** | `m15_service_acceptance.ps1 -AfterReboot` | ⏳ **pass 2 not run yet** |
| E1: CUDA from the service vs a child worker vs a session worker | **as SYSTEM:** service process ✅ (context 110 ms, 20 ms kernels); service child worker ✅ (799 ms); worker in the interactive session as SYSTEM ✅ (4.1 s); worker as the logged-in *user* ❌ "probe produced no result" (exit 1, not investigated: UDCS never runs work as the student, so this arrangement is excluded by design) | ✅ for the arrangements UDCS uses |
| **Isolation from the service** (M2, ADR 0001) | `m2_isolation_service_acceptance.ps1` | ✅ see below |

## Hardware / driver support matrix

| GPU | Driver | Facts | UDCS status |
|---|---|---|---|
| GeForce GT 730 (Kepler, CC 3.5) | 456.71 / CUDA 11.1 | **[measured]** NVML discovery works (utilization and power *Not Supported*); the CUDA driver API runs a JIT-compiled PTX kernel in the user session; PDH per-process GPU counters work | CPU-only for real workloads. Current PyTorch requires CC ≥ 7.5 **[documented]**. Usable for synthetic validation only |
| RTX 3060 / 4060 Ti (CC 8.6 / 8.9) | RTX 3060: 32.0.16.2124 | **[measured] RTX 3060, 2026-11-28 (machine 262cc47030b1):** E1 passes in the service process (context 124 ms, kernels around 20 ms) and its child worker (73 ms) as SYSTEM in session 0. The 4060 Ti is untested. | RTX 3060 ✅ for the arrangements UDCS uses |

## Weaknesses found and fixed during acceptance

| Weakness | Fix |
|---|---|
| Time-only hysteresis, so Defender spikes kept the node constrained forever | smoothed signal plus separate enter (50%) and exit (35%) thresholds |
| Exit threshold applied to the cautious start-up level | the exit threshold applies only to pressure actually detected |
| 25 adversarial-review findings, 2 of them high-severity | all fixed (see `DEVELOPMENT_STATUS.md`) |

## Isolation from the installed service (M2, ADR 0001), 2026-11-22

`tools/acceptance/m2_isolation_service_acceptance.ps1`, raw data `data/m2-isolation-service.json` (host and user names redacted). **PASSED.**

**Run context:** the self-test ran inside the UDCSAgent service, as `NT AUTHORITY\SYSTEM` in session 0, on build 22000.

| Check | Result |
|---|---|
| Permitted operations (read the approved input, read the runtime, write its own output) | ✅ all allowed |
| Prohibited operations | ✅ all 16 denied (see the list below) |
| Unsandboxed control | **for every one of the 16, the SYSTEM control was able to do it**, so each denial is meaningful on the service path |
| Token | AppContainer, low integrity (RID 4096), privileges only `SeChangeNotifyPrivilege`, although the parent is LocalSystem |
| Environment | only `LOCALAPPDATA`, `SYSTEMROOT`, `TEMP`, `TMP`, `USERPROFILE` |
| Process-tree kill | ✅ all 4 job members ended |
| CUDA inside the sandbox | `cuInit` OK, 1 device |
| AppContainer detection under the service | verified (263 ms) |

The 16 prohibited operations were:
- external TCP, loopback TCP and DNS;
- listing the forbidden directory and the user's profile;
- opening the agent process to terminate it or read its memory, terminating a host helper process, and reading lsass memory;
- reading the agent credential, another workload's file and an outside secret;
- an HKCU secret;
- writing the approved input, another workload's file and the runtime code.

The SYSTEM control could open lsass, which as a normal user it could not.

**Caveat:** this install was not enrolled, so `read:agent_credential` used a stand-in file in the same protected `ProgramData\UDCS\agent` tree (same ACL), not a real DPAPI credential.
