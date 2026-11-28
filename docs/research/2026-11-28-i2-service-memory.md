# I-2: why the UDCSAgent service sits at the 80 MiB memory limit

_2026-11-28, machine `262cc47030b1` (Windows 11 Home 26300, i5-14400F, 32 GB, RTX 3060, driver 32.0.16.2124). These are diagnostic measurements, not acceptance evidence. Nothing was changed: no code, no limit, no installed file, no evidence. There was no reboot and no reinstall, and no acceptance test was repeated._

## Summary

- **Verified fact:** the ~23 MiB difference from the retired machine (55.6 → 79.1 / 79.5 MiB working set) is **one fixed allocation made by `nvmlInit()` inside NVIDIA's `nvml.dll`** on this machine's driver: +21 to 23 MiB working set and private memory, plus 24 handles. It is **not growth** and **not a UDCS code change**:
  - the retired machine's own code (042f5bb), run on this PC, idles within 1 MiB of the current code;
  - without NVML, both builds idle at 57 MiB / 43–44 MiB private, matching the retired machine's 55.6 / 44.2;
  - `nvmlShutdown()` releases nothing, and `nvml.dll` cannot be unloaded (still loaded after 10 `FreeLibrary` calls), so the allocation lasts for the life of the process;
  - repeated `nvmlInit` adds nothing.
- **Verified fact:** in the configuration measured by the acceptance check (local-only, not enrolled), **the agent initializes NVML and never uses it**. Its only users are the controller-link pieces (inventory, heartbeat telemetry), which do not run when the node is not enrolled. The governor's GPU signals come from PDH.
- **Second, separate finding:** running E1 **in the service process** (the `service_process` arrangement) loads the CUDA driver libraries into the agent and keeps them. That adds +21 MiB working set, +14 MiB private, about +190 handles and +9 threads, and the agent's own shutdown does not release them. That is why the installed service is now at **~95 MiB**, above the limit, after the E1 re-check. It only happens when an administrator requests E1.
- **No leak found:** the installed service was flat for 40 minutes (93.3–96.0 MiB, trend −1.4 MiB/h), and every phase of the replica was flat apart from E1's one-time step.
- **Recommendation (not implemented):**
  1. start NVML lazily, only when an enrolled controller link needs it;
  2. stop running CUDA inside the service for E1;
  3. make the overhead check say what it measured.

## 1. What the limit measures

- **Check:** `tools/acceptance/m15_service_acceptance.ps1`, pass 1, `service_overhead`: `Process.WorkingSet64 / 1MB -le 80`, from one sample.
- **When:** about 35–40 s after the first start (the service is up, 3 governor ticks have run, then a 30 s CPU window). That is **before** the helper, the workload, the crash test and E1.
- **Target:** B6 in `docs/architecture/node-operating-model.md`: "Agent's own idle overhead ≤ 80 MiB RSS". The 80 MiB was set when the agent measured ~55 MiB on the GT 730 machine.
- **What the metric is:** the working set, meaning physical pages currently resident in the process, **including shared image pages** (DLLs). It is neither private commit nor unique memory. `PrivateMemorySize64` (private commit) is recorded next to it, but it is not judged.

| Machine / run | Build | Working set | Private |
|---|---|---|---|
| retired (i5-6500, GT 730, driver 456.71, build 22000) | 042f5bb | 55.6 MiB | 44.2 MiB |
| 262cc47030b1 pass 1 run 1 | e71d7bd | 79.5 MiB | 63.7 MiB |
| 262cc47030b1 pass 1 run 2 | c5dd16f | 79.1 MiB | 62.9 MiB |

## 2. Method

- **The installed service (non-invasive):** read-only samples of working set, peak working set, private memory, handles and threads every 15 s for 40 minutes. The service was never stopped, restarted or signalled.
- **The replica:** the installed build's own staged runtime (`udcs-agent-stage-c5dd16f`: the same `python.exe` and `site`), run as the current user with its own data directory.
  - The helper named-pipe channel is off, so the replica can never take the installed service's pipe.
  - Each step is measured in turn, then the real `AgentApp` runs through idle → a synthetic cpu workload → E1 (in-process probe plus child worker) → shutdown, sampled every 2 s.
- **Differential:** the same idle measurement with the old code (042f5bb, built in a temporary git worktree, since removed) and the current code, each with and without NVML.
- **NVML isolation:** a bare interpreter measured around `nvmlInit`, device queries, `nvmlShutdown`, a second init, and `FreeLibrary`.
- **Scripts:** `tools/experiments/memory/` (`agent_phases.py`, `agent_idle_differential.py`, `nvml_cost.py`, `nvml_unload.py`, `sample_service.ps1`).
- **Not usable:** `psutil.memory_maps()`. On Windows it reports mapped region sizes, not resident pages (its total, 93.8 MiB, exceeds the 80.6 MiB working set), so per-DLL attribution here comes only from step deltas.

## 3. Where the idle 79 MiB goes (replica, c5dd16f runtime, step deltas)

| Step | Working set after | Δ working set | Private after | Δ private | Handles | Threads |
|---|---|---|---|---|---|---|
| interpreter + `site` (pywin32 `.pth`) | 20.8 | — | 13.5 | — | 165 | 4 |
| pywin32 service modules | 28.3 | +7.5 | 20.5 | +7.0 | 169 | 4 |
| `udcs_agent.app` / `service` imports (pydantic-core, httpx with OpenSSL, …) | 44.4 | +16.0 | 32.9 | +12.4 | 180 | 4 |
| **`nvmlInit()`** | **71.4** | **+27.0** | **57.5** | **+24.7** | 205 | 4 |
| PDH query (`\GPU Engine(*)`: **494** instances; `\GPU Process Memory(*)`: 37) | 76.9 | +5.5 | 62.4 | +4.8 | 296 | 6 |
| agent running, idle (governor, workload manager) | 78.2–80.6 | +2–3 | 62.7–65.3 | +2 | 324 | 9–11 |

The idle replica (79.4–80.6 MiB) matches the service's 79.1–79.5 MiB.

**NVML in isolation** (bare interpreter, 3 runs, ranges):

| Step | Working set | Private | Handles | Threads |
|---|---|---|---|---|
| `import pynvml` | 25.4–26.3 | 17.3–19.5 | 170 | 4 |
| `nvml.dll` loaded, not initialized | 25.5–27.0 | 16.9–19.9 | 170 | 4 |
| **`nvmlInit`** | **48.2–49.4** | **37.9–40.3** | **194** | 4 |
| device queries | 48.4–48.8 | 37.9–38.5 | 194 | 4 |
| `nvmlShutdown` | 48.4–48.8 | 37.9–38.7 | 194 | 4 |
| `nvmlInit` again / shutdown again | 48.1–49.4 | 37.5–39.3 | 194 | 4 |
| `FreeLibrary(nvml.dll)` ×10 | 48.7–48.8 | 38.2–38.8 | 195 | 4 (DLL still loaded) |

So `nvmlInit` costs about 21 MiB of private memory: an allocation inside the driver library, not a page-in of the DLL image (loading the DLL alone adds ~0). It is made once and kept.

## 4. Old code vs current code on this PC (the differential)

| Build | NVML | Idle working set | Idle private | Runs |
|---|---|---|---|---|
| 042f5bb (the retired machine's code) | on | 76.3–78.7 MiB | 60.9–63.5 MiB | 2 |
| c5dd16f (installed) | on | 77.2–79.4 MiB | 62.1–64.5 MiB | 2 |
| 042f5bb | **off** | 54.6–56.8 MiB | 40.8–43.2 MiB | 1 |
| c5dd16f | **off** | 55.0–57.2 MiB | 42.1–44.5 MiB | 1 |

- **The code since 042f5bb adds about 0.7 MiB.** Without NVML, both builds land on the retired machine's 55.6 / 44.2 MiB.
- **Assumption, not measurable any more:** NVML on the retired machine's GT 730 driver (456.71) cost little. That machine is gone. The inference rests on the no-NVML numbers matching its result, on the same code.

## 5. Growth vs baseline: phases

- **Idle and workload** (replica, 45 s each, 22 samples per phase): working set 78.2–80.7 MiB, private 62.7–65.3 MiB, threads 8–11. No trend; the band is the governor's 1 s tick churn. The workload runs in its own process; the agent adds a few handles (324 → 330).
- **E1 (child workers):** during context creation, private memory peaks at **171 MiB** (CUDA/PTX loading). That matches the installed service's `PeakWorkingSet` of 184 MiB. Afterwards the process keeps **+21 MiB working set, +14 MiB private, about +190 handles and +9 threads** (`nvcuda.dll`, `nvcuda64.dll`, `nvobjectloader64.dll`, `nvapi64_impl.dll` and others stay loaded).
  - The child worker's own memory goes away with the child.
  - The retained part comes **only** from the `service_process` arrangement, which runs the probe inside the agent.
- **After E1** (30 s idle): 99.2–102.4 MiB, flat.
- **Shutdown:** after the agent's `run()` returns, the process still holds 101 MiB. That is normal: the process then exits, and the service host does not reuse it.
- **Recovery:** a crash restart is a new process, so it starts from the same baseline. That is what the six fresh-start replica runs measure (76–80 MiB). It was **not** measured on the service after a real recovery, because that would mean repeating the crash test, which this investigation excludes.
- **The installed service** (pid 25784, after the E1 re-check): see the long-run section.

## 6. Root cause

1. **The idle number (79 MiB):** a ~57 MiB agent baseline (interpreter, pywin32, pydantic, OpenSSL, PDH, threads), **plus a fixed ~21 to 23 MiB that NVIDIA's NVML allocates in `nvmlInit`** on this driver. The agent calls `nvmlInit` at startup (`app.py:75-76`), even when nothing will use NVML (local-only / not enrolled), and the memory can never be given back while the process lives.
2. **The current 95 MiB of the installed service:** that, **plus** the CUDA driver state that E1's in-process `service_process` probe loads into the agent and keeps (+21 MiB working set).
3. **Not a cause** (checked): code growth since the retired build (+0.7 MiB), a leak (flat over time), threads, or handles (idle 324 handles / 11 threads, stable).
4. **Contributing factor:** the PDH GPU-engine counter set scales with *processes × GPU engines* (494 instances here) and costs ~5.5 MiB. It will be larger on busy lab PCs. This is unmeasured beyond this machine.

## 7. Recommended fix (not implemented; for decision)

1. **Initialize NVML lazily, only for its users.** Start it inside the controller link, before the first inventory or telemetry call, not at `AgentApp.run()`.
   - Effect: a local-only or unenrolled agent stays at ~57 MiB, measured with NVML off.
   - Risk: low. The governor does not use NVML.
   - Test: a unit test that `AgentApp` without enrollment never calls `nvmlInit`, plus an idle measurement.
2. **For enrolled nodes, decide whether the NVML cost is worth it.** NVML supplies per-GPU inventory and telemetry: name, memory, temperature, power. PDH already supplies utilization and dedicated memory. Options:
   - **(a) keep NVML** and budget ~80 MiB plus a documented NVIDIA driver allowance;
   - **(b)** collect NVML inventory and telemetry in a **short-lived child process** at the heartbeat cadence, at the cost of a process start every 15 s (its time and transient memory are **unmeasured**; the interpreter plus NVML alone is about 49 MiB, per section 3);
   - **(c)** use PDH for runtime telemetry and run NVML only in a child at enrollment and inventory refresh.

   **Recommendation: (c).** It keeps the long-lived service small without losing data the controller uses for scheduling. **To verify:** whether the telemetry fields NVML provides are used by the scheduler (not checked in this investigation).
3. **Do not run CUDA inside the service for E1.** The `service_process` arrangement answered its research question (CUDA works in session 0 in the service process). Keep `service_child_worker`, which is the arrangement UDCS uses, and either drop `service_process` or run it only behind an explicit flag that says the agent will keep ~20 MiB until it restarts.
4. **Make the overhead check honest about what it measures:**
   - record private memory as well as the working set, and judge it;
   - record whether NVML was initialized and whether E1 has run in the process;
   - keep the limit unchanged until a decision on (1) and (2). With (1), the current check would read ~57 MiB on this PC. That reflects the agent's real idle cost when unenrolled, but it would no longer exercise the enrolled configuration, so an enrolled overhead measurement is also needed.

**Not changed:** the 80 MiB limit, the agent code, the installed build (c5dd16f plus the cd02387 `gpu_probe.py`), and all evidence files.

## 8. Reproducibility and limits

- **Reproducible:**
  - `nvmlInit` cost: 3 runs within ±1.2 MiB;
  - each build's idle: 2 runs within 0.4 MiB;
  - the replica matches the installed service within 1 MiB.
- **Limits:**
  - one machine and one NVIDIA driver;
  - the replica runs as the user (session 1), not as LocalSystem in session 0, with the helper channel off;
  - recovery was not measured on the real service;
  - the GT 730 / driver 456.71 NVML cost is inferred, not measured.
  - In the replica, E1's `service_child_worker` failed ("probe produced no result"), unlike in the real service. That is a user-context difference not investigated here; it does not affect the memory attribution, because the child's memory is not the agent's.

## 9. Long-run sample of the installed service

`sample_service.ps1`: pid 25784, 160 samples every 15 s, 23:19:53–23:59:40. The service had been up about 80 minutes, after the E1 re-check. It was never stopped or signalled.

| Metric | Min | Max | Mean | First-half mean | Second-half mean | Trend |
|---|---|---|---|---|---|---|
| Working set | 93.3 MiB | 96.0 MiB | 95.1 MiB | 95.3 | 94.8 | −1.4 MiB/h |
| Private | 68.2 MiB | 71.0 MiB | 70.2 MiB | 70.5 | 69.9 | −1.5 MiB/h |
| Handles | 434 | 525 | — | — | — | falling |
| Threads | 15 | 16 | — | — | — | flat |

`PeakWorkingSet` stayed at 183.9 MiB, set during E1. **No growth:** the service's ~95 MiB is a plateau (the NVML baseline plus retained E1 CUDA state), and it drifts slightly down.
