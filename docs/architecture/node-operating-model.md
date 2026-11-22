# Node Agent Operating Model

> **The local student always takes priority. UDCS borrows computing resources; it never takes ownership of the computer.**

This document turns that principle into mechanisms, measurable budgets and experiments. Every node-agent design decision must be checked against it.

Evidence labels: **[measured]** = measured on the dev PC (i5-6500 4C/4T, 24 GB, GeForce GT 730 + Intel HD 530, Windows 11 Pro Education 22000), 2026-11-21. **[documented]** = from primary documentation, verified by an independent fact-check (per-claim sources in [research/2026-11-21-node-operating-model.md](../research/2026-11-21-node-operating-model.md)). **[proposed]** = design, not yet built. **[open]** = unknown, with a planned experiment.

## 1. What "the student never notices" means — measurable budgets

A principle can't be tested, but a budget can. These are the acceptance criteria every node-agent milestone is judged against. The numbers are **[proposed]** starting points, to be tuned against real lab measurements.

| # | Budget | Target | How it is measured |
|---|---|---|---|
| B1 | Foreground slowdown while UDCS work runs | ≤ 5% on CPU-bound, ≤ 10% on memory-bound foreground benchmarks (median) | the foreground benchmarks from §2, run on every node hardware class |
| B2 | Reaction time to a student becoming active or a load spike | throttle within **2 s**, CPU freed within **5 s** | event-to-cap latency in the governor's logs |
| B3 | Memory released when the student needs it | job working set back under policy within **10 s**, or job evicted | test with a synthetic memory-pressure load |
| B4 | GPU | **no TDR resets ever**; no GPU jobs while there is interactive GPU demand (Phase 1) | event log 4101 (display driver reset), PDH counters |
| B5 | Shutdown / logoff / sleep | UDCS adds **< 2 s** to shutdown; never blocks sleep unless an admin policy allows it | `powercfg /requests`, shutdown timing |
| B6 | Agent's own idle overhead | ≤ 80 MiB RSS, ≤ 0.5% of one core on average, 0 open listening ports | **[measured]** today: ~55 MiB, ~0.1% at a 15 s heartbeat |
| B7 | Nothing visible | no windows, tray icon, notifications or console flashes for students | manual check on each release |

## 2. What we measured on this PC

| Experiment | Result | Consequence |
|---|---|---|
| 4 CPU-bound background processes vs. a CPU-bound foreground task | NORMAL priority: **1.33×** slower; BELOW_NORMAL: 0.89×; IDLE: 0.90× (no measurable slowdown) **[measured]** | For pure compute, Windows' strict priority scheduling already puts the student first. Running work at IDLE priority is the baseline, not killing it. |
| 3 memory-bandwidth-bound background processes vs. a memory-bound foreground task | NORMAL: **2.16×**; IDLE: **1.27×**; IDLE + 25% CPU cap: 1.28× **[measured]** | **Priority does not protect memory bandwidth**, and a CPU cap alone did not help. Memory-heavy jobs need pressure-aware pausing while a student is active. |
| Job Object hard CPU cap, changed while the job runs | 20% → 22.2%, 5% → 4.8%; suspend and resume work **[measured]** | Gradual throttling works on Windows 11 Pro, not just on Server editions. |
| Processes added to a job *after* they start | children escaped the job (the venv `python.exe` is a launcher that spawns the real interpreter) **[measured]** | Workloads must be **created inside the job** (CREATE_SUSPENDED → assign → resume, or `PROC_THREAD_ATTRIBUTE_JOB_LIST`), using the base interpreter, never the venv redirector. |
| PDH `\GPU Engine(*)\Utilization Percentage` | works; instances are per-PID and per-engine, even where NVML reports utilization as *Not Supported* **[measured]** | This is the way to tell the student's GPU use apart from UDCS's. |
| NVML per-process queries on driver 456.71 | raise `NVMLLibraryMismatchError`, which is *not* an `NVMLError` **[measured]** | A Milestone 1 crash bug; **fixed**, with regression tests. Old GPUs are pinned to old drivers, so this happens in real labs. |
| `WTSSessionInfoEx` for the console session | lock state available; `LastInputTime` = 0 **[measured]** | A service can tell whether the session is locked but not how long the student has been idle. That needs a per-session helper (§5). |
| CUDA driver API from the user session | context and 64 MiB allocation OK on the GT 730 **[measured]** | Baseline for experiment E1 (does it also work from session 0?). |
| Python agent footprint | 55 MiB RSS steady; 15.6 ms CPU per telemetry sample **[measured]** | Within B6. Python stays for the service; the per-session helper should be native (§5). |

These are single runs on one machine: the directions are reliable, the exact ratios are not. The benchmark scripts become a repeatable suite in Milestone 1.5.

## 3. Architecture of the agent

```
                         ┌──────────────── controller (policy, placement) ─────────────┐
                         │  heartbeats, telemetry, job assignments, policy documents   │
                         └───────────────────────────▲─────────────────────────────────┘
                                                     │ HTTPS (agent dials out)
┌───────────────────────── UDCS Node Agent service (session 0) ───────────────────────────┐
│  Controller link   ── heartbeats, inventory, assignments (seconds-to-minutes timescale) │
│  Governor          ── LOCAL control loop, ~1 s: signals → state → resource envelope     │
│  Executor (M2)     ── launches workloads inside Job Objects, applies the envelope       │
│  Session watcher   ── WTS session events, lock state, presence power notifications      │
└──────────────▲───────────────────────────────────────────────▲──────────────────────────┘
               │ named pipe (DACL-restricted)                  │ Job Object handles
   ┌───────────┴────────────┐                      ┌───────────┴─────────────┐
   │ Session helper (native)│  one per logged-on   │ Workload processes      │
   │ idle time, full-screen,│  session, invisible  │ low-priv account, IDLE  │
   │ presentation mode      │                      │ priority, capped        │
   └────────────────────────┘                      └─────────────────────────┘
```

**Rule 1 — the student's protection never depends on the network.** The governor decides locally within B2's time limits, using the last policy the controller sent. If the controller is unreachable, the agent keeps protecting the student and stops starting new work. It never stops protecting. **[proposed]**

**Rule 2 — fail toward the student.** Missing or stale data (no helper report, PDH failure, unknown session state) is treated as *student present and busy*, never as *idle*. The research found both BOINC and HTCondor fail toward "idle" in some cases, and that is the mistake to avoid. **[proposed]**

**Rule 3 — the controller owns policy; the agent owns enforcement.** The controller ships a versioned policy document (thresholds, allowed hours, per-class envelopes). The agent can only be *more* conservative than that policy, never less. **[proposed]**

## 4. Signals

| Signal | Source | Who reads it | Status |
|---|---|---|---|
| Session logon/logoff/lock/unlock | `SERVICE_CONTROL_SESSIONCHANGE`; `WTSSessionInfoEx.SessionFlags` at startup | service | **[documented]**, lock state **[measured]**. Notifications can be missed if the service starts after logon (delayed start), so sessions must be enumerated at startup |
| User presence | `GUID_GLOBAL_USER_PRESENCE` (sent only to session-0 programs), `GUID_CONSOLE_DISPLAY_STATE` | service | **[documented]**; whether an initial state is delivered on registration is **[open]** |
| Input idle time | `GetLastInputInfo` (session-scoped) | session helper | **[documented]**; service-side WTS idle **[measured]** unavailable |
| Full-screen / presentation / busy | `SHQueryUserNotificationState` | session helper | **[documented]** |
| Non-UDCS CPU load | total CPU − CPU used by UDCS jobs (Job Object accounting) | service | **[proposed]**, same idea as HTCondor's `NonCondorLoadAvg` |
| Memory pressure | available memory, commit charge, hard page-fault rate; `CreateMemoryResourceNotification` | service | **[documented]**; thresholds **[open]** |
| Non-UDCS GPU load | PDH GPU Engine utilization for PIDs not in UDCS jobs | service | **[measured]** working |
| GPU memory pressure | PDH `GPU Process Memory`, `GPU Adapter Memory`; NVML device memory | service | **[measured]** counters present |
| Disk pressure | PDH disk queue length; job I/O accounting | service | **[documented]** (per-job *I/O rate control* is **not supported** on Windows 10 1607+, so UDCS detects and pauses instead) |
| GPU temperature | NVML | service | **[measured]** |

**Input idleness is not interactive demand.** A student compiling, rendering or training a model may not touch the keyboard for minutes while the machine is fully loaded. Capacity decisions combine presence *and* measured non-UDCS pressure. Neither signal alone is enough. **[proposed]**

**Privacy.** The agent sends only **coarse, derived states** to the controller (§6). It never sends window titles, process names of student applications, keystroke timing or raw idle timestamps. Milestone 1 sends raw `user_idle_seconds`; that will be replaced (§10). **[proposed]**

## 5. The per-session helper

- **Why it's needed:** a session-0 service cannot see input or foreground state **[measured / documented]**. HTCondor (`condor_kbdd`) and BOINC (`boinctray`) both use the same pattern.
- **What it is:** one tiny process per logged-on session, started from the HKLM `Run` key or a logon task. It has no window, no tray icon and no network access, and reports to the service over a named pipe whose DACL allows only the service and interactive users.
- **Trust model:** a student controls their own helper. A forged report must only ever make UDCS **more** conservative. "Busy/present" takes effect at once; "idle" requires sustained, corroborated evidence. The service identifies each client with `GetNamedPipeClientProcessId` / `GetNamedPipeClientSessionId` so one session can't speak for another. **[proposed]**
- **Implementation language:** a Python helper would cost about 17+ MiB per session plus interpreter startup at every logon. A small native helper (C, C++ or Rust; on the order of a few MiB) better fits B6/B7. This would add a second toolchain to the repo, so it's a decision for the founder (§11, D-2). **[proposed]**

## 6. Node states and resource envelopes

The governor classifies the node every second **[proposed]**:

| State | Meaning | Default envelope for UDCS work |
|---|---|---|
| `NO_USER` | nobody logged on, or the only session is disconnected and idle | full CPU (still IDLE priority), RAM up to policy, GPU allowed |
| `USER_AWAY` | session locked, or no input for ≥ N min, *and* low non-UDCS load | CPU up to a policy cap (e.g. 75%), RAM capped, GPU allowed only if there is no interactive GPU demand |
| `USER_LIGHT` | active, low non-UDCS CPU/memory/GPU load | CPU-bound work continues at IDLE priority with a cap (e.g. 50%); memory-bound work paused; **no GPU work (Phase 1)** |
| `USER_HEAVY` | active and the machine is under real pressure | all work at ~0–5% cap or paused; checkpoint and evict if it continues past policy time |
| `PROTECTED` | full-screen, presentation or exam mode, or a policy calendar slot (e.g. a lecture in this lab) | everything paused; nothing new starts |
| `MAINTENANCE` | admin set it, or Windows Update / imaging is running | no UDCS work |

**Hysteresis:** go up in protection within ≤ 2 s; come down only after the condition has held steadily (e.g. 60 s), with an extra delay after unlock or logon (e.g. 5 min). This avoids visible stop/start flapping. **[proposed]**

**Login alone does not kill jobs.** A login moves the node to `USER_LIGHT`, where CPU-bound work keeps running at IDLE priority. That's justified by the measured 0.90× result. Whether jobs are throttled further depends on measured pressure, not on the login itself.

## 7. The action ladder

Actions escalate one rung at a time, each with a deadline before the next:

1. **Run at the lowest priority** (always): IDLE priority class, priority boost disabled (`SetProcessPriorityBoost`), low memory priority, EcoQoS where supported. **[documented]**
2. **Cap CPU live:** Job Object hard cap, adjusted every governor tick. **[measured]**
3. **Limit memory:** job commit cap (allocations fail; no OOM kill) and a working-set limit, against pressure on the student's pages. **[documented]**; paging cost **[open]**
4. **Cooperative pause / checkpoint:** signal the workload and let it checkpoint and park within a deadline (e.g. 30 s). **[proposed]**, part of the workload contract (§8)
5. **Thread suspension:** fallback for non-cooperative CPU jobs. It keeps RAM and VRAM allocated, and it relies on debugger-oriented APIs, so it's short-term only. **[documented]** with caveats
6. **Checkpoint and evict:** the process exits, freeing RAM and VRAM, and the job is resumed later, possibly on another node. **[proposed]**
7. **Kill:** last resort; the job is marked `INTERRUPTED` per its recovery policy. **[proposed]**

**GPU jobs skip rungs 2, 3 and 5.** A CPU cap doesn't free the GPU, a suspended CUDA process keeps its VRAM, and WDDM pages VRAM to system memory instead of failing, which hurts both sides. On Windows GeForce there is no MPS, no MIG, no TCC, and no driver checkpointing (NVIDIA's checkpoint API is Linux-only) **[documented]**. So "pause a GPU job" can honestly mean only: stop submitting work, then checkpoint at the application level and exit. In Phase 1, GPU work runs only when there is no interactive GPU demand.

## 8. Workload contract (for Milestone 2)

UDCS can't transparently checkpoint arbitrary processes (HTCondor removed this too), so jobs that want to survive interruption must cooperate:

- **Inputs:** `UDCS_CHECKPOINT_DIR`, and a pause/checkpoint request channel (a named event or pipe; a small Python helper library provides `udcs.should_checkpoint()`).
- **Exit codes:** a reserved code means "checkpointed, please reschedule"; anything else non-zero is a failure.
- **Declared capabilities:** checkpointable yes/no, expected checkpoint duration, GPU required, maximum kernel duration.
- **GPU jobs** must keep each kernel well under the 2 s TDR limit. UDCS never changes TDR registry keys, which Microsoft reserves for driver development.
- **Non-checkpointable jobs** are placed only on nodes and time windows where interruption is unlikely (`NO_USER`, policy night windows), and are told their recovery policy up front.

## 9. Service, process and fleet mechanics

| Topic | Decision | Basis |
|---|---|---|
| Start type | Automatic (Delayed Start) | **[documented]** |
| Recovery | restart on failure, with the failure-actions flag set so non-crash failures also trigger it | **[documented]** |
| Account | LocalSystem is needed to launch workloads under a separate low-privilege account (`LogonUser` + `CreateProcessAsUser`). The cost: the agent is highly privileged, so it opens no listening ports, validates everything, and ships signed binaries | **[documented]**; risk recorded in the threat model |
| Service host | `pywin32` service framework, using the base interpreter, not the venv redirector | **[documented]** / **[measured]** |
| Workload launch | `CreateProcessW` with CREATE_SUSPENDED → assign to job → resume (Python's `subprocess` can't do this) | **[measured]** |
| Agent crash | Phase 1: jobs live in a kill-on-close job and die with the agent; resumption comes from checkpoints. A separate job-holding supervisor process is **[future]** | **[documented]** trade-off |
| Shutdown | no checkpointing at preshutdown (10 s default since Windows 10 1703); jobs checkpoint periodically instead | **[documented]**, B5 |
| Sleep | never keeps a PC awake by default; any power request is cleared the moment a job pauses; jobs checkpoint on `PBT_APMSUSPEND` | **[documented]**, B5 |
| Reboot-to-restore (Deep Freeze etc.) | node identity, checkpoints and job cache live in a ThawSpace or are re-fetched from the controller; Deep Freeze "idle time" restarts must be reconciled with IT policy | **[documented]**, operational dependency |
| Application control | allowing `python.exe` implicitly allows any `.py` file, so security comes from the workload account's token and sandboxing, not from App Control | **[documented]** |
| Enrollment | **correction to Milestone 1:** reusable, lab-scoped enrollment keys (expiry, maximum uses) deployed with the MSI; new nodes enter `pending` until approved (or auto-approve per key) | **[proposed]** |
| GPU eligibility | the controller gates GPU placement on compute capability (≥ 7.5 for current prebuilt PyTorch); the GT 730 (CC 3.5) is CPU-only for UDCS | **[documented]** |

## 10. Consequences for the Milestone 1 code

| # | Change | Why |
|---|---|---|
| C1 | **Done:** NVML errors from bindings newer than the driver are handled | crash on old lab drivers **[measured]** |
| C2 | Telemetry reports **UDCS usage and non-UDCS usage separately** (CPU, RAM, GPU) | otherwise the controller sees UDCS's own load as the student's |
| C3 | Replace `user_idle_seconds` with a coarse `interactive_state` | privacy and fail-safe semantics |
| C4 | Fleet enrollment keys plus a `pending` admin state | IT deploys to many PCs at once |
| C5 | Report node class data: driver model (WDDM), HAGS, a second GPU (iGPU/dGPU), deep-freeze state | placement and policy |
| C6 | Split the agent into a governor loop and the heartbeat loop | Rule 1 |
| C7 | Windows service host with recovery and delayed start | the core of the operating model |

## 11. Decisions for the founder

- **D-1. Milestone order.** I recommend inserting **Milestone 1.5, "Background service and governor"** (C2–C7, plus a session helper prototype) before job execution. Running jobs before the student-protection loop exists would mean testing the riskiest behaviour without its safety net.
- **D-2. Native session helper** (adds a C/C++/Rust toolchain) vs. a Python helper (larger per-session footprint).
- **D-3. Isolation strategy** (from the earlier architecture review): still open, and it still blocks Milestone 2.
- **D-4. Power policy:** may UDCS ever keep lab PCs awake (e.g. at night windows), or never? This is an energy-cost and IT-policy question.

## 12. Experiments still required

| ID | Question | How | Needs |
|---|---|---|---|
| **E1** | Can a CUDA context be created from session 0 (as the service will run)? | `tools/experiments/cuda_context_probe.py` as SYSTEM | an elevated shell; repeat on RTX 3060 / 4060 Ti nodes. **If it fails, the GPU design changes**: work would need launching inside the user session, which conflicts with the operating model |
| E2 | Does `D3DKMTSetProcessSchedulingPriorityClass` actually lower CUDA's GPU priority on NVIDIA WDDM drivers? | a GPU-bound job vs. a frame-time benchmark | an RTX node |
| E3 | The paging cost of a working-set cap on the workload | memory-bound job with and without a cap | any node |
| E4 | Native vs. Python helper footprint and logon delay | prototype both | any node |
| E5 | How quickly the Job Object CPU cap takes effect (the scheduling interval is undocumented) | high-frequency sampling around a cap change | any node |
| E6 | Memory-pressure thresholds that keep B1 for memory-bound foreground work | parameter sweep | lab hardware classes |
| E7 | Does input on the lock screen or a UAC prompt update the user session's last-input time? | helper prototype | any node |
