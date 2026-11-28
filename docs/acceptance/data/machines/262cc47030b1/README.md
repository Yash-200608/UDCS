# Acceptance machine `262cc47030b1`

Designated as the M1.5 acceptance machine on 2026-11-28 (decision D-6), after the original build 22000 machine was retired. The label is the first 12 hex characters of SHA-256 of the lower-cased host name; the host name itself is not recorded.

| Fact | Value (read 2026-11-28) |
|---|---|
| Edition | Windows 11 Home Single Language (`CoreSingleLanguage`), 26H2 |
| Build | 10.0.26300 (UBR 26300.10075) |
| CPU | Intel Core i5-14400F, 10 cores / 16 threads |
| RAM | 31.7 GiB |
| GPU | NVIDIA GeForce RTX 3060, driver 32.0.16.2124 |

`m15-service-acceptance.json` is written here by `tools/acceptance/m15_service_acceptance.ps1` (pass 1, then pass 2 after a reboot), and it records the same facts in its `machine` field.

## Pass 1, run 1: 2026-11-28, founder-run, elevated, agent built from commit e71d7bd. **All 9 checks PASS.**

*(Its report is kept as `m15-service-acceptance.json.replaced-20261128-213205`, together with pass 2 attempt 1. An earlier version of this README said "8 checks": a miscount.)*

| Check | Result |
|---|---|
| `service_starts` | started in 0.41 s; first governor status after 5.6 s |
| `session0_localsystem` | session 0, LocalSystem, Auto (delayed) |
| `no_visible_windows` | 0 windowed processes |
| `service_overhead` | **79.5 MiB RSS against an 80 MiB limit** (63.7 MiB private), 0.21% of one core |
| `helper_and_presence` | helper reports `active`; level `shared` (`user_active`) |
| `workload_managed` | `accept-cpu` throttled under protection, 811 units |
| `crash_recovery` | service restarted after 5.5 s; workload resumed after 0.8 s from unit 891 |
| `e1_completed` | E1 finished in 2.6 s (see below) |
| `graceful_stop` | stopped in 0.27 s, 0 workload processes left |

- **E1 (CUDA from the service), RTX 3060, CC 8.6:**
  - the service process (session 0) and its child worker both work: contexts of 124 and 73 ms, kernels around 20 ms;
  - so does a SYSTEM worker in the interactive session (session 1);
  - the worker as the logged-on *user* fails with "probe produced no result" (exit 1). That arrangement failed the same way on the retired machine and is excluded by design: UDCS never runs work as the student. Not investigated.
- **Weak point: service overhead passed with a 0.5 MiB margin.** The retired machine measured 55.6 MiB, with older agent code. Why RSS grew, and whether 80 MiB is the right limit, is an open question. The limit was not changed.
- **Redaction (2026-11-28, before the first commit):**
  - The E1 probe recorded its `account` as `os.environ["USERNAME"]`. For LocalSystem that is the machine account, `HOSTNAME$`, so the host name was in the file.
  - The three occurrences were replaced with `"<host>$"` by exact text replacement; nothing else changed.
  - The probe now records `NT AUTHORITY\SYSTEM` or `<user>`, taken from the token SID.
  - `tests/test_acceptance_evidence.py` fails on any machine-account name in per-machine evidence.
  - The installed service still runs the e71d7bd code with the old probe. Pass 2 does not run E1, so this file is not affected again.

## Pass 2, attempt 1: 2026-11-28 20:33, founder-run. **`starts_after_reboot` FAIL, `helper_started_at_logon` PASS.**

The JSON records this attempt exactly as the script wrote it.

- **What happened (event log and process times, read afterwards):**
  - The PC booted at 20:31:10.
  - UDCSAgent is delayed-auto-start: the SCM started it at 20:33:27, **136.8 s after boot, on its own**. The Application log shows "UDCSAgent starting (pid 17160)".
  - Pass 2 wrote its file at 20:33:28.
  - It had read the service state once, *before* that start, and saw `Stopped`. It then waited for a fresh governor status, which arrived from the newly started service, hence `governor_status_fresh: true`.
  - With the service stopped, its PID was 0, and the script read the System Idle Process start time, hence `service_started_after_boot_s: -63931494670.5`.
- **Verdict:** a **harness defect**, not evidence that the service fails to start; the service did start after the reboot. This attempt still stays recorded as a FAIL: it is not edited into a pass.
- **Harness fixed:**
  - pass 2 now waits up to 300 s for the service to be `Running`;
  - it reads the process start time from `Win32_Process.CreationDate` and never from PID 0;
  - it keeps every earlier attempt in `pass2_attempts`, instead of overwriting it.
- **A real defect found at the same reboot: the shutdown is not clean.**
  - At 20:30:59 the SCM logged event 7024: "The UDCS Node Agent service terminated with the following service-specific error: 0x20000001".
  - There is no "UDCSAgent stopped" entry, whereas pass 1's manual stop logged "stopped (exit 0)".
  - **`agent.log`, read elevated by the founder:** `15:00:59.265Z "agent stopped", "shutdown_ms": 16, "reason": "stop requested"`. So the agent itself stopped cleanly, in the same second as the SCM error.
  - **Suspected cause (consistent, not confirmed):**
    - after `run()` returns, `SvcDoRun` writes "stopped" to the Application log;
    - that entry is missing;
    - pywin32 documents that an exception escaping `SvcRun` makes it report SERVICE_STOPPED with a non-zero code;
    - the Event Log service is presumably already stopping at shutdown.
    - `0x20000001` is not in pywin32's message table (its codes are `0xC000000x`), so the code itself is unexplained.
  - **Fix (implemented and unit-tested; not yet verified at a real shutdown):** the event-log writes are best-effort, any failure is logged to `agent.log`, and a final "service run returning" line is logged. `node_agent/tests/test_service_windows.py` fails without the fix.
  - **To verify:** upgrade the installed agent, which needs approval, reboot, then check that SCM records no 7024 and that `agent.log` shows "service run returning", plus "event log write failed" if the hypothesis is right.
  - **Pass 2 now checks this as `clean_shutdown_before_boot`:** no SCM 7023/7024/7031/7034 for UDCSAgent between the end of pass 1 and the boot. On today's events it finds exactly this 7024 and excludes pass 1's deliberate crash test (7031 at 20:17:56).
  - M1.5 cannot be accepted while this is open: workloads must checkpoint and stop cleanly when the PC shuts down.

## Pass 1, run 2: 2026-11-28 21:32, founder-run, after uninstall and reinstall, agent built from commit c5dd16f (shutdown fix). **All 9 recorded checks PASS, but E1 regressed.**

This is `m15-service-acceptance.json`. The previous report was kept by `-ReplaceEvidence`.

| Check | Result |
|---|---|
| `service_starts` | 0.44 s; first status after 5.4 s |
| `session0_localsystem`, `no_visible_windows` | PASS |
| `service_overhead` | 79.1 MiB RSS against an 80 MiB limit (62.9 MiB private), 0.47% of one core |
| `helper_and_presence`, `workload_managed` | PASS (`throttled`, 810 units) |
| `crash_recovery` | restarted after 5.4 s; resumed after 0.5 s from unit 890 |
| `e1_completed` | PASS, but this only means the GPU check finished |
| `graceful_stop` | 0.26 s, 0 processes left |

- **E1 regression, caused by my redaction fix:**
  - The service process still works: account `NT AUTHORITY\SYSTEM`, RTX 3060, 20 ms kernels.
  - But `service_child_worker` and `session_worker_system`, which worked in run 1, now fail with "probe produced no result".
  - **Cause, reproduced with the staged interpreter:** the new `_account()` imported pywin32 (`win32api`). The E1 children run `python -I`, where pywin32's DLLs are not on the search path, so `ImportError: DLL load failed while importing win32api` killed `probe()` before it wrote a result.
  - **Fixed:** the identity lookup uses `ctypes` only (`OpenProcessToken`, `GetTokenInformation(TokenUser)`, `IsWellKnownSid`) and cannot raise. `node_agent/tests/test_gpu_probe_windows.py` launches the probe exactly like an E1 child; it fails on the c5dd16f code and passes on the fix.
  - The **installed** agent (c5dd16f) still has the broken probe, so this run's E1 child result is a valid record of that build.
- **Harness weakness exposed:** `e1_completed` passed although the children failed. Pass 1 now also records `e1_used_arrangements_ok`, which requires `service_process` and `service_child_worker` to succeed.
- **Service overhead** is again within 1 MiB of the limit (79.1 MiB): consistent, and still unexplained.

**Pass 2 for run 2: not run yet.** It needs a reboot, and its main purpose is to verify the shutdown fix on this build.

**Scope.** This is new evidence for one machine, not proof of lab compatibility:
- lab images are Pro, Education or Enterprise, often domain-joined and under Deep Freeze;
- this PC runs Home edition;
- its GPU is a modern one.

The lab-image gate (ADR 0001 gate 2) and the second-machine check (ADR 0004 open item 1) stay open regardless of what is recorded here.

The retired machine's records in `../../m15-service-acceptance.json` and `../../m2-isolation-service.json` are history and are never written. `tests/test_acceptance_evidence.py` pins their content.
