# Development Status

_Last updated: 2026-11-22. Development checkpoint on branch `feature/udcs-background-agent-m15`. This is **not** a release, and Milestone 1.5 is **not accepted**._

## Summary

| Milestone | State |
|---|---|
| M1: Working Foundation | **Met**, verified live over TLS on one Windows 11 PC. The "no terminal" gap is now covered by the M1.5 service, which is not yet verified as a service. |
| M1.5: Background Service & Local Resource Protection | **Implemented. Tested without admin rights. NOT accepted.** Six acceptance gates are still open (see below). Report: [docs/acceptance/milestone-1.5.md](docs/acceptance/milestone-1.5.md) |
| M2a: Distributed execution pipeline (catalog workloads only) | **Implemented and tested** on one PC with two agent instances: controller → scheduler → agent → Job Object workload → telemetry → verified result, plus recovery. See [execution-pipeline.md](docs/architecture/execution-pipeline.md) |
| M2b: Isolation for workloads (D-3) | **Decided: [ADR 0001](docs/decisions/0001-workload-isolation.md). Native AppContainer backend implemented and tested; the catalog runs inside it where a node verifies it.** User code is still **disabled**: the service-path gate (elevated) is open |

## Status legend

| Label | Meaning |
|---|---|
| **tested** | Implemented, with automated tests that pass on this checkout |
| **verified live** | Also exercised by hand on real hardware |
| **implemented, unverified** | Code exists, but the path that matters has not run |
| **pending** | Not done |

## Component status

### Control plane (M1, with the M1.5 extensions)

| Component | State | Evidence |
|---|---|---|
| uv workspace (shared / controller / agent), pinned `uv.lock` | tested | `uv sync`; the whole suite |
| Controller config, app factory, health and readiness | tested | `test_auth.py` |
| DB models plus Alembic migration `0001` | tested on SQLite | migrations ≡ models check; downgrade and upgrade round-trip |
| Migration `0002`: lab keys, pending state, rotation | tested on SQLite | `test_schema_and_units.py`; the PostgreSQL DDL was checked only by offline rendering |
| **PostgreSQL path** | **tested in CI (PostgreSQL 16)** | Run [44985979000](https://github.com/Yash-200608/UDCS/actions/runs/44985979000): a clean database, then `udcs-controller migrate`, reaching head `0002`; models match the migrations; **57/57** shared and controller tests passed with `UDCS_REQUIRE_POSTGRES=1`. Earlier runs: 44984896914 never reached PostgreSQL (Windows-only agent tests crashed collection on Linux), and 44985672167 got to 56/57 (the audit ordering bug, now fixed) |
| Migration 0002 data logic (real M1 rows, up and down) | tested on SQLite | `test_migration_data.py`. It found a **bug in the 0002 downgrade**: on SQLite the batch rebuild of `nodes` triggered `ON DELETE SET NULL` and erased the token→node links. Fixed |
| User auth: Argon2id, opaque sessions, rate limit, RBAC | tested | `test_auth.py` |
| Admin user management | tested | `test_auth.py` |
| Lab enrollment keys (expiry, use limit, revoke, atomic claim) | tested | `test_enrollment_identity.py` |
| Pending approval of new nodes | tested | `test_enrollment_identity.py` |
| Two-phase node credential rotation | tested | `test_enrollment_identity.py` |
| Heartbeat (protocol v2), telemetry, online/offline | tested, verified live (M1 protocol) | `test_nodes.py`, e2e |
| Controller-supplied protection policy (can only tighten) | tested | `shared/tests`, `test_governor_logic.py` |
| Student-facing resource summary (no node identities) | tested | `test_nodes.py` |
| Append-only audit log | tested | `test_nodes.py`, `test_auth.py` |
| Prometheus `/metrics` | pending | — |

### Node agent

| Component | State | Evidence |
|---|---|---|
| Hardware and NVIDIA discovery (NVML) | tested, verified live (GT 730) | `test_discovery.py` |
| HTTPS client: TLS ≥ 1.2, CA pinning, back-off, revocation stop | tested | `test_client.py`, `test_runner.py`, e2e |
| DPAPI credential at rest | tested on Windows | `test_config_and_credentials.py` |
| Governor: 1 s loop, smoothed signals, enter/exit thresholds, time hysteresis, fail-safe rules | tested | `test_governor_logic.py` |
| Usage split (total / UDCS / non-UDCS) and coarse presence states | tested | `test_governor_logic.py`, benchmarks |
| Per-class protection: CPU cap, memory freeze/pause/evict, disk pause, GPU pause | tested (real Job Objects) | `test_workloads_windows.py`, B1/B2 benchmarks |
| Synthetic workloads with checkpoint and resume | tested | `test_workloads_windows.py` |
| Local protection while the controller is unreachable; fail-closed no-work state | tested | `tests/e2e/test_agent_app.py` |
| Hardened per-session helper pipe | tested as a normal user | `test_governor_logic.py` |
| Data-directory ACL check | tested | `test_governor_logic.py` |
| **Windows service host (pywin32)** | **implemented, unverified as a service** | needs `m15_service_acceptance.ps1` elevated |
| **Installer / uninstaller (ACL hardening, recovery, delayed auto-start)** | **implemented, unverified** | the same script |
| **Session helper autostart at logon** | **implemented, unverified** | the same script |
| GPU diagnostic E1 (service vs child worker vs session worker) | tested in the user session only | session 0 is pending |
| Native session helper (D-2) | pending, decision open | — |

### Execution pipeline (M2a, 2026-11-22)

| Component | State | Evidence |
|---|---|---|
| Job contracts (catalog spec, sync request and response, result checksum) | tested | `udcs_shared/jobs.py`; controller and agent tests |
| `jobs` and `job_logs` tables, migration `0003` | tested on SQLite and PostgreSQL 16 (CI) | schema-matches-models check, migration round trip |
| Job API: submit, list, get, cancel, logs, result; per-user limit; admin-only priority; node placement hidden from users | tested | `controller/tests/test_jobs.py` (13) |
| Pull scheduler: offer-constrained kinds, slots and memory; GPU only on GPU-inventory nodes; GPU-first on GPU nodes; per-user fair share | tested | `test_jobs.py` |
| **Concurrent claims and updates (PostgreSQL)**: `FOR UPDATE SKIP LOCKED` candidates, conditional claim, row locks on report, reap and cancel | **tested under genuine concurrency in CI** | `test_jobs_concurrency.py`: independent sessions released by a barrier; 2 agents → 1 job, 8 agents → 6 jobs, report vs reaper; 150/150 over 50 rounds. A mutation probe with both claim guards removed failed 10/15 |
| **Checkpoint migration**: central versioned store; atomic, hash-checked and validated uploads; fenced upload and download; resume on another node before the workload starts; stale and corrupt versions rejected; checkpoints dropped on finish or failure | **tested** | `test_jobs.py` (5 new), `test_job_sync.py` (7 new), e2e: the job resumes on a second node after the first node *and its disk* are gone, with a verified result |
| Leases, requeue, fencing (stale attempt or wrong node), restart grace, failure and requeue limits, lost assignments | tested (3 of 4 key mutations killed; the claim-guard mutation survives) | `test_jobs.py` |
| Result verification (Σ i² checksum, checkpointed with progress) | tested | unit and e2e. It detects lost or repeated units, **not** a dishonest node (T26) |
| Agent `JobSync`: capacity offer from the governor envelope, reports, log cursors, persist-before-create, reassignment keeps progress, cancel/ack purge, orphan cleanup | tested | `node_agent/tests/test_job_sync.py` (15) |
| Workload manager: thread-safe snapshots, ordered request queue, purge with exit-wait and retry, cumulative CPU per workload | tested (real Job Objects) | `test_workloads_windows.py` |
| **End to end**: 4 jobs over 2 real agents, all verified, spread over both nodes; cancel purges the node; agent restart resumes the same attempt from its checkpoint; a lost node's job is requeued by lease and finished on the other node | **tested** on one PC | `tests/e2e/test_job_pipeline.py` (4, about 5 min) |
| Pipeline under the real Windows service (SYSTEM, session 0) | **unverified** | part of the elevated M1.5 acceptance |
| Separate physical machines, real power-off, clock skew | **unverified** | — |
| Checkpoint migration between nodes; preemption; predictive availability; quotas beyond the per-user limit | pending | — |
| User-supplied code | **disabled**: the isolation backend exists, and the gate (service-path acceptance, ALL APPLICATION PACKAGES review, packaging design) is open | ADR 0001 |

Test run, 2026-11-22 (local, Windows 11): **204 passed and 15 skipped** (the PostgreSQL race tests skip on SQLite), and ruff is clean.
- **Intermittent failures.** In an earlier full run, `test_memory_class_is_paused_while_a_student_is_active` and the e2e cancel test each failed once. Neither reproduced in isolated reruns (3×) or in the next full run.
- **Cause.** Not identified. The suspicion is timing under load, because both wait on real process start and stop. Treat them as **known flaky** until explained.

CI on the feature branch, run 44990049659:
- **PostgreSQL:** 70/70, which includes migration 0003 and every job scheduler test.
- **Windows:** 190 passed and 1 failed. The e2e cancel test waited 60 s for a job to start, but a fresh agent's deliberate start-up caution (≥ 30 s of calm, restarted by noise) took longer on the runner. The waits now allow for it, and the next run, [44990617979](https://github.com/Yash-200608/UDCS/actions/runs/44990617979), is **all green**: lint; PostgreSQL 70/70; Windows 191 passed, 1 skipped (no NVIDIA driver), including the 4 e2e pipeline tests.

Bugs found and fixed while building it:
- **CPU time was lost for short jobs:** they finished between syncs, so the manager now keeps cumulative CPU per workload.
- **Cancelled workload directories survived:** Windows would not delete a just-terminated process's working directory, so the manager now waits for the exit and retries the purge.

### Concurrency hardening and checkpoint migration (2026-11-22)

**Races fixed** (found by analysing the code while writing the race tests; the tests then confirmed the fixes):
- **Lost updates:** a node's report and another node's lease reaper or a user's cancel could overwrite each other, for example requeuing a job that had just succeeded. Every read-modify-write now locks the job row.
- **Possible claimer deadlock:** syncs sort candidates differently, so two claimers could lock rows in different orders. Candidates are now locked `SKIP LOCKED`, so claimers never wait on each other.

**First race-test failure:** the first CI run of the race tests failed in 5 rounds. The cause was a test bug, not a race: the drain loop did not report held jobs, so the controller correctly requeued them as lost. It is fixed, and the race-phase assertion had passed every time.

**What resumes now:** a requeued job resumes from its last uploaded checkpoint on any node. At most one upload interval of work is repeated (15 s by default).

**CI** [44994104218](https://github.com/Yash-200608/UDCS/actions/runs/44994104218):

| Job | Result |
|---|---|
| PostgreSQL migrate | a clean database reaches head `0004`; the models match |
| PostgreSQL tests | **90/90** |
| Race step | **150/150** (50 rounds × 3) |
| Windows | **203 passed, 16 skipped** (the race tests skip on SQLite; one GPU test needs a driver), including the checkpoint-migration e2e test |
| Lint | clean |

**Still open:**
- checkpoints over 1 MiB (chunked uploads) and object storage for big state;
- checkpoint history (only the latest version is kept);
- integrity for user workloads (D-3);
- forgery by a dishonest node (T26/T29).

### Workload isolation (D-3, 2026-11-22)

Decision: [ADR 0001](docs/decisions/0001-workload-isolation.md).

**MXC v1.1.0** (`wxc-exec.exe`) cannot run on this fleet's build 22000. Its ProcessContainer needs 24H2 (26100+), and v1.1.0 removed the legacy fallbacks. It is detected and reported per node, but not integrated.

**Chosen:** a native AppContainer backend in the agent.

| Component | State | Evidence |
|---|---|---|
| `winplat/appcontainer.py`: per-workload AppContainer profiles, restricted token (no privileges, Administrators deny-only), no network capability, process created suspended inside the existing Job Object, UI restrictions, ACL grants and revokes, profile listing | tested | `test_isolation_windows.py` (14) |
| `workloads/isolation.py`: adapter with a runtime capability SID, a minimal runtime copy (checked and repaired on every launch), per-workload grants (own workdir: modify; inputs: read/execute), crash traceback to `workload-error.txt`, per-agent scoped profile names, orphan sweep | tested | same |
| No fallback: required isolation missing, or launch failure → workload FAILED, nothing started | tested | same |
| Four catalog workloads (cpu, memory, disk, **gpu/CUDA**) completing inside AppContainer, with governor pause and Job Object accounting intact | tested on the GT 730 | same |
| Isolation self-test: 18 operations (allowed vs prohibited), token, environment, process-tree kill, each with an unsandboxed control | **passed as the interactive user** | `test_isolation_selftest_denies_every_prohibited_operation`; the `AgentApp` request-file path (`test_agent_app.py`) |
| Per-node capability detection reported in inventory (`isolation`: appcontainer, lpac, mxc, windows_sandbox, hyperv, wsl) | tested | `test_detection_reports_a_verified_appcontainer` |
| **Self-test from the installed service (LocalSystem, session 0)** | **not run; needs elevation** | `tools/acceptance/m2_isolation_service_acceptance.ps1` |
| LPAC (stricter) | not used: Python fails at start (0xC0000022) on build 22000 | detection reports it |

**Bugs found on the way:**
- `synthetic.py` passed an invalid 32-bit handle to `SetPriorityClass`. Windows ignored it on the host, so **background mode was never applied before**; inside AppContainer it crashed.
- The self-test's unsandboxed control wrote into the shared runtime, which would have broken every later isolated job on a node.
- `DeleteAppContainerProfile` reports success for unknown profiles. Leaks are now checked through the registry mapping and swept.
- **Found by CI, which is the closest thing to the service path run so far.** With an elevated-admin parent (and therefore almost certainly a LocalSystem one), the restricted token kept Administrators as owner and in its default DACL, so every AppContainer child failed with 0xC0000142. Fixed: owner and default DACL are now the user, SYSTEM and the package SID. Workloads also run on a private window station or desktop, never the student's. Verified on the runner with `tools/experiments/appcontainer_ci_probe.py`.

**Measured costs:**
- AppContainer process start is about 0.12 s for Python, and the detection launch takes about 0.6 s;
- the one-time grant on the interpreter directory takes 41.6 s per node.

### M2a engineering review

**Achieved and verified:**
- A job submitted over HTTPS is scheduled by pull, run under local protection in a Job Object on a real agent, reported back with progress, CPU, memory and lifecycle logs, and returned as a result the controller verifies.
- Recovery is verified for four cases: agent restart (resume, same attempt); a lost node (lease → requeue → another node); a lost assignment; and controller restart (grace).

**Weak or unverified:**
- the agent under the real service;
- separate machines;
- the result checksum is not attestation;
- logs are lifecycle-only;
- the start-up delay before a node takes work;
- 2 intermittently failing tests.

**Tech debt:**
- `jobs/service.py` holds both lifecycle and scheduling (about 400 lines). Split it when the scheduler grows (quotas, preemption).
- Lazy reaping should become a periodic task if a UI needs fresh states without polling.

**Next, in priority order:**
1. The elevated service acceptance, now including the pipeline.
2. ~~A concurrency test of the claim~~: done (PostgreSQL race tests in CI).
3. ~~Checkpoint migration~~: done (central, verified, fenced).
4. ~~The D-3 isolation decision~~: decided (ADR 0001); user code still gated.

## Acceptance gates still open for M1.5

None of these are done. Do not report them as passed until they are.

1. **Elevated Windows service acceptance.** Run `tools/acceptance/m15_service_acceptance.ps1` in an elevated shell on a lab PC.
2. **Actual reboot and crash-recovery verification.** Run the same script, reboot, then run it with `-AfterReboot`.
3. **Session-0 CUDA execution verification (E1 as SYSTEM).** The GT 730 detection is not evidence of workload compatibility. RTX-class hardware is still untested.
4. **Real service resource overhead.** The 124 MiB RSS was measured in the benchmark process, not the service. The target is ≤ 80 MiB.
5. **PostgreSQL integration through CI: passed in CI on the feature branch** (run 44985979000, 57/57). This gate is closed for the controller only. Remaining limits:
   - The model diff ignores CHECK constraints and server defaults. The `admin_state` CHECK is covered behaviourally by `test_migration_data.py`.
   - The end-to-end TLS tests run on SQLite.
   - `main` (77ac1be) does not contain these CI and test changes until the feature branch is brought into it.
6. **Disk interference benchmark validation.** The result is inconclusive on this machine because of baseline noise (p95 noise floor +139%).

## Measured results (one machine, not a fleet guarantee)

- **B1, foreground slowdown (managed median):**

  | Class | Median slowdown |
  |---|---|
  | CPU, 1 thread | +1.3% |
  | CPU, all cores | +0.1% |
  | Memory | +0.7% |
  | GPU | 0.0% |
  | Disk | inconclusive |

  The p95 values sit near the noise floor.
- **B2, response time (all within 2 s):**

  | Trigger | Mean | Worst |
  |---|---|---|
  | Student arrives | 0.06–0.45 s | 0.52 s |
  | Pressure while locked | 1.07–1.20 s | 1.33 s |

- **Governor overhead:** about 2 ms of CPU per tick, 0.21% of one core.

## Test results

Pre-commit run, 2026-11-22 (Windows 11, Python 3.12, SQLite):

| Check | Result |
|---|---|
| `uv run pytest` | **158 passed**, 1 third-party deprecation warning (Starlette test client) |
| `ruff check .` | clean |
| `ruff format --check .` | clean (111 files) |
| GitHub Actions `test-windows` (run 44985979000) | 157 passed, 1 skipped (no NVIDIA driver on the runner) |
| GitHub Actions `test-postgres` (run 44985979000) | 57 passed on PostgreSQL 16 |

Not covered by this run:
- PostgreSQL, which runs only in CI;
- anything that needs admin rights;
- the service host as a real service.

## Known limitations

1. Graceful shutdown is tested in-process (< 5 s). The < 2 s target has not been measured in the service.
2. The rate limiter is per-process and in memory. Client IP is the TCP peer (no trusted-proxy handling).
3. There is no password reset, MFA or SSO. University SSO should be decided before onboarding students.
4. Re-enrolling a machine creates a new node record. A node that lies in its inventory is still accepted; verification is planned for M3.
5. The session helper is a Python process (memory cost; D-2 is open).
7. **Audit events with equal timestamps have no chronological order.** The listing now breaks ties by id, so the order is deterministic but not chronological. PostgreSQL CI exposed this: SQLite had been returning tied rows in insertion order by accident. The proper fix is a strict sequence column (a schema change, and the basis for T9 hash-chaining). That is a founder decision.
6. The threat model's T10 (malicious workload escape) is **reduced, not closed**. AppContainer is not a VM: kernel or driver exploits cross it. User code stays disabled until the ADR 0001 gate passes.

## Decisions awaiting the founder

| Decision | Status / recommendation |
|---|---|
| D-2: native session helper | open |
| D-3: execution isolation | **decided**: native AppContainer now; MXC for 24H2+ nodes later (ADR 0001) |
| D-4: power policy | open |
| Repository license | none chosen |
| Differentiator versus HTCondor | needs to be written before M3 |

## History

- **2026-11-21, M1 met.**
  - Live TLS run: enroll, then heartbeats every 5 s, then online; offline after 3 intervals.
  - A reused enrollment token was rejected, and an `http://` URL was refused.
  - No secrets appeared in the logs.
  - Test suite: 90 passed.
- **2026-11-21, operating-model clarification.**
  - The agent becomes a background service, and the local student always takes priority.
  - Research is in [docs/research/](docs/research/2026-11-21-node-operating-model.md); the design is in [node-operating-model.md](docs/architecture/node-operating-model.md).
  - Fixed: an NVML crash on old drivers.
- **2026-11-22, M1.5 implemented.**
  - The adversarial review's 25 findings were all fixed. The two high-severity ones were the installer ACL handling and the PostgreSQL migration CHECK swap.
  - Benchmark harness fixes:
    - the response wait now covers the 120 s grace plus the 30 s relax period;
    - the first all-core result (+33.5%) was noise, as an interleaved retest showed.
