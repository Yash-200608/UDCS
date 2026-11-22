# Development Status

_Last updated: 2026-11-22. Development checkpoint on branch `feature/udcs-background-agent-m15`. This is **not** a release, and Milestone 1.5 is **not accepted**._

## Summary

| Milestone | State |
|---|---|
| M1: Working Foundation | **Met**, verified live over TLS on one Windows 11 PC. The "no terminal" gap is now covered by the M1.5 service, which is not yet verified as a service. |
| M1.5: Background Service & Local Resource Protection | **Implemented. Tested without admin rights. NOT accepted.** Six acceptance gates are still open (see below). Report: [docs/acceptance/milestone-1.5.md](docs/acceptance/milestone-1.5.md) |
| M2: Job execution | Not started. Blocked on decision D-3 (isolation). |

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
6. The threat model's T10 (malicious workload escape) is **open**. M2 must not start without an isolation decision.

## Decisions awaiting the founder

| Decision | Status / recommendation |
|---|---|
| D-2: native session helper | open |
| D-3: execution isolation (**blocks M2**) | recommendation: tiered trust, with containers for untrusted workloads |
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
