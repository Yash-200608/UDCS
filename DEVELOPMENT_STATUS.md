# Development Status

_Last updated: 2026-11-28. Development checkpoint on branch `feature/udcs-background-agent-m15`. This is **not** a release, and Milestone 1.5 is **not accepted**._

## Summary

| Milestone | State |
|---|---|
| M1: Working Foundation | **Met**, verified live over TLS on one Windows 11 PC. The "no terminal" gap is now covered by the M1.5 service, which is not yet verified as a service. |
| M1.5: Background Service & Local Resource Protection | **Implemented. Tested without admin rights. NOT accepted.** Six acceptance gates are still open (see below). Report: [docs/acceptance/milestone-1.5.md](docs/acceptance/milestone-1.5.md) |
| M2a: Distributed execution pipeline (catalog workloads only) | **Implemented and tested** on one PC with two agent instances: controller → scheduler → agent → Job Object workload → telemetry → verified result, plus recovery. See [execution-pipeline.md](docs/architecture/execution-pipeline.md) |
| M2b: Isolation for workloads (D-3) | **Decided: [ADR 0001](docs/decisions/0001-workload-isolation.md). Native AppContainer backend implemented and tested; the catalog runs inside it where a node verifies it.** **Service-path gate passed** (2026-11-22, SYSTEM in session 0). User code is still **disabled**: ADR gate 2 (review of what ALL APPLICATION PACKAGES exposes on a lab image) is open |
| ADR 0001 gate 3: user-code packaging and delivery | **Implemented, tested and security-reviewed** ([ADR 0002](docs/decisions/0002-user-code-packaging.md)). Manifest, validator, CAS, resumable chunked transfer, node staging and outputs work end to end **without executing anything**. All 11 review findings are fixed and regression-tested. Execution is still disabled by two switches |
| Researcher submission client (`udcs`) | **Implemented and tested; execution still disabled.** Create or select a project, declare its entry point and dependencies (approved environments only), attach datasets, validate, upload, submit, monitor and fetch verified results. The disabled path is honest: it registers the package, creates no job and exits 3. Review: 27 findings fixed. [Guide](docs/guides/researcher-client.md) |
| Package execution pipeline ([ADR 0003](docs/decisions/0003-package-execution.md)) | **Implemented and tested end to end on one PC, disabled by default.** Researcher CLI → HTTPS controller → eligibility-checked scheduling → Windows agent → AppContainer + Job Object → chunked upload → verified `udcs fetch` passes for real (`tests/e2e/test_package_execution_e2e.py`). Three switches are off in every shipped default: controller flag, agent constant, per-node admin flag. **Blocked for real use** on M1.5 pass 2, ADR 0001 gate 2 and an operator procedure |

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
| Pipeline under the real Windows service (SYSTEM, session 0) | partly verified: the service manages and recovers workloads, and isolated launches work from it; a full controller-driven job through the installed service has not been run (this install is not enrolled) | `m15-service-acceptance.json`, `m2-isolation-service.json` |
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
| **Self-test from the installed service (LocalSystem, session 0)** | **PASSED** (2026-11-22): all 16 prohibited operations denied, each possible for the SYSTEM control, lsass included; token privilege-free; tree kill OK; CUDA OK inside | `docs/acceptance/data/m2-isolation-service.json` |
| LPAC (stricter) | not used: Python fails at start (0xC0000022) on build 22000 | detection reports it |

**Bugs found on the way:**
- `synthetic.py` passed an invalid 32-bit handle to `SetPriorityClass`. Windows ignored it on the host, so **background mode was never applied before**; inside AppContainer it crashed.
- The self-test's unsandboxed control wrote into the shared runtime, which would have broken every later isolated job on a node.
- `DeleteAppContainerProfile` reports success for unknown profiles. Leaks are now checked through the registry mapping and swept.
- **CI after the fixes** ([45009429033](https://github.com/Yash-200608/UDCS/actions/runs/45009429033)): Windows **217 passed** (isolation self-test, catalog in AppContainer, job pipeline in AppContainer) with an elevated-admin parent on build 26100; PostgreSQL 90/90 + 150/150 races; lint clean. The real service run followed and **passed** (see the isolation table).
- **Grants also name the agent's own user SID** (CI): otherwise an admin-parented workload could not write an admin-only workdir.
- **Found by CI, which is the closest thing to the service path run so far.** With an elevated-admin parent (and therefore almost certainly a LocalSystem one), the restricted token kept Administrators as owner and in its default DACL, so every AppContainer child failed with 0xC0000142. Fixed: owner and default DACL are now the user, SYSTEM and the package SID. Workloads also run on a private window station or desktop, never the student's. Verified on the runner with `tools/experiments/appcontainer_ci_probe.py`.

**Measured costs:**
- AppContainer process start is about 0.12 s for Python, and the detection launch takes about 0.6 s;
- the one-time grant on the interpreter directory takes 41.6 s per node.

### User-code packaging and delivery (ADR 0001 gate 3, 2026-11-22)

Decision: [ADR 0002](docs/decisions/0002-user-code-packaging.md). **Nothing executes:** controller `user_code_enabled = false` (checked at dispatch and on every node package endpoint) and agent `USER_CODE_ENABLED = False`.

| Component | State | Evidence |
|---|---|---|
| Versioned manifest (`udcs_shared.packages`): SHA-256 for every file, canonical digest, path rules (traversal, drives, UNC, ADS, device names, NFC, case-insensitive duplicates), kinds package/environment/dataset | tested | `test_packages.py` (parametrised attacks) |
| `PackagePolicy`: every limit configurable (`UDCS_PACKAGE_POLICY`) | tested | `test_policy_limits_are_configurable_not_hardcoded` |
| Controller CAS: chunked, resumable uploads with a SHA-256 per chunk, bounded zlib, full hash before naming, global storage dedup, no cross-user oracle, quotas, session sweep | tested | `test_packages.py` |
| Dependencies: exact pins only, from admin-approved wheel-only environments; Python version match; `.pth` refused | tested | `test_environment_and_dataset_rules`, `test_registration_checks_sizes_and_approvals` |
| Scheduling integration: package jobs only to nodes offering user code *and* only with the controller flag on; fenced node downloads | tested | end-to-end and kill-switch tests |
| Node: verified Range-resumable fetch into a CAS cache, per-attempt read-only staging re-hashing every byte, handle-based output collection into a private snapshot, junction- and hardlink-safe cleanup | tested (NTFS) | `test_packages_windows.py` (10) |
| Outputs: chunked node upload bounded per attempt, possession-checked manifest, owner download with Range | tested | `test_outputs_cannot_claim_another_users_blob` and others |
| Adversarial security review | **11 findings fixed** (1 high, 6 medium, 4 low); 13 of 13 fix mutations caught | ADR 0002 "Review findings" |

**Measured** (loopback TLS, one PC):
- upload 15.2 MiB/s; compressible data 0.117× on the wire;
- download with verification 94.6 MiB/s;
- resume re-sends exactly the missing bytes (upload and download);
- 200 small files at 13.5 files/s (**weak**: per-file round trips);
- staging 200 files in 0.48 s;
- storage overhead: blob store 192.39 MiB for 192.78 MiB logical, about 111 B of manifest per file, database 0.42 MiB.

**Not done:** unreferenced-blob GC and a periodic sweep; per-node admin eligibility for user code; node Python-version matching in the scheduler; per-group dataset access; a batch upload endpoint; a standalone client; attestation against a dishonest node (T26).

### Researcher client (`udcs`, 2026-11-23)

Design and review: [ADR 0002, "Researcher client"](docs/decisions/0002-user-code-packaging.md). Guide: [docs/guides/researcher-client.md](docs/guides/researcher-client.md).

| Component | State | Evidence |
|---|---|---|
| `udcs` CLI: login/logout/whoami, init, check, push, submit, env list/show/use, dataset list/add/push, jobs/status/watch/logs/cancel, fetch | tested in-process against the real controller | `client/tests/` (83) |
| Over real TLS: certificate verification, stored session (DPAPI user scope), disabled submit, catalog job | tested | `tests/e2e/test_researcher_client_tls.py` |
| Hostile project directory (secrets, venvs, links, junctions, unsafe names) and hostile controller (traversal, clashes, wrong bytes, redirects, escape sequences) | tested | `test_client_hostile_*.py` |
| Controller additions: approved-package listing, `/deployment`, `JobOut.package`, log cursor | tested | `controller/tests/test_packages.py` |
| Transfer, DPAPI and URL code moved from the agent to `udcs_shared` | tested; agent suite unchanged | `shared/tests/test_dpapi.py` |
| Package job end to end (real agent executes, outputs fetched) | **not possible yet**: execution disabled | skipped `test_package_job_end_to_end` |

### Package execution pipeline (ADR 0003, 2026-11-27)

Tested on Windows 11 build 26300 (a different PC from the earlier milestones), as the interactive user, not elevated.

**Tested:**

| Component | Evidence |
|---|---|
| Package job contract: no units or checksum; `PackageRunLimits`, `PackageResult` (exit code + output digest), `FailureKind`, `staging`/`uploading` states; catalog jobs unchanged | `controller/tests/test_packages.py`, `test_jobs.py` |
| Scheduling refuses, before the claim: nodes not admin-eligible, without a verified AppContainer, with the wrong Python, or (with an environment) the wrong platform or an unapproved environment | `test_incompatible_nodes_never_receive_package_jobs`, `test_environment_platform_and_approval_are_matched` |
| Admin eligibility endpoint: `MANAGE_NODES` only, audited with a reason | `test_node_eligibility_is_admin_only_and_audited` |
| Stale attempts cannot publish (uploads, output report, result); cancel during upload stops publication; a result must name this attempt's outputs | `test_a_stale_attempt_cannot_publish_*`, `test_cancel_during_result_upload_*`, `test_a_result_must_name_*` |
| Workload failures final, infrastructure failures retried; non-zero exit recorded | `test_workload_failures_are_final_*` |
| Agent: offer only when enabled AND AppContainer verified; refuse otherwise; substituted manifest, corrupted blob or Python mismatch refused before staging; phases, upload, result digest, cleanup, reassignment, opaque checkpoints up and down | `node_agent/tests/test_package_sync.py` (17) |
| Real AppContainer runs: outputs, log capture, exit codes and crashes as results; a hostile package denied the node credential, another job's files, the data dir, the user profile, writes to source/config/outside `out/`, and loopback network; a surviving child killed; junction/hard-link planting refused; runtime, storage and memory limits; output limits; reserved log name; import from an approved environment, read-only | `node_agent/tests/test_package_runs_windows.py` (10) |
| **Full path**, researcher CLI → HTTPS → scheduler → `AgentApp` → AppContainer → upload → `udcs fetch`, plus cancel mid-run with cleanup | `tests/e2e/test_package_execution_e2e.py` (2) |
| Mutation check: 14 guards removed one at a time, 14 caught | ADR 0003 |

**Bug found by the tests:** the storage limit never fired, because NTFS directory listings report stale sizes for files still being written. Sizes are now read from the files themselves.

**Untested:**
- packages under the installed service (LocalSystem, session 0);
- GPU frameworks inside AppContainer;
- two live agents with node loss for packages (covered at controller and agent level only);
- PostgreSQL for the new migration (CI will run it).

**Full-suite result on this PC:** 418 passed, 19 skipped, 4 failed. All 4 failures are e2e tests whose agents never left `constrained`: the governor protecting a busy machine.
- Three are catalog tests in `test_job_pipeline.py`; one is the package cancel test, which passed when run alone.
- Running two of the catalog tests on the **unmodified previous commit**, in a separate worktree, under the same conditions failed the same way (2 of 2).
- So they are environmental (local protection working as designed), not a regression. They are the same intermittent tests the M2a review lists.
- CI runs them on a quiet runner.

**Blocked (by design):** enabling execution anywhere real needs M1.5 pass 2, ADR 0001 gate 2 (lab-image exposure audit) and an operator procedure for the per-node flag. The node's AppContainer claim is self-reported, so the admin flag is the control that counts.

### Acceptance readiness (2026-11-27)

**1. Audit of ADR 0003 against the code.** Six findings, all fixed with tests:

| # | Finding | Fix | Evidence |
|---|---|---|---|
| A1 | Revoking eligibility, losing the AppContainer capability or switching the controller flag off did not stop package jobs already assigned; the node could keep downloading and uploading | One rule, `user_code_unfit()`, applied by the scheduler, the sync (requeue + cancel) and every node package endpoint (409) | `test_revocation_and_reimaging_stop_running_package_jobs`, `test_switching_the_controller_flag_off_stops_running_package_jobs` |
| A2 | A previous attempt's output manifest survived a requeue, so a later attempt with no outputs appeared to have them | Outputs and exit code are cleared on requeue | `test_a_requeue_clears_the_previous_attempts_outputs` |
| A3 | Reimaging a node kept its eligibility | Eligibility is bound to the audited OS image; a different image in the inventory suspends it (audited, actor `system`) | the revocation test above |
| A4 | Eligibility could be granted without evidence, to a node that is not ACTIVE or has no verified AppContainer | A grant needs ACTIVE, a verified AppContainer, and a passing, recent, SYSTEM-context exposure audit of the current image; refusals are audited | `test_node_eligibility_follows_the_operator_procedure`, `test_grant_needs_*` |
| A5 | A future-dated audit report would pass the age check forever | Reports more than 10 minutes in the future are refused | same test |
| A6 | **Measured:** a sandbox launched by an agent running as the interactive user can stop that user's 11 per-user services and open the student's `WinSta0\Default` desktop | The agent offers user code only when it runs as LocalSystem | `test_an_interactive_agent_never_offers_user_code` |

**Mutation check:** removed 15 of the new guards one at a time; all 15 were caught, after three weak tests were strengthened (image match and ACTIVE on grant, and a stale image grant at run time).

**Also verified:**
- cancellation kills a package's child processes, not just its main process (`test_cancelling_a_run_kills_its_whole_process_tree`);
- the earlier tests for stale attempts, output ownership and credential isolation still pass.

**2. AppContainer exposure audit.** Implemented:
- the probe, `diagnostics/exposure_probe.py`, runs inside a real UDCS AppContainer;
- the host side, `diagnostics/exposure_audit.py`, builds its plan;
- the shared verdict is `udcs_shared/exposure.py`, which the controller re-applies;
- the command is `udcs-agent audit-exposure`.

What it records: filesystem (list and add-file rights), registry (read, set-value and create-subkey rights), every process (six access rights), every named pipe, global named objects, every listening TCP port plus external endpoints and DNS, every service (five rights), the window station and desktop, the clipboard, and the token. It modifies nothing; write access is tested by opening a handle with the right.

The probe's first runs on this PC found three false positives in the probe itself, all fixed:
- predefined registry roots return their handle without an access check;
- the sandbox's own `conhost.exe` looked like a controllable foreign process;
- `HKLM\SAM` is world-readable by design; the secrets are in `SAM\SAM`.

**Measured on this development PC** (Windows 11 build 26300, as the interactive standard user, *not* a lab image and *not* the service context); summary in `docs/acceptance/data/m3-exposure-audit-devpc-user-context.json`:
- reachable: 118 directories listable, 6,221 registry keys readable, 10 named pipes connectable, 8 global objects openable, 34 services startable, 40 services queryable;
- none of these: filesystem or registry write, sensitive data readable, process control, network.
- **12 violations, all caused by the interactive context:** stop rights on 11 per-user services, and the student's desktop (hence A6).

**Also measured, in CI** (GitHub `windows-latest` runner, run 46034655858): a UDCS AppContainer could **read the autologon password** in `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword`. That image stores the password in plain text, and the key is readable by AppContainers.
- The audit flagged it as a violation, so that image could never be made eligible.
- Lab PCs often use autologon, so this is a concrete reason the gate exists.
- **Fix for lab images:** configure autologon so the password is not in that value (for example Sysinternals Autologon, which keeps it as an LSA secret), then re-audit.

**3. Operator procedure.** [docs/operations/node-eligibility.md](docs/operations/node-eligibility.md).
- It is enforced by the controller (migration 0007: `node_exposure_audits`, and the eligibility bound to an image and audit).
- It is operated with `udcs admin nodes | audit-upload | audits | user-code allow|revoke`.
- Tested end to end against the real controller (`client/tests/test_client_admin.py`).

**4. Original-machine acceptance, prepared, not run:**

| Script | What it does | Status |
|---|---|---|
| `tools/acceptance/m3_preflight.ps1` | Read-only readiness check: same machine as pass 1 (build and GPU), rebooted since, service present and LocalSystem, installed agent version, repository environment, OneDrive online-only files | run here: correctly reports this is *not* the pass-1 machine and no service is installed |
| `tools/acceptance/m15_service_acceptance.ps1 -AfterReboot` | M1.5 pass 2 | now refuses to record anything unless it is on the pass-1 machine and that machine rebooted since; still read-only |
| `tools/acceptance/m2_isolation_service_acceptance.ps1` | Service-path isolation self-test (unchanged) | ready |
| `tools/acceptance/m3_exposure_audit.ps1 -AsSystem -Staging <dir>` | The exposure audit as LocalSystem through a temporary scheduled task. It runs a hashed copy of a `package_agent.py` staging folder inside a new, admin-owned folder that only SYSTEM and Administrators can access (the installed service is not upgraded, stopped or reconfigured) | hardened after a security inspection (below); **the elevated run is untested** |

**Security inspection of the SYSTEM path (2026-11-28), and fixes:**

The previous `-AsSystem` design was unsafe and was never run. It had two flaws:
- **Code a normal user can write, run as SYSTEM.** It ran the repository's `.venv` (`python.exe`, `site-packages` and `.pth` files), the base interpreter in the user profile, and editable sources. All of these are full-control for the unelevated user. Because that account is a split-token admin, any medium-integrity process could have planted code to run as SYSTEM.
- **A user-creatable working folder.** It worked in `%ProgramData%\UDCS\exposure-audit`, where `BUILTIN\Users` may create folders. A standard user could create it first and plant junctions. SYSTEM's `rmtree`, `SetNamedSecurityInfo` grants, the runner file and the log writes could then be redirected.

Fixes:
- The script never runs repository or venv code while elevated, and only a hashed copy of the package runs as SYSTEM.
- The working folder gets a random name and is created with a protected DACL (Administrators as owner; only SYSTEM and Administrators have access).
- Reparse points are refused in the folder's path and in the copied files.
- Results are written only as new files (`CreateNew`) and never through a reparse point.
- Python runs with `-I -B`.
- The folder is deleted with `rd /s /q`, which doesn't follow junctions. (Windows PowerShell 5.1's `Remove-Item -Recurse` can follow them.)
- A result counts as evidence only if four cross-checks pass: the audit reports LocalSystem in session 0, the task ran as SYSTEM, the exit code is 0 or 1, and the manifest is unchanged.

Verified unelevated:
- 9 helper checks: junction detection, refusal to write through junctions or over existing files, manifest stability and change detection, and `rd` not following a junction.
- A full rehearsal from the snapshot as the current user: 1,692 files, manifest unchanged, same 12 violations, cleanup complete.
- Unelevated `-AsSystem` refuses.

**First real `-AsSystem` run (dev PC, image `11|10.0.26300`, build 26300.10075, 2026-11-28; run by the founder from an elevated PowerShell):**
- Protected folder created and verified. Snapshot of 1,692 files, manifest unchanged after the run.
- All 4 cross-checks passed. The probe ran in an AppContainer at low integrity with only `SeChangeNotifyPrivilege`; no errors, no truncation.
- Task and folder removed afterwards (verified empty).
- **Result: 11 violations, not eligible.** Every violation is a *per-user* service instance (`*_23d828`: BcastDVRUserService, WpnUserService, UnistoreSvc, UserDataSvc and 7 more) that the sandbox can open with `SERVICE_STOP`.
  - The DACL (`sc sdshow`) grants `ALL APPLICATION PACKAGES` `RPWP` (start and stop).
  - Correction to an earlier claim: the run did **not** use LPAC. Workloads were launched as standard AppContainers (ADR 0001), which honour `ALL APPLICATION PACKAGES` grants, so the open is expected. The probe does not try to actually stop a service.
  - **Fixed:** workloads now run under LPAC plus `registryRead`.
    - **Experiment:** under LPAC alone, Python dies with `0xC0000022`. With `registryRead`, Python starts and `OpenSCManager` is denied.
    - **Interactive-user audit, before → after:** 12 → 1 violations. The remaining one is `WinSta0\Default`, which is absent in session 0.
    - **Isolation self-test:** passes, and CUDA still initialises in the sandbox.
    - **Side effect:** under LPAC, `LookupPrivilegeNameW` fails, so privilege names now come from fixed LUIDs.
    - **LocalSystem re-run (2026-11-28, commit 644d18f, founder-run):**
      - All four cross-checks passed. The identity reads `NT AUTHORITY\SYSTEM`, with no host or user names in the summary.
      - Service findings are gone and one pipe remains; the summary reported **no violations**.
- **That was a FALSE PASS, found while reviewing the reachable items.**
  - **What the sandbox could read:** keys in the signed-in student's own hive (`HKU\S-1-5-21-…-1001\Software`, `\Environment`, `\Control Panel`, and 500 keys of the `_Classes` hive).
  - **Why the audit missed it:** the sensitivity rule `HKU\S-1-5-21` was matched as a path component, but a user hive is `HKU\S-1-5-21-<domain>-<rid>`, so it never matched. Every earlier run, standard AppContainer included, had the same blind spot.
  - **Why it is readable:** Windows grants `ReadKey` on every user's `HKCU\Software` and `HKCU\Environment` (inherited down to, for example, `Explorer\RecentDocs`) to both ALL APPLICATION PACKAGES and the `registryRead` capability SID. The normal half of the access check passes because the sandbox token's user is SYSTEM.
  - **Fixes:**
    - the probe rule is now a SID prefix;
    - the shared verdict, which the controller uses to re-judge uploads, classifies `HKU\S-1-5-21-*`, `HKLM\SAM\SAM` and `HKLM\SECURITY` from the target itself instead of trusting the probe's flag;
    - a pinned unit test covers it.
  - **Re-judged:** 506 violations.
  - **Evidence folder:** the false-pass summary was removed from `docs/acceptance/data`.
  - **Open, needs a design decision:** no AppContainer configuration fixes this, because the exposure comes from SYSTEM being the token user. See "Decisions awaiting the founder".
  - The same 11 appear in the interactive-user run. The user run's 12th finding, `WinSta0\Default`, is absent in session 0 as expected.
  - Impact: user code could stop services of the logged-on student, which breaks the "students have priority" rule. This looks like a property of the Windows 11 image, not of this PC; mitigation is undecided.
- **Two bugs found by this run, fixed:**
  - For LocalSystem, `USERNAME` is `HOSTNAME$`, so the summary recorded the host name.
  - The report's `runner` read `HOSTNAME$ (elevated)`, which fails `grant_user_code`'s `"SYSTEM" in runner` check, so even a passing SYSTEM audit could never have been granted.

  The identity now comes from the token SID (`NT AUTHORITY\SYSTEM (session 0)`). That run's summary was kept out of the repository because it contains the host name. The evidence test now rejects a `$`-suffixed identity.
- Still unverified: task self-deletion after a force-killed console, and the stale-folder sweep.
- Weakness: the controller's runner check is a string match on a self-reported field. It is an operator attestation, not proof.

**Remaining trust assumption:** the staging folder is user-built, so the copy is only as trustworthy as that folder at copy time.

**Same class, not fixed:** `m15` pass 1 runs `uv run python tools/package_agent.py` while elevated.

**5. Diagnostic dry run on a development PC (build 26300, standard user, no service):**

Diagnostics are kept apart from evidence. `udcs_agent.diagnostics.context` labels every result with the machine (a hash of its name), the image and the execution identity. A result counts as `evidence` only in the LocalSystem session-0 context. Diagnostics are written to `%LOCALAPPDATA%\UDCS\diagnostics`, never to `docs/acceptance/data`. `tests/test_acceptance_evidence.py` fails if a diagnostic lands there.

Script guards:
- `m15` pass 1 refuses to run when UDCSAgent is already installed. It also refuses when pass-1 evidence exists, unless `-ReplaceEvidence` is given, which keeps a backup of the old report.
- `m2` writes a non-SYSTEM result as a diagnostic only. `-Diagnostic` runs the self-test as the current user.
- The scheduled task in `m3 -AsSystem` is swept first and removed in `finally`. If the console is killed, the task expires and deletes itself within 45 minutes, and the audit is stopped after 30.
- No script elevates itself.

| Run (this PC, not elevated) | Result (diagnostic only) |
|---|---|
| `m3_preflight.ps1` | exit 3, NOT READY. Mismatches: not elevated, build 26300 vs 22000, GPUs differ, no reboot of the pass-1 machine, service not installed. (Fixed during the run: the reboot check passed on a *different* machine because its boot time was later; it now requires the same machine.) |
| `m2_isolation_service_acceptance.ps1 -Diagnostic` | interactive-user context: all 21 checks and the process-tree kill passed; the temporary HKCU key was removed |
| `m3_exposure_audit.ps1` (user) | interactive-user context, image `11\|10.0.26300`: 12 violations, the same as before; no task created |
| not run (need elevation) | `m15` pass 1 and pass 2, `m2` service path, `m3 -AsSystem` |

**Finding:** this user profile holds 14 `udcs.*` AppContainer profiles left by earlier development and test runs. These runs did not add to them, and the source of the leak has not been investigated.

**Test evidence:**

| Run | Result |
|---|---|
| Local suite without e2e, after the dry-run changes | 421 passed, 18 skipped |
| Local full suite (this PC) | 432 passed, 19 skipped, 2 failed: the known intermittent catalog e2e tests |
| CI run 46036973142, commit `dd7063e` | green on its second re-run: Windows full suite, PostgreSQL including migrations 0006 and 0007, lint |

**Tech debt: the catalog e2e tests are intermittent.** `tests/e2e/test_job_pipeline.py` failed in 2 of 3 CI attempts on identical code, a different test each time.
- The symptom is the in-process TLS controller not answering within the test client's timeout ("Server disconnected", `ReadTimeout`) under runner load.
- The same tests failed on the unmodified previous commit on this PC.
- They need their own investigation: a separate controller process, and longer client timeouts.

**Outstanding acceptance requirements (none can be claimed yet):**
- M1.5 pass 2 (start after reboot) on the original machine: **not run**.
- Exposure audit as SYSTEM on the original machine, then on each real lab image: **not run**. No lab image has been validated.
- A reviewed decision on each lab image's reachable items (pipes, objects, services): **not done**.
- Packages executed by the installed service: **not done**. It runs older code; upgrading it is a separate, explicit step.

**Unverified assumptions:**
- Under SYSTEM, the per-user-service and desktop violations disappear. This is expected from token membership and the private window station, but not measured.
- The audit's roots and depths are enough to find an image's exposures. They are bounded: Users depth 4, ProgramData 3, others 1–2. A deeper exposure can be missed, so review the coverage numbers.
- The OS release and build are a sufficient image key; software and patch changes need a manual re-audit.

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

Do not report an item as passed until it is.

1. **Elevated Windows service acceptance: pass 1 PASSED** (2026-11-22, `data/m15-service-acceptance.json`).
   - Service start, LocalSystem in session 0, no visible windows.
   - Helper and presence, workload management, graceful stop in 0.27 s.
2. **Reboot and crash recovery.**
   - Crash recovery **passed**: the service restarted in 6.1 s, and the workload resumed from its checkpoint 1.1 s later.
   - **Service start after a reboot is still open**: run `m15_service_acceptance.ps1 -AfterReboot` after a reboot.
3. **Session-0 CUDA (E1 as SYSTEM): PASSED** for the arrangements UDCS uses.
   - CUDA works in the service process (context 110 ms, 20 ms kernels), in its child worker, and inside the AppContainer (`cuInit`).
   - A worker as the logged-in *user* failed ("probe produced no result"). It is not investigated, because UDCS never runs work as the student.
   - Only on the GT 730 (CC 3.5); RTX-class hardware is still untested.
4. **Real service resource overhead: PASSED.** 55.6 MiB RSS and 44.2 MiB private (target ≤ 80 MiB), 0.68% of one core; workload jobs are excluded.
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

Pre-commit run, 2026-11-22, after the gate 3 review fixes (Windows 11, Python 3.12, SQLite):

| Check | Result |
|---|---|
| `uv run pytest` | **289 passed**, 15 skipped (PostgreSQL-only race tests), third-party deprecation warnings only |
| `ruff check .` | clean |
| `ruff format --check .` | clean (144 files) |
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
| D-5 (first written as "D-4", which was already taken): workload token identity. As SYSTEM, the sandbox reads the signed-in student's `HKCU\Software`, `Environment` and `_Classes` through Windows' own ALL APPLICATION PACKAGES and `registryRead` grants | **Open, blocks user code. Recommendation: Option B.** The restricted token (SYSTEM and Administrators deny-only) passed in a real temporary LocalSystem service with `sidtype unrestricted`, using its own service SID for grants (details below). It uses documented APIs only, needs no account and no lab-policy dependency, and the only measured dependency is that the service token contains `BUILTIN\Users` and Everyone. The narrowest working child token (measured) keeps only `Users`, Everyone and the service SID enabled. Still to do: an ADR, the implementation, and a re-measurement on build 22000. Option A remains the fallback. |
| D-2: native session helper | open |
| D-3: execution isolation | **decided**: native AppContainer now; MXC for 24H2+ nodes later (ADR 0001) |
| Enabling user code | **not yet**: per-node admin eligibility is now built (ADR 0003); still needs ADR 0001 gate 2 (lab-image review), M1.5 pass 2 and an operator procedure for granting eligibility |
| D-4: power policy | open |
| Repository license | none chosen |
| Differentiator versus HTCondor | needs to be written before M3 |

**D-5 Option B experiment (`tools/experiments/restricted_token_experiment.*`, 2026-11-28, dev PC; diagnostic only):**
- **Method:**
  - It drives the production launch path (`AppContainerIsolation`, `run_audit`, `run_selftest`) and swaps only three things: the `CreateRestrictedToken` `SidsToDisable` list, the grant SID, and the default DACL.
  - Documented APIs only: `OpenProcessToken`, `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)`, `SetTokenInformation(TokenOwner, TokenDefaultDacl)`, `UpdateProcThreadAttribute(SECURITY_CAPABILITIES, ALL_APPLICATION_PACKAGES_POLICY)`, `CreateProcessAsUserW`, job objects, and `GetTokenInformation` on the child.
- **LocalSystem run (scheduled task, session 0, run by the founder):**

  | Variant | Student-hive registry findings | Probe / self-test / kill tree / CUDA |
  |---|---|---|
  | V0 production (control) | 1,015, all six explicit student targets readable (including `RecentDocs`, `Environment` values, `_Classes`) | all pass |
  | V1 (SYSTEM and Administrators deny-only, default DACL names the grant SID) | **0**, and 0 exposure violations | all pass |
  | V2 (every group deny-only) | — | child dies `0xC0000022`: `System32`/`ntdll` grant only TrustedInstaller, SYSTEM, Administrators and Users |

  - Profile folders, credentials and `System32\config` were denied in every variant.
  - Child token in V1: low integrity, only `SeChangeNotifyPrivilege`, 2 capabilities, user SID and Administrators deny-only.
- **The same in the user context** (logon SID as the grant SID): V1 has 0 student findings and the self-test passes.
- **My prediction was wrong:** I expected a SYSTEM token to lack `BUILTIN\Users`. The task-created SYSTEM token has it, plus `SERVICE`, `CONSOLE LOGON`, a logon SID and `NT SERVICE\Schedule`.
- **Limits:**
  1. **Not the service token.** The experiment ran from a scheduled task, not the UDCSAgent service. The service token's groups (`Users`? the `NT SERVICE\UDCSAgent` SID from `sc sidtype unrestricted`?) are unmeasured, and B needs both.
  2. **Grant SID not valid for production.** The experiment's grant SID was `NT SERVICE\Schedule`, Task Scheduler's own SID. A task SID (`ProcessTokenSidType`) was refused for SYSTEM tasks (0x80041316).
  3. **Snapshot changed.** The snapshot manifest changed during the SYSTEM run (audit runs left it unchanged). Cause not yet found.
  4. **Broad groups still pass the normal half.** V1's child keeps `Users`, Authenticated Users and Everyone enabled, so for files those groups can read, only the AppContainer half (LPAC plus capabilities) stops it. That is the same exposure a dedicated account (option A) would have.
- **Temporary LocalSystem service run (`-AsService`, 2026-11-28, founder-run):**
  - **Setup:** hosted like UDCSAgent: `python.exe -I`, pywin32 `ServiceFramework`, `sc sidtype unrestricted`. The service deleted itself afterwards (verified: no service and no folder left).
  - **Service token groups:** Everyone, `BUILTIN\Users`, `SERVICE`, `CONSOLE LOGON`, Authenticated Users, This Organization, `NT SERVICE\UDCSTokenExperiment` (owner), a logon SID, `LOCAL`, Administrators.
  - **V0 (control):** 1,015 student-hive findings, all six explicit targets readable.
  - **V1, grant SID = the service's own `NT SERVICE\` SID:** **0 student findings, 0 violations**; self-test, kill tree and CUDA pass; no leftover profiles. Child token: SYSTEM and Administrators deny-only, low integrity, only `SeChangeNotifyPrivilege`, AppContainer with 2 capabilities.
  - **V2:** `0xC0000022`, which confirms that B depends on `BUILTIN\Users` being in the service token.
  - **Snapshot change explained:** the isolation self-test's two *host-side* (unsandboxed, SYSTEM) Python processes (`diagnostics/isolation.py:216`, `:268`) run without `-B` and write stdlib `.pyc` into the interpreter folder. It is not the sandbox. Fix proposed: add `-B`.
  - **Open:**
    1. **One machine:** measured only on build 26300; the original machine is build 22000.
    2. **Owner rights untested:** the child's token owner is SYSTEM, which is deny-only. Whether its files carry owner rights is untested.
    3. **Constraint:** the child keeps the service SID and the logon SID enabled. Production B must therefore never grant the service SID on agent-private data, because only the AppContainer check would then protect it.
    4. ~~Narrower variant untested~~: measured in the narrow-variant service run below.
- **Narrow-variant service run (`-AsService -Variants V0,V3–V6`, 2026-11-28, founder-run; grant SID = `NT SERVICE\UDCSTokenExperiment`):**

  | Variant | Groups left enabled (besides the grant SID) | Probe | Student findings / violations | Self-test, kill tree, CUDA |
  |---|---|---|---|---|
  | V0 production (control) | all | ran | 1,015 / 1,015 | pass |
  | V3 | `Users` | child dies `0xC0000022` | — | fail (nothing starts) |
  | V4 | `Users`, Everyone, Authenticated Users | ran | 0 / 0 | pass (21/21 checks, CUDA devices=1) |
  | **V5** | **`Users`, Everyone** | ran | **0 / 0** | **pass (21/21 checks, CUDA devices=1)** |
  | V6 | `Users`, Authenticated Users | child dies `0xC0000022` | — | fail (nothing starts) |

  - **Narrowest working token (measured):** `Users` + Everyone + the service SID enabled. SYSTEM, Administrators, `SERVICE`, `CONSOLE LOGON`, Authenticated Users, This Organization, `LOCAL` and the logon SID are all deny-only. That removes the earlier shared-logon-SID concern (open item 3, for the logon SID only).
  - **Everyone is required:** without it, process startup is denied. Which object needs Everyone is **not identified**. The user-context rehearsal gave the same pattern.
  - In V3/V6 the process is created (its token was captured), then dies during loader start-up. The failure is closed, not a partial sandbox.
  - In V5 the probe reached 5,674 registry keys, against 6,705 in V0. None of them is in a student hive.
  - Cleanup: the service was removed and no folder was left (founder verified both). The snapshot changes (43 `.pyc` files) are the known host-side self-test cause above.
- **Changes B would need in production:**
  - add the SYSTEM SID to `SidsToDisable`;
  - grants name the agent's service SID instead of SYSTEM;
  - the default DACL also names the service SID (without it, the child fails with `0xC0000142`);
  - the window station and desktop grant the service SID.

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
- **2026-11-22, ADR 0001 gate 3 (packaging and delivery).**
  - Implemented manifest, validator, CAS, resumable chunked transfer, node staging and outputs, with no execution.
  - The adversarial review found 11 issues. The high-severity one: an output manifest could grant the job owner any blob in the store. All are fixed, with regression tests and 13 of 13 fix mutations caught.
  - Full suite on Windows: 289 passed, 15 skipped (these need PostgreSQL).
- **2026-11-23, researcher client (`udcs`).**
  - Researchers can prepare, validate, upload and register packages, and attach approved environments and datasets.
  - Package submission is refused honestly while execution is disabled.
  - Catalog jobs can be submitted, watched and verified locally.
  - The adversarial review confirmed 27 findings; all are fixed with regression tests, and 14 of 15 guard mutations are caught.
  - Two latent bugs were fixed: zero-byte blob downloads, and e2e tests writing into `var/`.
- **2026-11-27, package execution pipeline (ADR 0003).**
  - Package jobs got their own contract: exit code, output digest, failure class, run limits.
  - Scheduling now checks administrator eligibility, verified AppContainer, and Python and platform compatibility before the claim.
  - The agent stages, runs in AppContainer, collects only after an empty Job Object, uploads in chunks and reports. Stale attempts cannot publish.
  - The full researcher → controller → agent → AppContainer → fetch path passes for real on one PC. Execution stays disabled by default.
  - Moved to a new PC (build 26300): uv installed from PyPI with approval; the baseline suite passed unchanged there (382 passed, 19 skipped).

