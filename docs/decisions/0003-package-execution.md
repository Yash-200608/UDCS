# ADR 0003: Package execution pipeline

- **Status:** implemented and tested on one PC (Windows 11, build 26300, interactive user, not elevated), 2026-11-27.
- **Default:** user code execution stays **disabled** in every shipped default. Three independent switches must all be on before a package runs anywhere:
  1. the controller flag, `user_code_enabled = false`;
  2. the agent constant, `USER_CODE_ENABLED = False`;
  3. a per-node administrator flag, `user_code_allowed = false` for every node, new and existing.

  The tests turn them on in memory, in the test process only.
- **Blocked on (before enabling anywhere real):**
  - M1.5 installed-service acceptance pass 2 (start after a reboot);
  - ADR 0001 gate 2 (an audit of what a lab image exposes to ALL APPLICATION PACKAGES);
  - an operator procedure for granting the per-node flag.
- **Builds on:** [ADR 0001](0001-workload-isolation.md) (AppContainer) and [ADR 0002](0002-user-code-packaging.md) (packaging and delivery).

## 1. Contract (`udcs_shared.jobs`)

Catalog jobs are unchanged: units, a closed-form checksum, catalog checkpoints. Package jobs differ:

| Aspect | Package jobs |
|---|---|
| Units | `total_units` is 1 and carries no meaning. Clients no longer send it. |
| Limits | `JobSpec.limits` holds `PackageRunLimits` (runtime, output bytes, output files, walk entries, walk depth). These are the package's own limits capped by the deployment policy, fixed at submission (`jobs.run_limits`). |
| Local states | Adds `staging` (fetching and verifying; nothing runs) and `uploading` (the process tree is gone; outputs are being uploaded). |
| Result | `PackageResult`: `exit_code`, `outputs_sha256` (the SHA-256 of the canonical output manifest the node reported), file count and bytes. |
| Failure class | `FailureKind` on every report. `workload` (a non-zero exit, runtime, storage or output limits, refused outputs) is **final**, because re-running the same package elsewhere would fail the same way. `infrastructure` (staging, verification, isolation, a process tree that would not die) is retried on another node, as before. |
| Success | Exit code 0 **and** `outputs_sha256` equal to the digest of the output manifest **this attempt** reported, whose blobs this attempt uploaded (ADR 0002 F1). A non-zero exit is `failed` with `exit_code` recorded, and not retried. |
| Logs | stdout and stderr go to `logs/` in the sandbox. The last 20 lines go into the job log, and the last 4 MiB of each stream become outputs under the reserved name `udcs-logs/`. |

## 2. Scheduling (`jobs/service.py`, `package_mismatch`)

A package job is offered to a node only if **all** of these hold. They are checked before the atomic claim, so an incompatible node never holds the job, and it stays queued for one that fits:

1. the controller flag is on, and the node's sync offers `user_code`;
2. the node's administrator flag `user_code_allowed` is set (`POST /admin/nodes/{id}/user-code`, `MANAGE_NODES`, audited with a reason);
3. the node's inventory reports `appcontainer` as **available and verified** (a real launch it measured itself, not mere presence);
4. the node's offered Python equals the package's;
5. if the package uses an environment: it is still approved, and its platform and Python equal the node's.

`NodeOut.user_code_ready` shows whether conditions 2 and 3 hold. The agent repeats checks 4 and 5 itself (defence in depth) and refuses a closure whose manifests do not hash to the digests they are filed under, which catches substitution.

## 3. Agent execution (`package_runs.py`, `jobs.py`, `workloads/manager.py`)

Phases of an assignment:

1. **staging:**
   - fetch the closure and verify every manifest digest;
   - download every blob with Range resume into the verified node cache;
   - stage `staging/<job>-<attempt>/`, re-hashing every byte;
   - create `state/`, `logs/` and `tmp/`;
   - restore a central package checkpoint into `state/checkpoint.bin` if the assignment carries one.
2. **ready:** the workload manager launches the run in a fresh AppContainer profile inside a Job Object:
   - `python -I -S -B`, with the entry script run via `runpy` and an explicit `sys.path` of the source and the environment only;
   - read/execute on the source, environment, inputs and config, and modify on `out/`, `state/`, `logs/` and `tmp/` only;
   - no network capability, a private desktop, UI restrictions;
   - memory capped at the requested size and by the governor's share.

   The governor throttles, pauses and evicts it like any workload. An evicted run is killed and later restarted from the beginning, with `out/` and `logs/` cleared and `state/` kept.
3. **finished:** when the main process exits, the manager terminates the whole Job Object and **waits until it is empty** before marking the run finished. Collection never starts while any process of the run can still write. If the tree does not empty within 10 s, the run fails as an infrastructure failure (`tree_survived`).
4. **uploading:**
   - outputs are copied through checked handles into a private snapshot (ADR 0002 F5/F6);
   - the log tails are added, and `out/udcs-logs/` is refused;
   - every file is uploaded in chunks as this attempt, then the manifest is reported.

   A retried report after a lost response counts as done. A 409 means the attempt is no longer current, and nothing is published.
5. **done or failed:** the result is reported; the workload and its AppContainer profile are removed once the controller acknowledges it, and the staging tree one sync later.

**Limits enforced on the node:**

| Limit | How |
|---|---|
| Runtime | Running time, not counting pauses: a paused run is not penalised for the student being present |
| Storage | `out/` + `state/` + `logs/` + `tmp/` ≤ output limit + 64 MiB, measured every 5 s by opening each file (NTFS directory entries report stale sizes for open files: measured, and the first implementation missed it) |
| Output | File, byte, entry and depth limits at collection |
| Memory | Job Object limit |

**Package checkpoints:**
- A package may write `state/checkpoint.bin` (at most 1 MiB, opaque). The agent uploads it when its hash changes, with `units_done = 0` and an increasing version.
- The controller stores it without catalog validation; integrity is the hash.
- On reassignment the new node restores it before the run starts.
- What the bytes mean is the package's business.

## 4. Fencing and recovery

| Event | Behaviour |
|---|---|
| Cancel during the run | The run is killed with its tree; staging is removed; nothing is published (e2e tested) |
| Cancel during upload | Blob uploads and the output report get 409; the next report is told to cancel (tested) |
| Node loss | The lease expires and the job is requeued. The stale attempt's uploads and output report get 409, and its result report is cancelled; the new attempt publishes normally (tested) |
| A newer attempt reassigned to the same node | The old run is removed and the job restarts from staging under the new attempt (tested) |
| Agent restart | `assignments.json` keeps the phase. A `ready` run is re-added; a finished run's result is re-reported |

## 5. Measured (2026-11-27, i-class laptop, build 26300)

- **The full path, researcher CLI → HTTPS controller → scheduler → `AgentApp` → AppContainer → chunked upload → `udcs fetch`**, takes about 2 minutes for the two e2e tests together. Most of that is the node's start-up isolation detection and 5 s heartbeats, not execution.
- **A trivial package's AppContainer run** takes about 1 s from launch to exit.

These are single runs on one machine, not benchmarks.

## 6. Acceptance-readiness changes (2026-11-27)

- **A fourth condition:** the agent offers user code only when it runs as **LocalSystem**. The exposure audit measured that an interactive agent's sandbox can stop the student's per-user services and open their desktop.
- **Eligibility** now needs a passing, SYSTEM-context exposure audit of the node's current image (operator procedure: `docs/operations/node-eligibility.md`). It is bound to that image and is suspended automatically when the image changes.
- **Revocation, a lost capability or the controller flag switched off** stop package jobs already running (requeued, cancelled on the node), and every node package endpoint refuses.
- **A requeue clears** the previous attempt's outputs and exit code.

## 7. Not done (honest)

- **Real-fleet enablement.** Blocked as above. Nothing here has run as the installed service (LocalSystem, session 0) with user code; the service-path isolation gate (ADR 0001 gate 1) covered the catalog only.
- **GPU packages.** The `gpu` resource class is scheduled like any other, but CUDA inside AppContainer was verified only for the catalog `cuInit` path, not for researcher frameworks.
- **Networked packages.** By design there is no network. Packages needing data must use datasets.
- **Per-group dataset access.**
- **Output storage charged to quotas.** Bounded by output limits only.
- **Result attestation** (T26). A dishonest node can still fabricate outputs.
- **Trusting the node's self-report.** "Verified AppContainer" is what the node reports about itself. A compromised or lying node could claim it (DEVELOPMENT_STATUS known limitation 4). The administrator's per-node flag is therefore the control that actually counts; node attestation is M3 work.
- **Two-node e2e for packages.** Node loss is tested at controller and agent level, not with two live agents (the catalog two-node e2e exists).
