# Execution pipeline (Milestone 2, catalog phase)

_2026-11-22. Status: **implemented and tested** on one Windows 11 PC, with two agent instances against a real TLS controller. Not tested on separate machines or at fleet scale._

```
user ──POST /jobs──▶ controller (jobs table)
                         ▲      │
       reports + offer   │      │ assignments / cancel / ack
                         │      ▼
            node agent: JobSync ──request queue──▶ WorkloadManager ◀── governor (1 s)
                                                      │ Job Object
                                                      ▼
                                          catalog workload (checkpoint, result.json)
```

## What runs

Only the **built-in catalog**: the `cpu`, `memory`, `disk` and `gpu` synthetic workloads, with bounded parameters (`total_units` ≤ 10⁷, `memory_mb` ≤ 4096).
- **No user code.** A job request cannot carry code, a command line, paths or environment. An unknown `kind` is a validation error.
- **Why.** Arbitrary code stays blocked until the [ADR 0001](../decisions/0001-workload-isolation.md) gate passes. Catalog workloads already run inside a per-workload AppContainer wherever the node has verified that backend, and on the host (Job Object only) elsewhere. The level is recorded in each job's log (`started (appcontainer)`).

## Who decides what

| Decision | Made by |
|---|---|
| Whether a job may exist, and its priority | controller (permissions, per-user limit; priority > 0 needs `manage_jobs`) |
| Whether a node takes *new* work, and which classes | **node**. `NodeJobCapacity` is derived from the governor's current envelope. Nothing is offered while the node is under pressure, CONSTRAINED, PROTECTED or MAINTENANCE, or the controller has said "no work" |
| Which queued jobs fit that offer | controller scheduler |
| Whether an accepted job runs, is capped, paused or evicted right now | **governor**, every ~1 s, exactly as for any other workload. The controller only *observes* this (`local_state`) |

The controller can therefore never push work past local protection.

## Sync protocol: `POST /agent/jobs/sync`

There is one reconciling round trip after each heartbeat, on the same thread, so a controller outage backs it off together with the heartbeat.

**Request:**
- every job the agent holds, each with its `attempt`, local state, progress, CPU seconds, memory bytes, new log lines, and the result once it has one;
- a capacity offer: `accept`, `slots`, `kinds` and `memory_available_mb`.

**Response:**
- `assignments`;
- `cancel` (stop and discard);
- `acknowledged` (terminal report recorded; the agent may clean up);
- `lease_seconds`.

**Idempotence:** replaying a request after a lost response is safe. A completed report that was already recorded is acknowledged again, not cancelled.

## Correctness rules

| Rule | Mechanism | Test |
|---|---|---|
| A job runs on at most one node *as the current attempt* | candidates are locked `FOR UPDATE SKIP LOCKED` (concurrent syncs see disjoint rows and never wait), plus the claim `UPDATE … WHERE state = 'queued'` as a second guard; `attempt` increments on every assignment | **PostgreSQL race tests** (`test_jobs_concurrency.py`): independent sessions released together by a barrier; 50 rounds in CI. A mutation probe with both guards removed fails them |
| Reports, reaping and cancel cannot overwrite each other | every read-modify-write locks the job row (`FOR UPDATE`); the reaper skips locked rows | PostgreSQL race test: a completion report racing the reaper ends in exactly one consistent state |
| Stale work cannot overwrite current work | a report whose `(node, attempt)` does not match the job is ignored, and the node is told to cancel | `test_stale_attempt_reports_are_fenced…`, `test_same_node_old_attempt_is_fenced…` |
| A lost node loses neither the job nor its progress | a lease that is not renewed is requeued with a new attempt, keeping the central checkpoint's progress; after too many requeues the job fails | e2e `test_lost_node_job_resumes_on_another_node_from_the_central_checkpoint` (the original node's disk is deleted) |
| A lost assignment (response never arrived) is recovered at once | a job assigned to a node that does not report it is requeued on that node's next sync | `test_stale_attempt_reports…` |
| A controller restart does not mass-requeue | no lease is reaped during the first lease period after start, so nodes renew first | `test_controller_restart_does_not_requeue_before_nodes_can_renew` |
| An agent restart resumes rather than restarts | `jobs/assignments.json` is written *before* the workload exists; the workload resumes from its checkpoint with the same attempt | e2e `test_agent_restart_resumes_the_same_attempt…` |
| A lost or repeated unit is detected | `result.checksum` = Σ i² over the processed unit indices, checkpointed with `units_done`; the controller checks it in O(1) | `test_wrong_checksum_is_a_failure…`, e2e |
| Failures are bounded | `job_max_failures` (3) for workload failures or bad results, and `job_max_requeues` (10) for lease losses | unit tests |
| Finished or cancelled jobs leave nothing behind | an acknowledgement or cancel purges the workload directory; the manager waits for the process to exit and retries, because Windows will not delete a running process's working directory | `test_purge_removes_a_running_workloads_directory`, e2e cancel |

## Checkpoint migration (implemented, tested)

**Upload.** After each sync, the agent uploads a running job's local `checkpoint.json` whenever its progress has advanced. Uploads are rate-limited by `checkpoint_upload_seconds` (default 15 s).
- **Atomic:** one request carries the bytes, their SHA-256 and `units_done`.
- **Version:** the upload's version is `units_done`, so it is monotonic per attempt and stays valid across agent restarts.

**Controller acceptance** (`PUT /agent/jobs/{id}/checkpoint`) requires all of the following, under the job's row lock:
- the uploader holds the current attempt on its own node (fencing, exactly as for reports);
- the payload decodes, is within 1 MiB, and matches the SHA-256;
- the content is a consistent catalog checkpoint, whose checksum must equal the closed form for its `units_done`;
- progress is not behind the stored checkpoint, and the version is newer for the same attempt.

If any check fails, nothing is stored and the previous version stays. A truncated, interrupted or corrupted upload can therefore never replace a good checkpoint, and a retry of an accepted upload is idempotent.

**Resume.**
- **Requeue:** a requeue keeps the checkpoint's progress, and the next assignment carries a `CheckpointRef` (version, units, SHA-256, size).
- **Before the workload starts:** the new node downloads the checkpoint (`GET …/checkpoint?attempt=N`, fenced) and verifies its hash against the reference, the version and units against the reference, and its semantics. It then installs the checkpoint into the workload directory and only then creates the workload, which resumes from it.
- **Controller unreachable:** the job keeps waiting and the download is retried.
- **Checkpoint unusable:** the job starts from zero, never from bad state, and its log says why.

**What is still repeated:** only the units done after the last accepted upload, which is at most one upload interval of work.

**When checkpoints are discarded:** a checkpoint is deleted when its job finishes, and it is not reused after a failed attempt, because that run's state may be the cause of the failure.

**Limits:**
- one checkpoint version per job (no history);
- at most 1 MiB, in one request; larger state needs chunked, resumable uploads (future);
- payloads are stored in PostgreSQL. That is fine for catalog checkpoints of a few hundred bytes, but not for gigabyte model state, which needs object storage;
- semantic validation exists only for catalog checkpoints. User workloads (D-3) would need their own integrity model.

## Scheduling (proposed design, implemented)

The scheduler is **pull-based**: when a node syncs with an offer, the controller picks from at most 200 queued candidates. Candidates are ordered by these keys:
1. priority, descending;
2. on a GPU node, GPU jobs first (only GPU nodes can run them);
3. fair share: the owner with fewer jobs already running goes first;
4. queue time.

Each candidate must fit the offer's kinds, remaining slots and memory. A GPU job also needs GPUs in the node's *inventory*, whatever the node offers.

This is deliberately simple. It does not yet do any of the following:
- predictive availability ("this lab empties at 17:00");
- preemption of low-priority work;
- quotas beyond the per-user unfinished-job limit.

## Known limits (honest)

- **Delivery is at-least-once.** During a network partition a node can keep running a job that has already been reassigned, so the work is done twice. Only the current attempt's result is accepted.
- **The checksum detects bugs, not cheating.** A malicious node can compute it without doing the work. Result attestation is open (T26, with T6).
- **Race tests run only in CI.** No PostgreSQL is installed on the development PC, so they need CI to run. A local SQLite run skips them.
- **A freshly started agent takes no work for at least 30 s.** This is by design: the governor starts at CONSTRAINED and offers work only after 30 s of continuous calm, and any noise restarts the timer. After a reboot a lab PC therefore joins the pool with a delay, and the agent logs each `job offer:` change. CI exposed this: an e2e wait of 60 s was too short on a noisy runner.
- **Short jobs report coarsely.** Progress arrives once per heartbeat (default 15 s). A job shorter than that can go straight from `assigned` to `succeeded`.
- **Job logs are lifecycle events only:** started, paused, evicted, completed and similar. Catalog workloads print nothing else, and stdout capture belongs with user code (D-3).
- **Lease reaping is lazy.** It happens on node syncs and on job reads, so a fleet with no syncing node and no readers does not reap. That is harmless, because no node could run the work anyway.
- **Both e2e "nodes" share one PC,** so each sees the other's work as non-UDCS load. Real multi-machine behaviour (clock skew, NAT, a real power-off) is untested.
- **The Windows-service path of the pipeline is not exercised.** The e2e tests run `AgentApp` in-process as the current user, so as SYSTEM in session 0 it is still part of the open M1.5 elevated acceptance.
