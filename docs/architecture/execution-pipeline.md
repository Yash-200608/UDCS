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
- **Why.** Arbitrary code stays blocked until an isolation model is approved (D-3, threat T10).

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
| A job runs on at most one node *as the current attempt* | atomic claim: `UPDATE … WHERE state = 'queued'`; `attempt` increments on every assignment | `test_two_nodes_never_receive_the_same_job…` (sequential only; see limits) |
| Stale work cannot overwrite current work | a report whose `(node, attempt)` does not match the job is ignored, and the node is told to cancel | `test_stale_attempt_reports_are_fenced…`, `test_same_node_old_attempt_is_fenced…` |
| A lost node does not lose the job | a lease that is not renewed is requeued with a new attempt; after too many requeues the job fails | unit test plus e2e `test_lost_node_job_is_requeued_and_finished_elsewhere` |
| A lost assignment (response never arrived) is recovered at once | a job assigned to a node that does not report it is requeued on that node's next sync | `test_stale_attempt_reports…` |
| A controller restart does not mass-requeue | no lease is reaped during the first lease period after start, so nodes renew first | `test_controller_restart_does_not_requeue_before_nodes_can_renew` |
| An agent restart resumes rather than restarts | `jobs/assignments.json` is written *before* the workload exists; the workload resumes from its checkpoint with the same attempt | e2e `test_agent_restart_resumes_the_same_attempt…` |
| A lost or repeated unit is detected | `result.checksum` = Σ i² over the processed unit indices, checkpointed with `units_done`; the controller checks it in O(1) | `test_wrong_checksum_is_a_failure…`, e2e |
| Failures are bounded | `job_max_failures` (3) for workload failures or bad results, and `job_max_requeues` (10) for lease losses | unit tests |
| Finished or cancelled jobs leave nothing behind | an acknowledgement or cancel purges the workload directory; the manager waits for the process to exit and retries, because Windows will not delete a running process's working directory | `test_purge_removes_a_running_workloads_directory`, e2e cancel |

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
- checkpoint migration between nodes (a requeued job restarts from zero);
- quotas beyond the per-user unfinished-job limit.

## Known limits (honest)

- **Delivery is at-least-once.** During a network partition a node can keep running a job that has already been reassigned, so the work is done twice. Only the current attempt's result is accepted.
- **The checksum detects bugs, not cheating.** A malicious node can compute it without doing the work. Result attestation is open (T26, with T6).
- **Concurrency of the claim is not tested.** It relies on the conditional UPDATE. No test runs two real concurrent transactions, and a mutation that removes the `state = 'queued'` guard is not caught by the suite.
- **Short jobs report coarsely.** Progress arrives once per heartbeat (default 15 s). A job shorter than that can go straight from `assigned` to `succeeded`.
- **Job logs are lifecycle events only:** started, paused, evicted, completed and similar. Catalog workloads print nothing else, and stdout capture belongs with user code (D-3).
- **Lease reaping is lazy.** It happens on node syncs and on job reads, so a fleet with no syncing node and no readers does not reap. That is harmless, because no node could run the work anyway.
- **Both e2e "nodes" share one PC,** so each sees the other's work as non-UDCS load. Real multi-machine behaviour (clock skew, NAT, a real power-off) is untested.
- **The Windows-service path of the pipeline is not exercised.** The e2e tests run `AgentApp` in-process as the current user, so as SYSTEM in session 0 it is still part of the open M1.5 elevated acceptance.
