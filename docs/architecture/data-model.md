# Data Model

PostgreSQL is the target database. All timestamps are timezone-aware UTC (`timestamptz`), and all primary keys are UUIDs. Enums are stored as constrained `VARCHAR` (`CHECK`), not native PG enums, so adding a value is a simple migration. Constraint names follow a fixed naming convention so Alembic diffs stay stable.

## Implemented in M1

```
users ─┬─< auth_sessions
       └─< enrollment_tokens >── nodes ──1:1── hardware_inventories
audit_events (append-only, references actors/targets by id, no FKs)
```

### `users`
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| username | varchar(64) UNIQUE | lowercase, `^[a-z0-9][a-z0-9._-]{2,63}$` |
| display_name | varchar(128) | |
| password_hash | varchar(255) | Argon2id |
| role | varchar(32) CHECK | `student` \| `researcher` \| `admin` |
| is_active | bool | deactivated users can't authenticate |
| created_at, updated_at | timestamptz | |

### `auth_sessions`
Opaque bearer sessions. `token_hash` = SHA-256 of the 256-bit token; the plaintext is never stored.
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| user_id | uuid FK → users ON DELETE CASCADE | indexed |
| token_hash | char(64) UNIQUE | |
| created_at, expires_at | timestamptz | |
| revoked_at | timestamptz NULL | logout / admin revocation |
| client_ip | varchar(45) NULL | |

### `enrollment_tokens`
Single-use, expiring. Consumption is an atomic `UPDATE … WHERE used_at IS NULL`, so two agents racing with the same token cannot both succeed.
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| token_hash | char(64) UNIQUE | |
| created_by_user_id | uuid FK → users ON DELETE SET NULL | |
| note | varchar(256) | e.g. "Lab B row 3" |
| created_at, expires_at | timestamptz | |
| used_at | timestamptz NULL | |
| node_id | uuid FK → nodes ON DELETE SET NULL | the node it created |

### `nodes`
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| name | varchar(128) | admin-facing name, defaults to hostname |
| hostname | varchar(255) | as reported (untrusted, informational) |
| admin_state | varchar(32) CHECK, indexed | `active` \| `maintenance` \| `revoked` |
| credential_hash | char(64) UNIQUE | SHA-256 of node credential |
| enrolled_at | timestamptz | |
| revoked_at | timestamptz NULL | |
| last_heartbeat_at | timestamptz NULL | **controller clock**, not agent clock |
| last_seen_ip | varchar(45) NULL | |
| agent_version | varchar(32) | |
| protocol_version | int | |
| inventory_fingerprint | char(64) NULL | SHA-256 of canonical inventory JSON, computed by the controller |
| latest_telemetry | jsonb NULL | overwritten each heartbeat (see D7) |

Connectivity (`online`/`offline`) is **not stored**. It is derived: `online ⇔ now − last_heartbeat_at < interval × missed_threshold`.

### `hardware_inventories`
The current inventory per node (one row), plus denormalized columns for fast capacity queries.
| column | type | notes |
|---|---|---|
| node_id | uuid PK, FK → nodes ON DELETE CASCADE | |
| fingerprint | char(64) | |
| inventory | jsonb | full validated `HardwareInventory` |
| logical_cores | int | |
| memory_total_bytes | bigint | |
| gpu_count | int | |
| gpu_memory_total_bytes | bigint | sum across GPUs |
| updated_at | timestamptz | |

### `audit_events`
Append-only. No FKs, so audit history survives deletion of the user or node it refers to.
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| created_at | timestamptz, indexed | |
| actor_type | varchar(16) CHECK | `user` \| `node` \| `anonymous` \| `system` |
| actor_id | uuid NULL | |
| action | varchar(64), indexed | e.g. `auth.login_failed`, `node.enrolled`, `node.revoked` |
| target_type, target_id | varchar NULL | |
| details | jsonb | never contains secrets |
| client_ip | varchar(45) NULL | |
| request_id | varchar(64) NULL | correlation id |

## Proposed for M2+ **[proposed]**

- `jobs` — owner, spec (image/runtime, entrypoint, resource request), priority, `state` (state machine below), `state_version` (optimistic concurrency), timestamps.
- `job_tasks` — the unit of placement; a Level-1 job has one task, a Level-2 job has many.
- `job_assignments` — task ↔ node attempt with `attempt_number`, lease expiry, exit status. A new attempt row on each retry keeps history.
- `job_events` — append-only state transitions and agent-reported events, deduplicated by `(assignment_id, agent_seq)` for idempotency.
- `job_artifacts` — metadata only (content-addressed SHA-256, size, storage key). Blobs live on the filesystem or object store, not in PostgreSQL.
- `resource_reservations` — node, resources, window, reason (e.g. teaching session).
- `scheduling_policies` — versioned JSON policy documents with an active pointer.
- Log lines: **not** in PostgreSQL. Chunked files per assignment, with an index row in `job_artifacts`.

Job state machine **[proposed]**: `SUBMITTED → VALIDATING → QUEUED → SCHEDULED → DISPATCHED → PREPARING → RUNNING → {COMPLETED | FAILED | CANCELLED | INTERRUPTED}`, with `RUNNING ⇄ PAUSING → PAUSED → RESUMING → RUNNING` only for jobs that declare checkpoint support. The controller owns state. Agents report *events*, and the controller validates them against the current state and `state_version`.
