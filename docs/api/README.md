# Controller API (v1)

Base path `/api/v1`. JSON request and response bodies. Interactive schema at `/docs` (OpenAPI), generated from the code, which is the source of truth.

Every response carries `X-Request-ID`. Clients may send their own (≤ 64 chars, `[A-Za-z0-9._-]`), and the agent always does. Errors use FastAPI's shape: `{"detail": ...}`.

## Authentication

| Caller | Header | Credential |
|---|---|---|
| User | `Authorization: Bearer udcs_s_…` | session token from `POST /auth/login` |
| Node agent | `Authorization: Bearer udcs_n_…` | node credential from `POST /agent/enroll` |

The prefixes let each endpoint reject the wrong credential type immediately. A node credential is never accepted on user endpoints, and a session token is never accepted on agent endpoints.

## User endpoints

| Method & path | Permission | Purpose | Status |
|---|---|---|---|
| `POST /auth/login` | public, rate-limited | `{username, password}` → `{access_token, expires_at, user}` | [implemented] |
| `POST /auth/logout` | any user | revoke current session | [implemented] |
| `GET /auth/me` | any user | current user | [implemented] |
| `GET /resources/summary` | `view_resource_summary` (all roles) | aggregate capacity: online nodes, cores, RAM, GPU models & VRAM, without exposing node identities | [implemented] |
| `POST /admin/users` | `manage_users` | create user | [implemented] |
| `GET /admin/users` | `manage_users` | list users | [implemented] |
| `PATCH /admin/users/{id}` | `manage_users` | change role / deactivate (can't demote or deactivate yourself) | [implemented] |
| `POST /admin/enrollment-keys` | `manage_enrollment` | `{lab, ttl_minutes, max_uses, auto_approve, note}` → lab key shown **once** (M1.5; replaces `/admin/enrollment-tokens`) | [implemented] |
| `GET /admin/enrollment-keys` | `manage_enrollment` | keys with use counts (never the secret) | [implemented] |
| `POST /admin/enrollment-keys/{id}/revoke` | `manage_enrollment` | stop further enrollments; enrolled nodes unaffected | [implemented] |
| `GET /admin/nodes` | `view_nodes` | node list with connectivity, inventory, latest telemetry | [implemented] |
| `GET /admin/nodes/{id}` | `view_nodes` | node detail | [implemented] |
| `POST /admin/nodes/{id}/approve` | `manage_nodes` | `pending` → `active` (audited) | [implemented] |
| `POST /admin/nodes/{id}/state` | `manage_nodes` | `{admin_state: active \| maintenance}`; refused for `pending` nodes (approve first) | [implemented] |
| `POST /admin/nodes/{id}/revoke` | `manage_nodes` | permanently revoke node credential | [implemented] |
| `GET /admin/audit-events` | `view_audit` | newest first, `?limit=&action=` | [implemented] |
| `POST /jobs` | `submit_jobs` (all roles) | `{name?, kind: cpu\|memory\|disk\|gpu, total_units, memory_mb?, priority?}`: catalog workloads only (no user code); priority > 0 needs `manage_jobs`; 429 over the per-user unfinished-job limit | [implemented] |
| `GET /jobs` | `submit_jobs` | own jobs, newest first; `?state=&limit=`; `?all=true` lists everyone's for `manage_jobs` | [implemented] |
| `GET /jobs/{id}` | owner or `manage_jobs` | state, `local_state` (the node's governor view, e.g. paused), progress, attempt, failures, requeues, CPU seconds, memory; `node_id` only for `manage_jobs`; others' jobs are 404 | [implemented] |
| `POST /jobs/{id}/cancel` | owner or `manage_jobs` | 409 if already terminal; the node stops and purges it on its next sync | [implemented] |
| `GET /jobs/{id}/logs` | owner or `manage_jobs` | lifecycle log: controller events plus the node's governor events | [implemented] |
| `GET /jobs/{id}/result` | owner or `manage_jobs` | `{result: {units, checksum}, verified}`; 409 unless succeeded | [implemented] |

## Agent endpoints

| Method & path | Auth | Purpose | Status |
|---|---|---|---|
| `POST /agent/enroll` | lab enrollment key in body, rate-limited | `{enrollment_token, protocol_version, inventory, requested_name?}` → `{node_id, node_credential, heartbeat_interval_seconds, admin_state}`; `admin_state` is `pending` unless the key auto-approves | [implemented] |
| `POST /agent/heartbeat` | node credential | `{protocol_version, telemetry, inventory_fingerprint}` → `{heartbeat_interval_seconds, inventory_required, admin_state, protection_policy, rotate_credential}` | [implemented] |
| `POST /agent/credential/rotate` | node credential | → `{node_credential}`; the old credential stays valid until the new one is first used | [implemented] |
| `PUT /agent/inventory` | node credential | `{inventory}` → 204 | [implemented] |
| `POST /agent/jobs/sync` | node credential | `{protocol_version, reports[], capacity}` → `{assignments[], cancel[], acknowledged[], lease_seconds}`; reconciling and idempotent; see [execution-pipeline.md](../architecture/execution-pipeline.md) | [implemented] |

## Health

| Path | Purpose |
|---|---|
| `GET /healthz` | process liveness (no DB) |
| `GET /readyz` | DB reachable → 200, else 503 |

## Status codes the agent acts on

| Code | Agent behaviour |
|---|---|
| 2xx | success |
| 401 / 403 on node endpoints | credential invalid or node revoked → stop heartbeating, **pause all UDCS work** (persisted), keep local protection running |
| 422 / other 4xx | protocol bug → log, back off, retry |
| 429, 5xx, network error, timeout | controller unavailable → exponential back-off with jitter, capped at 300 s |

## Protocol version 2 (Milestone 1.5)

Version 1 agents are rejected with HTTP 400. There is no deployed fleet, so the controller does not support both versions. Changes:

- `telemetry.user_idle_seconds` is **removed**. Raw input timing never leaves the machine.
- `telemetry.interactive_state` is one of `no_user | locked | idle | active` (coarse, privacy-preserving).
- `telemetry.usage` splits CPU, memory and GPU into `total / udcs / non_udcs`. **`non_udcs` is not "the student"**: it includes Windows and unrelated services.
- `telemetry.protection` reports the local level, coarse reasons, workload counts and the governor's own overhead.
- The heartbeat response carries `protection_policy`. The agent enforces the **stricter** of that policy and its local floor, field by field, so the controller can only tighten protection.
