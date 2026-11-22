# UDCS Architecture

Status labels used throughout: **[implemented]**, **[tested]**, **[proposed]**, **[assumption]**, **[future]**.

## 1. Development environment (inspected 2026-11-21)

| Item | Finding | Consequence |
|---|---|---|
| OS | Windows 11 Pro Education (10.0.22000) | Windows is the primary agent target, as required. |
| Python | 3.12.10 (also 3.11, 3.10); `uv` 0.11 | Python ≥ 3.11; `uv` workspace monorepo. |
| CPU / RAM | Intel i5-6500, 4C/4T, 24 GB | — |
| GPU | GeForce GT 730, 2 GB, driver 456.71, CUDA 11.1 | NVML reports utilization `N/A` on this card, so every GPU field must be optional. Its compute capability is below what current PyTorch builds support, so "has an NVIDIA GPU" ≠ "can run CUDA ML workloads". |
| PostgreSQL | Not installed | Code targets PostgreSQL. Local tests use SQLite through the same SQLAlchemy models; CI runs against real PostgreSQL. **The PostgreSQL path is unverified until CI runs.** |
| Docker / WSL | Not installed | Confirms the requirement that we can't assume containers on lab machines. This matters most in Milestone 2 (isolation). |
| Redis | Not installed | Not needed for M1. |
| `nvcc` | Not installed | Not needed: the agent uses the driver's NVML, not the CUDA toolkit. |

## 2. Architecture assessment

The three-layer split (control plane / application plane / execution plane) is sound and matches how proven batch systems are built. My main concerns:

1. **Prior art.** HTCondor has been scavenging idle university desktops since the late 1980s, and it supports owner-priority policies, checkpointing and Windows execute nodes. UDCS needs a clear answer to "why not HTCondor?". Plausible answers: a modern GPU-first scheduling model, student-first protection tuned to lab PCs, and far simpler operations for a university IT team. Until that answer is written down, we risk rebuilding a weaker HTCondor. **[open question for the founder]**
2. **Execution isolation on Windows without Docker is the project's hardest problem.** It is not the scheduler. With no containers or VMs, a Windows process running untrusted code under a low-privilege account (Job Objects, restricted token) limits *resources* but is a weak *security* boundary, especially on a machine where a student is logged in. This decision fundamentally shapes M2 and needs to be made before then (see §6).
3. **Three protocols (REST + gRPC + WebSockets) is too many for M1.** See decision D2.
4. **"Pause any GPU job" is not physically possible in general.** The design keeps cooperative pause/checkpoint as an opt-in workload capability, as the spec already acknowledges.

## 3. Key decisions for M1

**D1 — Monorepo with a `uv` workspace and three packages.** `udcs-shared` (wire contracts), `udcs-controller`, `udcs-agent`. The agent does not depend on FastAPI or SQLAlchemy, so lab machines install a small package.

**D2 — Agent ↔ controller over HTTPS + JSON (REST), not gRPC. *Deviates from the spec.*** The agent always initiates outbound connections, which works through NAT, separate subnets, dynamic IPs and default-deny inbound firewalls on lab PCs. One protocol stack means one auth path, one TLS config and one set of tests. Pydantic models in `udcs-shared` give typed contracts without protobuf codegen. *Revisit when* M2 needs low-latency dispatch and log streaming. Then compare a long-poll/WebSocket channel against gRPC streaming on measured latency and operational cost.

**D3 — Synchronous SQLAlchemy 2.0 with psycopg 3, run in FastAPI's thread pool.** Expected load is small. 500 nodes at a 15 s heartbeat is about 33 writes/s, well within a thread pool. Async SQLAlchemy would add a second driver stack and harder debugging for no measured benefit. *Revisit if* profiling shows thread-pool saturation.

**D4 — Opaque, hashed bearer tokens instead of JWTs.** Both user sessions and node credentials are 256-bit random secrets. Only their SHA-256 hash is stored. Revocation is immediate (a row update), and there is no signing key to manage or rotate. The cost is one indexed lookup per request, which is negligible at university scale.

**D5 — Node enrollment with single-use, expiring, admin-issued tokens.** In exchange for a token, the agent receives a long-lived node credential. The controller stores only its hash. Revoking a node invalidates the credential at once. mTLS client certificates are **[future]**: stronger, but they need a CA and rotation, which is a large burden for IT teams in M1.

**D6 — Node state has two separate dimensions.** *Admin state* (`active`, `maintenance`, `revoked`) is set only by admins. *Connectivity* (`online`, `offline`) is **derived** from the last heartbeat time, so no background sweeper can drift out of sync with reality. A node can be scheduled only when it is `active` and `online`.

**D7 — Latest telemetry only, no time series in PostgreSQL.** Each heartbeat overwrites one JSON column on the node row. Time-series metrics will go to a Prometheus-compatible endpoint **[future, M1.x]**. This follows the spec's warning about telemetry load on the database.

**D8 — Roles and permissions defined in code (`student`, `researcher`, `admin`), not in database tables. *Deviates from the proposed schema.*** Three fixed roles don't justify a configurable RBAC data model yet. Moving to tables later is a straightforward migration if real policy needs appear.

**D9 — Plaintext HTTP is refused by default.** The controller won't bind a non-loopback address without TLS unless the admin explicitly passes `--insecure-allow-plaintext` (meant for TLS terminated by a reverse proxy). The agent refuses `http://` controller URLs without `--allow-insecure-http`.

**D10 — The agent's node credential is encrypted at rest with Windows DPAPI (machine scope).** A copied credential file is useless on another machine. File ACL hardening belongs to the installer (M7).

## 4. Repository structure (actual, not aspirational)

Directories are created only when they hold real code.

```
UDCS/
├── pyproject.toml              # uv workspace root, dev tooling config
├── shared/                     # udcs-shared: wire contracts used by both sides
│   └── src/udcs_shared/        #   hardware.py, telemetry.py, agent_api.py, logging.py
├── controller/                 # udcs-controller: FastAPI control plane
│   └── src/udcs_controller/
│       ├── core/               #   security, rate limiting, request context
│       ├── database/           #   engine, base types, Alembic migrations
│       ├── auth/               #   users, sessions, roles, login API
│       ├── nodes/              #   enrollment, registry, heartbeat, agent API
│       └── audit/              #   audit events
├── node_agent/                 # udcs-agent: execution-plane agent
│   └── src/udcs_agent/
│       ├── discovery/          #   OS/CPU/RAM/disk/network + NVIDIA (NVML)
│       ├── monitoring/         #   telemetry, interactive-idle detection
│       └── communication/      #   controller HTTPS client
├── tests/e2e/                  # cross-package end-to-end tests (real TLS)
├── docs/                       # architecture, api, security
└── .github/workflows/ci.yml
```

Future directories, added when their milestone starts: `node_agent/.../execution`, `isolation`, `protection`, `checkpointing`, `service`; `controller/.../scheduler`, `jobs`, `policies`; `applications/`; `infrastructure/`.

## 5. Dependency plan

Exact versions are pinned in `uv.lock`. `pyproject.toml` files carry compatible ranges.

| Package | Used by | Why |
|---|---|---|
| pydantic 2 | all | API boundary validation |
| fastapi, uvicorn | controller | HTTP API and ASGI server (TLS support built in) |
| sqlalchemy 2, alembic | controller | ORM + migrations |
| psycopg 3 (binary) | controller | PostgreSQL driver |
| pydantic-settings | controller | env-based configuration |
| argon2-cffi | controller | Argon2id password hashing |
| httpx | agent | HTTPS client with CA pinning support |
| psutil | agent | cross-platform CPU/RAM/disk/network |
| nvidia-ml-py | agent | official NVML bindings (no CUDA toolkit needed) |
| pytest, ruff, trustme | dev | tests, linting, throwaway TLS CA for e2e tests |

Deliberately **not** used in M1: Redis (PostgreSQL `SELECT … FOR UPDATE SKIP LOCKED` should cover the M2 job queue), gRPC, Celery, Docker, PySide6.

## 6. Milestone plan

| M | Scope | Acceptance test | Notes |
|---|---|---|---|
| **1** | Workspace, controller, DB + migrations, user auth, enrollment, node identity, discovery, heartbeat, telemetry, node status | Agent on this Windows machine enrolls over TLS, reports real hardware, heartbeats; controller shows it `online` | In progress. Windows service wrapper → see status file. |
| 2 | Job model + state machine, submission, Postgres-backed queue, basic placement, dispatch via agent pull, execution, logs, results, cancel | Python job submitted → runs on a remote node → result returned | **Blocked on an isolation decision** (below). |
| 3 | Resource-aware placement (GPU arch/VRAM/CUDA, CPU/RAM), reservations, student-first priority, placement diagnostics ("why wasn't my job placed?") | Placement picks a correct node for real requirements; explains rejections | |
| 4 | Local protection: thresholds, throttling (Job Objects), cooperative pause/checkpoint API, preemption, recovery | Simulated pressure releases resources within a bounded time | Idle detection groundwork exists in M1. |
| 5 | Researcher app and admin app | Real backend data only | Recommend the **admin UI be web-based** (no per-PC install for IT staff); researcher client TBD. |
| 6 | Task-parallel jobs, PyTorch DDP on homogeneous node subsets, benchmarks vs single node | Measured speedup or measured reason why not | Heterogeneous DDP runs at the speed of the slowest GPU, so placement must group similar nodes. |
| 7 | Installer (MSI/WinSW service), config management, backups, upgrades, runbooks | Clean install on a fresh lab PC | |

**Decision needed before M2: execution isolation strategy on Windows.** Options:
(a) Require Docker Desktop or Hyper-V containers on participating nodes. Strong isolation, but heavy, and licensing may matter.
(b) WSL2 + containers. Good isolation, but needs virtualization and admin setup per PC.
(c) A native Windows process with a dedicated low-privilege account, Job Object limits and a restricted token. Lightweight, but a weak security boundary.
(d) Tiered trust: only vetted researchers may run native jobs; untrusted workloads are allowed only on nodes with (a) or (b).
My current recommendation is **(d)**. It is an architectural commitment that affects lab PC provisioning, so the founder should make it.
