# Security Threat Assessment

Scope: M1 (control plane, enrollment, telemetry), plus the threats that M2 execution introduces, so they inform design now.

## Assets

1. Lab PCs and the students using them. Their availability, integrity and privacy come first.
2. Researcher code, data and results.
3. Controller: user database, node credentials, audit trail.
4. University network reputation (UDCS must not become a pivot point or a crypto-mining farm).

## Actors

| Actor | Capability |
|---|---|
| Student / researcher | Authenticated; may submit workloads (M2) |
| Student at a lab PC | Physical / local-user access to a node |
| Malicious workload author | Arbitrary code running on nodes (M2+) |
| Network attacker on campus Wi-Fi | Sniff and spoof traffic |
| Rogue machine | Tries to join as a node |
| Compromised node | Lies in telemetry, tries to reach the controller and other nodes |

## Threats and mitigations

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T1 | Credential sniffing on Wi-Fi | TLS required. Agent refuses `http://`; controller refuses plaintext non-loopback binds by default | [implemented] |
| T2 | Rogue machine enrolls | Admin-issued, single-use, expiring enrollment tokens; atomic consumption; audit log | [implemented] |
| T3 | Stolen node credential reused elsewhere | Hash-only storage on the controller; DPAPI machine-scope encryption on the node; instant revocation | [implemented] (file ACLs: M7 installer) |
| T4 | Brute-force login | Argon2id; rate limit per IP + username; uniform error message; dummy hash verification to equalize timing for unknown users | [implemented] (per-process limiter, see limits) |
| T5 | Privilege escalation (student → admin) | Permission checks on every route via a single `require(permission)` dependency; role changes only by admins; an admin can't demote themselves (prevents lockout) | [implemented] |
| T6 | Compromised node lies (fake GPUs, bogus telemetry) | Strict Pydantic bounds and size limits; `extra="forbid"`; controller clock for liveness. **A lying node can still attract jobs it can't run.** M3 should verify claims (benchmark probe on enroll) and track reputation | partial |
| T7 | Node impersonates a user (or vice versa) | Credential type prefixes; separate auth dependencies | [implemented] |
| T8 | Secrets in source or logs | No default credentials; bootstrap admin password via prompt or env var; tokens shown once; `Authorization` never logged; DB URL hidden from repr | [implemented] |
| T9 | Audit tampering | Append-only table, no update or delete API. **Not** tamper-proof against a DB admin; hash-chaining is [future] | partial |
| T10 | **Malicious workload escapes onto a lab PC** (reads the logged-in student's files, keylogging, lateral movement) | ADR 0001: each workload runs in its own AppContainer, from a privilege-free restricted token with no network capability, inside a Job Object with UI restrictions. Only its own workdir and approved inputs are granted. The self-test verifies the denials (profiles, credentials, other workloads, processes, network, registry). **Not a VM:** kernel or driver exploits cross it, and anything granted to ALL APPLICATION PACKAGES is readable. User code stays disabled until the ADR gate passes | **reduced**; tested as the interactive user; the service path is pending |
| T11 | Workload exhausts the PC and harms the student | Local protection (M4): Job Object limits, thresholds, preemption | open |
| T12 | Workload abuses the network (scanning, mining pools) | M2+: per-job network policy (Windows Firewall rules per job account, or a container network) | open |
| T13 | Unauthenticated admin surface exposed | All `/admin/*` require an authenticated admin; no anonymous endpoints except login, enroll, health, docs | [implemented] |
| T14 | Enrollment token leaks via shell history or process list | Agent reads the token from env var or a hidden prompt, never from argv | [implemented] |
| T15 | Controller is a single point of failure | Agents tolerate outages with back-off; running jobs (M2) must continue without the controller. HA controller is [future] | partial |

## Known M1 limitations (accepted for now)

- The rate limiter is in-memory, per process. With multiple controller workers or replicas, limits multiply. Move to PostgreSQL or Redis if scaled out.
- Client IP is the TCP peer. Behind a reverse proxy it is the proxy's IP until trusted-proxy handling is added.
- Sessions are not bound to a client and have no idle timeout (only an absolute TTL).
- No password reset flow, MFA or SSO. University SSO (SAML/OIDC) is likely the right long-term answer and should replace local passwords for students.

## Milestone 1.5 additions (background service, local protection, fleet enrollment)

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T16 | **Student pre-creates or plants junctions in `C:\ProgramData\UDCS`** (Users may create folders there), so the SYSTEM service writes through them: arbitrary file writes as SYSTEM, a stolen credential, or a swapped CA / config | The installer moves aside any folder not owned by SYSTEM, Administrators or TrustedInstaller, or containing a reparse point, then applies owner = Administrators, `/reset`, and a protected SYSTEM + Administrators ACL. The service verifies owner, DACL and the absence of reparse points at every start, and refuses to lend resources if the check fails (found by the adversarial review) | [implemented]; the installer path is verified only by the elevated acceptance script |
| T17 | Rogue server squats the helper pipe name, or impersonates its clients | No `FILE_CREATE_PIPE_INSTANCE` for interactive users (an explicit `0x100082` mask instead of generic write); `FILE_FLAG_FIRST_PIPE_INSTANCE`; a listening instance always exists; clients connect with identification-only SQOS; helpers talk only to a server in session 0; remote clients rejected | [implemented, tested as a normal user] |
| T18 | Helper reports forged by the student | Attributed to the client's real session (`GetNamedPipeClientSessionId`), so a student can't speak for another session. A forged "idle" affects only their own machine and is still bounded by measured pressure (AWAY requires low non-UDCS CPU). Missing or stale reports count as ACTIVE; a report from before an unlock is ignored | [implemented, tested] |
| T19 | Lab enrollment key leaks (it is shared by a whole deployment wave) | Expiry plus a use limit; revocable at any time; nodes it creates are **pending** unless the key is auto-approve; it never becomes a node identity, and the agent never writes it to disk | [implemented, tested] |
| T20 | Old node credential reused after rotation | Two-phase rotation: the new credential is promoted on first use and the old one stops working at that moment; revocation also kills a pending credential | [implemented, tested] |
| T21 | Controller tells the node to stop (maintenance / pending / revoked), but the PC reboots while offline | The no-work state is persisted and loaded before the governor starts; an enrolled node lends nothing until the controller confirms it is ACTIVE; an unreadable state file fails closed | [implemented, tested] |
| T22 | The GPU diagnostic (E1) runs code in the student's session | It is admin-requested only (a file in the admin-only data dir); its child processes run in a kill-on-close job at IDLE priority, are killed at the timeout, and run off the main thread. The `as_user` variant exists **only** to answer E1: running workloads as the student is never acceptable | [implemented]; not run as SYSTEM yet |
| T23 | Python service hijacked through the environment or user-writable paths | A private interpreter under Program Files (admin-only); `-I` isolated mode, so no `PYTHON*` environment variables or user site; workload children get an explicit `sys.path` in a `-c` bootstrap, not `PYTHONPATH` | [implemented]; packaging verified by the acceptance script |

## Milestone 2 (catalog execution) additions

| # | Threat | Mitigation | Status |
|---|---|---|---|
| T24 | A job submission smuggles code or commands onto lab PCs | A job is a catalog `kind` plus bounded integers; there is no field for code, command lines, paths or environment. The agent builds the argv itself from a validated `WorkloadSpec` | [implemented, tested] |
| T25 | A stale or partitioned node overwrites a reassigned job's result | Fencing: a report counts only if its `(node, attempt)` matches the current assignment; otherwise the node is told to cancel | [implemented, tested] |
| T26 | A node fakes a result | The checksum detects bugs (lost or repeated units), **not** a dishonest node, which can compute it without working. Requires result attestation and node reputation (with T6) | **open** |
| T27 | Students learn which lab PC runs whose job | `node_id` is shown only to `manage_jobs`; jobs of other users are 404, not 403 | [implemented, tested] |
| T29 | A stale, partitioned or corrupt node poisons a job's checkpoint, or another node is fed a bad one | Uploads are accepted only from the current attempt's node, after SHA-256 and catalog-consistency checks and with monotonic progress; downloads are verified the same way before use; an unusable checkpoint means starting from zero. A *dishonest* node can still forge a consistent catalog checkpoint (as with T26) | [implemented, tested]; forgery by a dishonest node is open |
| T28 | A user floods the queue | Per-user unfinished-job limit (`max_active_jobs_per_user`, 429); priority above 0 is admin-only | [implemented, tested]; no per-lab or time quota yet |
