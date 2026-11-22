# Node Agent ↔ Controller Protocol

## Principles

1. **The agent always dials out.** The controller never opens connections to lab PCs. This works across subnets, NAT, Wi-Fi, dynamic IPs and default-deny inbound firewalls, with no firewall changes on lab machines.
2. **The controller owns truth.** The agent reports observations, and the controller decides state. Agent-supplied values (hostname, telemetry, timestamps) are validated and treated as untrusted. Liveness uses the controller's clock.
3. **Every message is safe to retry.** Heartbeat and inventory upload are idempotent overwrites. Enrollment is the one non-idempotent step, and a single-use token protects it.
4. **Versioned.** Every agent message carries `protocol_version` (currently `1`). The controller rejects versions it doesn't support with a clear error, so a mixed-version fleet can't fail silently.

## Lifecycle

```
            admin issues enrollment token (single use, expiring)
                                │
 agent: discover hardware ──► POST /agent/enroll ──► node_credential (stored, DPAPI-encrypted)
                                │
          ┌─────────────────────┴────────────────────────┐
          │ PUT /agent/inventory   (on start + on change)│
          │ POST /agent/heartbeat  (every N seconds)     │◄── controller may change N,
          │   ← inventory_required → re-send inventory   │    request inventory, or
          │   ← admin_state                              │    revoke (401/403 → agent stops)
          └──────────────────────────────────────────────┘
```

- **Heartbeat interval.** The controller sets it (default 15 s) and returns it in every heartbeat response. The agent clamps it to 5–300 s, so IT can tune fleet-wide load centrally.
- **Offline detection.** A node is `offline` once no heartbeat has arrived for `interval × 3` (configurable). This is derived on read, with no sweeper process.
- **Inventory changes.** The agent re-runs discovery every 10 minutes. It always sends the fingerprint of its current inventory, and if that differs from what the controller holds, the controller answers `inventory_required: true`. A GPU swapped between reboots is therefore picked up automatically.
- **Network failure.** Exponential back-off with full jitter (base = heartbeat interval, cap 300 s), so a fleet of agents doesn't stampede a controller that has just restarted.
- **Revocation.** 401/403 on a node endpoint makes the agent stop with exit code 3 rather than retrying forever. An admin re-enrolls the machine deliberately.

## Transport security

- HTTPS is required. The agent verifies the controller certificate against the system trust store or an explicit `ca_bundle` (recommended for a university-internal CA). `http://` URLs are refused unless `allow_insecure_http = true`, which is meant for local development only.
- The credential is a bearer secret sent only over TLS. It is never logged, and it is stored encrypted with DPAPI (machine scope) on Windows.
- **[future]** mTLS node certificates, issued during enrollment, would remove bearer secrets entirely.

## Telemetry content (per heartbeat)

CPU %, RAM available/total, free disk on the agent's data volume, uptime, and per-GPU utilization, memory, temperature and power. Each GPU field is `null` where NVML reports *Not Supported*, as on the GT 730 dev machine. `user_idle_seconds` is the time since the last keyboard or mouse input in the interactive session. It is reported only when the agent runs inside a user session; in a Windows service (session 0) it is `null`, because the value would be meaningless there. Getting real interactive-activity detection into a service needs a small per-session helper. That is **[future, M4]**.

## Correlation

Every agent request carries `X-Request-ID: agent-<uuid>`, which is logged on both sides. In M2 this extends to job and assignment IDs so a job can be traced from submission to completion.
