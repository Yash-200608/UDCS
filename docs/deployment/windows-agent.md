# Deploying the UDCS Node Agent on Windows lab PCs

Audience: university IT. Students never interact with the agent.

## What gets installed

| Item | Location | Notes |
|---|---|---|
| Service `UDCSAgent` ("UDCS Node Agent") | — | LocalSystem, **Automatic (Delayed Start)**, restart on failure 5 s / 15 s / 60 s, failure counter reset after 1 day, failure flag on |
| Program files | `C:\Program Files\UDCS\Agent` | private CPython runtime + agent; admin-writable only |
| Data directory | `C:\ProgramData\UDCS\agent` | ACL: SYSTEM + Administrators only. Holds the node credential (DPAPI machine-scope), cached policy, workload state and checkpoints, logs (`logs\agent.log`, 5 MiB × 4), status (`status\governor.json`) |
| Session helper | `HKLM\...\Run\UDCSSessionHelper` | `pythonw.exe` (no window) started at each logon; reports only idle time and full-screen/presentation state, over a local named pipe |

The agent opens **no listening network ports**. It only connects out to the controller over HTTPS.

## Before deploying

1. **Controller:** reachable over HTTPS from the lab subnet, with a certificate from a CA the PCs trust. For a private CA, distribute `campus-ca.pem` with the package.
2. **Lab enrollment key:** an admin creates one per lab and deployment wave:

   ```powershell
   udcs-controller create-enrollment-key --created-by itadmin --lab "CS Lab B" --max-uses 60 --ttl-minutes 2880
   ```

   - The key can enroll **at most `--max-uses` machines** before it expires. It is **not** an identity: each machine gets its own credential, and the key is never stored on the PC.
   - New nodes are **pending** until approved (`POST /admin/nodes/{id}/approve`), unless the key was created with `--auto-approve`.
   - **Revoke** the key once the wave is done (`POST /admin/enrollment-keys/{id}/revoke`). That stops new enrollments; already-enrolled nodes are unaffected.
3. **Reboot-to-restore products (e.g. Deep Freeze):** put `C:\ProgramData\UDCS` in a ThawSpace or an exclusion, or every reboot will discard the node's identity and checkpoints. Align any "restart when idle" task with UDCS policy, because idle time is exactly when UDCS runs.
4. **Power policy:** the agent never keeps a PC awake. If you want overnight compute, configure that in your normal power or GPO policy.

## Build and install

On a build machine with the repository and `uv`:

```powershell
uv run python tools/package_agent.py C:\build\udcs-agent
```

On each lab PC (elevated; for example from Intune, ConfigMgr or a GPO startup script):

```powershell
$env:UDCS_ENROLLMENT_TOKEN = "<lab key>"
.\install-agent.ps1 -Staging \\deploy\udcs-agent -ControllerUrl https://udcs.campus.edu:8443 -CaBundle \\deploy\campus-ca.pem
```

`install-agent.ps1` is idempotent. Running it again upgrades in place, keeping the node identity, policy and checkpoints.

## Verify a machine

```powershell
Get-Service UDCSAgent
```

```powershell
& "C:\Program Files\UDCS\Agent\python\python.exe" -I "C:\Program Files\UDCS\Agent\run_agent.py" status
```

`status` prints the current protection level, the reasons for it, the coarse presence state, total / UDCS / non-UDCS usage, and per-workload state.

## Operate

| Task | How |
|---|---|
| Take a PC out of the pool temporarily | Admin API: `POST /admin/nodes/{id}/state {"admin_state":"maintenance"}`; or locally create `C:\ProgramData\UDCS\agent\maintenance.flag` |
| Remove a PC permanently | `POST /admin/nodes/{id}/revoke`; then `uninstall-agent.ps1 -RemoveData` |
| Re-image a PC | Revoke the old node, then reinstall with a lab key; it becomes a new node |
| Logs | `C:\ProgramData\UDCS\agent\logs\agent.log` (JSON lines, correlation ids); Windows Event Log (Application) for service start and stop |
| GPU execution-context diagnostic (E1) | create `C:\ProgramData\UDCS\agent\diagnostics\gpu-request`; the result appears in `gpu-result.json` within about 2 minutes |
| Uninstall | `uninstall-agent.ps1` (keeps identity) or `-RemoveData` (removes it) |

## Security notes for IT

- The service runs as **LocalSystem**, which it will need in Milestone 2 to launch workloads under a low-privilege account. To limit the risk, it executes only from admin-only paths, starts Python in isolated mode (`-I`: no environment-variable or user-site injection), opens no ports, and validates every controller message.
- Allowing `python.exe` in AppLocker or WDAC implicitly allows any `.py` file. Workload security therefore comes from the workload account's token and Job Object limits, not from application control.
- The session helper's pipe accepts only `FILE_WRITE_DATA` from interactive users. It cannot be used to create a rogue server instance, and the helper refuses to talk to any server that isn't in session 0.
