# ADR 0001: Workload isolation backend (decision D-3)

- **Status:** accepted for implementation, 2026-11-22. **User code stays disabled** until the elevated service acceptance passes (see "Gate").
- **Scope:** how a UDCS workload process is contained on a Windows lab PC.

## Context

Lab PCs differ in Windows build, edition and virtualisation support. Workloads must never inherit the service's privileges or credentials. File and network access must be denied by default. The governor and Job Objects must keep control, and cancellation must kill the whole process tree.

## Options evaluated

Labels: **[doc]** = primary documentation, **[measured]** = on the dev PC (i5-6500, Windows 11 Pro Education build 22000).

| Option | Findings | Verdict now |
|---|---|---|
| **MXC v1.1.0** (`microsoft/mxc`, MIT, `wxc-exec.exe`, JSON config) | **[doc]** ProcessContainer needs Windows 11 **24H2 (26100.x)+**; Session Isolation also needs 24H2+. v1.1.0 removed the legacy fallbacks ("require native PSEC support"). MicroVM is experimental (Windows Hypervisor Platform + NVX); the WSL container needs WSL ≥ 3.0.5. Network is deny-by-default with CIDR allowlists, and the filesystem uses `readonlyPaths`/`readwritePaths`/`deniedPaths`. The docs read do not cover service or Session-0 operation, Job Objects, resource limits or CUDA for ProcessContainer. **[measured]** Not runnable here (build 22000) | **Detected per node, not integrated.** Revisit on a 24H2 machine: it can drive `wxc-exec` with our Job Object policy only once that is tested |
| **Native AppContainer** (Win32 lowbox, from the agent) | **[measured]** Works on build 22000; Python starts in ≈0.12 s; CUDA `cuInit` succeeds inside. It composes directly with our Job Objects (assignment while suspended, caps, kill-on-close). Every probe check passed: see below | **Chosen backend** |
| LPAC (AppContainer with the ALL_APPLICATION_PACKAGES opt-out) | **[measured]** `cmd.exe` runs; Python dies at start (0xC0000022) | Future hardening: needs the capabilities Python requires |
| Windows Sandbox | **[measured]** feature not installed here; a full VM per job, with no per-job file or GPU policy integration in the agent | Not used |
| Hyper-V | **[measured]** host compute service present; would need image management and GPU partitioning | Later phase, if ever |
| WSL container | MXC-mediated only, with WSL ≥ 3.0.5; WSL 2 is present here | Not used now |

## Decision

1. **Execution levels:** `host` (Job Object only) for the four built-in catalog workloads, and `appcontainer` (required isolation).
2. **AppContainer construction:**
   - each workload gets its own AppContainer profile, so its own package SID;
   - it runs from a restricted token (no privileges, Administrators deny-only), with no network capability;
   - grants are modify on its own workdir and read/execute on approved inputs;
   - the runtime (interpreter and catalog files) is read/execute through a shared `udcsWorkloadRuntime` capability SID;
   - the process is created suspended inside the existing Job Object, with UI restrictions;
   - the profile is deleted on purge.
3. **Per-node choice:** every node detects its own capabilities at start-up and reports them in its inventory (`isolation`). Catalog jobs use `appcontainer` where a real test launch succeeded, and `host` otherwise.
4. **No fallback:** a workload that requires `appcontainer` never runs any other way. A missing backend means `FAILED (isolation_unavailable)`, and a launch error counts as a failure, with no host retry.
5. **MXC:** detected and reported, never claimed as available. It is a candidate second backend for 24H2+ nodes.

## Evidence ([measured], `udcs_agent.diagnostics.isolation.run_selftest`)

**Allowed:**
- read the approved input;
- read the runtime;
- write its own output.

**Denied:**
- writing the input or the runtime;
- reading a secret outside the grant;
- reading or writing another workload's files;
- reading the agent credential file;
- listing every user profile;
- an HKCU secret;
- loopback and external TCP, and DNS;
- `OpenProcess` (terminate or VM read) on the agent, a helper process and lsass.

**Control run:** for each prohibited check, the same probe running unsandboxed *could* do it (except lsass as a non-admin), so the checks are meaningful.

**Token and environment:**
- the token is an AppContainer at low integrity, holding only `SeChangeNotifyPrivilege`;
- the environment holds only the five variables set.

**Cancellation:** terminating the job killed the probe and its child.

## Privileged-parent findings (from CI; the service itself has not run this yet)

The GitHub Windows runner (an elevated administrator, build 26100) killed every AppContainer child at start with `0xC0000142` (DLL init failed). A fast diagnostic (`tools/experiments/appcontainer_ci_probe.py`) isolated the cause.

**Not the cause:** the desktop. With the caller's own token the same launch worked.

**The cause:** the restricted token. With Administrators deny-only, an elevated admin token still names Administrators as its owner and in its default DACL, so the child cannot open its own process objects. LocalSystem tokens are built the same way, so the installed service would very likely have failed identically.

**Fix:**
- set the restricted token's owner to the user SID;
- set its default DACL to the user, SYSTEM and the workload's package SID.

**Workload desktop:** workloads also start on a dedicated desktop, never the student's.
- *As an admin or SYSTEM:* a private window station `UDCSWorkloads\Workloads`, granted only to the runtime capability.
- *Otherwise:* a private desktop, adding a minimal grant on the current window station only if it is not the interactive `WinSta0`.

**Verified after the fix, on the runner:** `cmd` and Python start inside the AppContainer.

## Consequences and limits

- **One-time grant cost:** read/execute is granted on the interpreter directory once per node (41.6 s measured on first propagation).
- **Standard, not LPAC:** this mode is not LPAC, so anything Windows grants to ALL APPLICATION PACKAGES is readable, for example `C:\Windows` and parts of HKLM. Student profiles, `ProgramData\UDCS` and other workloads are not.
- **Kernel attack surface:** AppContainer is not a VM. A kernel or driver exploit (including in the GPU driver) crosses it, so threat T10 is reduced, not closed.
- **Network:** jobs that need networking need an explicit, reviewed capability design. Not done yet.

## Gate before enabling user code

1. `tools/acceptance/m2_isolation_service_acceptance.ps1` passes. It runs this self-test **from the installed service** (LocalSystem, session 0), where the parent really has SYSTEM privileges.
2. A review of what ALL APPLICATION PACKAGES exposes on a lab image (Deep Freeze, Office, campus software).
3. A user-code packaging design: inputs, outputs, dependencies and size limits.
