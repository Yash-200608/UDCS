# ADR 0004: Workload token identity (restricted SYSTEM token, service-SID grants)

- **Status:** **proposed, not implemented.** The design was measured in a diagnostic experiment on one PC (Windows 11, build 26300, temporary LocalSystem service), 2026-11-28. Nothing in the agent uses it yet, and user code stays disabled (ADR 0003's three switches are unchanged).
- **Resolves:** decision D-5 in `DEVELOPMENT_STATUS.md`.
- **Builds on:** [ADR 0001](0001-workload-isolation.md) (AppContainer with LPAC + `registryRead`) and [ADR 0003](0003-package-execution.md) (package execution, offered only by a LocalSystem agent).
- **Evidence:** `tools/experiments/restricted_token_experiment.{py,ps1}`. Its result files are diagnostic only (`evidence: false`), are kept outside the repository, and are summarised under D-5 in `DEVELOPMENT_STATUS.md`.

## Context

An AppContainer access check has two halves, and both must pass:

1. **The normal half** checks the token's user and groups against the object's DACL.
2. **The AppContainer half** checks the package SID and its capabilities.

Windows grants `KEY_READ` to ALL APPLICATION PACKAGES and to the `registryRead` capability on every user's `HKCU\Software`, `HKCU\Environment` and `_Classes` hive. The grant is inherited down to keys such as `Explorer\RecentDocs`. Workloads need `registryRead`: under LPAC without it, Python dies with `0xC0000022` (measured; ADR 0001).

The sandbox token comes from the agent, LocalSystem. Today's workload token keeps SYSTEM enabled and disables only Administrators. SYSTEM is in every user hive's DACL, so the normal half passes, and the `registryRead` grant passes the AppContainer half.

**Measured result, production path (V0):** the sandbox reads the signed-in student's hive, with **1,015** findings, and all six explicit student targets are readable, including `RecentDocs`, `Environment` values and `_Classes`. User code cannot be enabled while this holds.

## Options evaluated

| Option | Mechanism | Assessment |
|---|---|---|
| **A. Dedicated low-privilege account** | Workloads run as a separate local account. The agent needs its credentials or an S4U logon. | It works with only the normal half, but it adds an account to create, rotate and police per node. Lab images and Deep Freeze may reset or forbid it, and it needs a password or LSA logon right on every node. **This is the fallback if B fails on a second machine or on lab images.** |
| **B. Restricted SYSTEM token, service-SID grants** (chosen) | `CreateRestrictedToken` marks SYSTEM and every group except an allowlist deny-only. Agent-made grants name the agent's service SID (`NT SERVICE\UDCSAgent`) instead of SYSTEM. | Documented APIs only, no account, no credentials, no policy change. Measured working (below). Its safety rests on two invariants, given under "Invariants". |
| C. Change the hive ACLs | Remove the ALL APPLICATION PACKAGES / `registryRead` ACEs from user hives. | **Rejected:** a system-wide ACL change to Windows-owned objects, undone by profile creation and updates, and off-limits for UDCS. |
| D. Drop `registryRead` | Run LPAC without it. | **Rejected:** Python does not start (`0xC0000022`, measured). |
| E. Disable every group (V2) | Leave no group enabled. | **Rejected:** the child cannot load `ntdll` (`0xC0000022`, measured). `System32` grants only TrustedInstaller, SYSTEM, Administrators and Users. |

## Decision (proposed)

For package workloads launched by the **LocalSystem service**, the workload token is built as measured in variant **V5**:

1. **Restricted token.** `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE, SidsToDisable = …)` marks these deny-only:
   - the user SID (SYSTEM);
   - **every group except an allowlist** of `BUILTIN\Users` (S-1-5-32-545), Everyone (S-1-1-0) and the agent's service SID.

   The integrity label is not a group the call can disable, and is not touched. The list is built by enumerating the token's groups (`GetTokenInformation(TokenGroups)`), so a group not seen on the measured build, such as a domain group on a joined lab image, becomes deny-only by default, not enabled by default.
2. **Grant SID.** The agent's own service SID: `LookupAccountNameW("NT SERVICE\UDCSAgent")`, which must be present **and enabled** in the agent's token. Every grant the agent makes for a workload names it instead of `current_user_sid()`:
   - the runtime and Python home;
   - the work directory and outputs;
   - read-only inputs;
   - the package root.

   The package SID or capability grants stay as they are.
3. **Default DACL.** SYSTEM, the package SID and the grant SID. Without the grant SID the child cannot open its own process and thread objects and fails with `0xC0000142` (measured). The token owner stays the SYSTEM SID, as measured; see open item 2.
4. **Window station and desktop.** The private workload window station and its desktop also grant the grant SID.
5. **Unchanged:** LPAC, `registryRead` and the runtime capability, low integrity, the job object, UI restrictions, the environment allowlist, and `-I -S -B`.

The installer already sets `sc sidtype UDCSAgent unrestricted` (`infrastructure/windows/install-agent.ps1:108`, added before the Pass 1 install on 2026-11-22). The service SID should therefore already be in the installed service's token, and **no service configuration change is expected** (an assumption, verified read-only before implementation; see Rollout).

### Scope

- **Applies only when the agent is LocalSystem**, the only context in which user code is offered (`jobs.running_as_local_system`, ADR 0003).
- Interactive and developer runs keep today's token. They never receive package jobs, and their grant SID would not be agent-unique: the logon SID is shared by the whole logon session. Catalog workloads (synthetic CPU/GPU) also move to the new token under the service, so that there is one launch path, not two.

### Fail-closed rules

The agent refuses to launch a workload, raising `IsolationUnavailable`, and its inventory reports `appcontainer` as **unavailable**, which stops package scheduling (ADR 0003 condition 3), if any of these fail:

- the service SID cannot be resolved, or is absent or not enabled in the agent's token (for example `sidtype` was reset to `none`);
- `BUILTIN\Users` or Everyone is absent from the agent's token, which would make the measured design impossible;
- the restricted child's token, read back with `OpenProcessToken` + `GetTokenInformation` before the process is resumed, does not have exactly the allowlist enabled, or does not have SYSTEM and Administrators deny-only.

## Invariants (security-relevant)

1. **The service SID is never granted on agent-private data.** The child keeps the service SID enabled. Any object granted to `NT SERVICE\UDCSAgent` passes the normal half for the workload, and then only the AppContainer half protects it. Agent-private data must therefore be granted to SYSTEM and Administrators only, as the installer does today: credentials, the state database, configuration, logs, staging and the package cache. A test must enforce this. The existing self-test check `read:agent_credential` covers credentials at runtime; a static check over the installer and data-dir ACL code is still to be written.
2. **Grant only what the workload needs.** Because Users and Everyone stay enabled, anything Users or Everyone can read passes the normal half, the same exposure option A would have. For those objects, only LPAC and the two capabilities protect them, and the exposure audit is what measures that. This is the residual risk of the decision, and gate 2 of ADR 0001 (the lab-image audit) must re-run under the new token.

## Evidence ([measured], diagnostic, dev PC, build 26300, founder-run temporary LocalSystem service with `sidtype unrestricted`)

| Variant | Enabled groups (besides the service SID) | Student-hive findings / violations | Self-test (21 checks), kill tree, CUDA |
|---|---|---|---|
| V0 production (control) | all | 1,015 / 1,015 | pass |
| V1 | all except SYSTEM and Administrators | 0 / 0 | pass |
| V3 | Users | child dies `0xC0000022` | — |
| V4 | Users, Everyone, Authenticated Users | 0 / 0 | pass |
| **V5 (chosen)** | **Users, Everyone** | **0 / 0** (measured twice) | **pass** (devices=1) |
| V6 | Users, Authenticated Users | child dies `0xC0000022` | — |

- **Child token (V5):** low integrity, only `SeChangeNotifyPrivilege`, AppContainer with 2 capabilities. SYSTEM, Administrators, `SERVICE`, `CONSOLE LOGON`, Authenticated Users, This Organization, `LOCAL` and the logon SID are deny-only.
- **Denied in every variant:** profile folders, `Credentials`, `Protect` and `System32\config`.
- **Harness integrity:** after the `-B` fix (commit 87f1245), the second V5 run left the protected snapshot unchanged (per-file, 1,693 files), and the temporary service and folder were removed.

## Open items (must be closed before implementation is declared done)

1. **Only one machine is measured** (build 26300, Home edition). The build 22000 machine this item first named was retired on 2026-11-28 and cannot be measured. A second machine, ideally a real lab image (Pro/Education/Enterprise, domain join, Deep Freeze), must confirm the SYSTEM token groups and that Users + Everyone suffice for the loader. This decides between B and A, and belongs with ADR 0001 gate 2.
2. **Owner rights are untested.** The child's token owner is SYSTEM, which is deny-only, so the files the child creates are owned by a SID the child cannot use. This has to be measured: whether the child can still read and write its own outputs in every case (it could in the self-test), and whether the agent can always read and delete them afterwards. The alternative, the service SID as owner, gives the child `WRITE_DAC` on its own files. That is not obviously worse, but it is unmeasured.
3. **Why Everyone is required is unexplained.** Startup fails without it (V3, V6), and the object that needs it has not been identified. A loader trace (Process Monitor on the failing variant) should name it, so that the dependency is understood rather than empirical.
4. **Lab images:** Deep Freeze, domain join, Office and campus software. The allowlist makes extra groups deny-only by design, but this is unmeasured.
5. **The service host itself runs without `-B`** (`python.exe -I run_service.py`). It is not part of this decision; noted because it is an installer/binPath change.

## Consequences

- **Implementation sketch.** One token builder in `winplat/appcontainer.py` (allowlist in, `SidsToDisable` out), a `workload_grant_sid()` that resolves and validates the service SID, and `workloads/isolation.py` switched from `current_user_sid()` to the grant SID for workload grants. `current_user_sid()` keeps its meaning, because `jobs.running_as_local_system` depends on it. Expected size: small, about 100–200 lines plus tests.
- **Testing.** Unit tests cover the allowlist builder and the fail-closed rules. CI runs as an elevated administrator, not as a service, so CI cannot exercise B end to end. The end-to-end measurement stays a founder-run temporary-service run, plus the installed-service acceptance on the original machine. Proposed: a CI job that hosts the self-test in a temporary service, as the experiment does, if the runner allows it.
- **Acceptance.** This changes the sandbox token that `m2_isolation_service_acceptance.ps1` gate 1 passed on 2026-11-22. That evidence stays as recorded, and the new token needs its own installed-service run. It does not alter Pass 1 or Pass 2 of M1.5.
- **If B fails on a second machine or on a lab image,** fall back to option A rather than weakening the token (for example, by re-enabling SYSTEM).

## Rollout and verification (proposed order)

1. **On the designated acceptance machine (decision D-6), after UDCSAgent is installed:** a read-only `sc qsidtype UDCSAgent`, expected to report `UNRESTRICTED`.
2. **Re-measure V0/V5 on a second machine, ideally a lab image,** with the portable bundle (`tools/experiments/make_d5_bundle.ps1`, `RUNBOOK-other-machine.md`) and the experiment's temporary service. Any installed UDCSAgent is not touched. This needs the machine owner's approval. Until it is done, B rests on one machine.
3. **Implement** behind the existing switches, with tests, if step 2 passes.
4. Run the exposure audit and isolation self-test from the **installed** service, on both machines.
5. Run gate 2 (the lab-image audit) under the new token.
