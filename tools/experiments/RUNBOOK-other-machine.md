# Runbook: ADR 0004 / D-5 re-measurement on another machine (a second PC or a lab image)

This was first written for the build 22000 acceptance machine, which was retired on 2026-11-28. It applies to any other Windows machine.

If UDCSAgent is not installed there, skip the `UDCSAgent` checks in step 1: the experiment does not need the agent.

**Diagnostic only.** The results are never acceptance evidence and must not go into `docs/acceptance/data`.

**What this does not touch:**
- the installed `UDCSAgent` service: its configuration, state, data or files;
- Pass 1 or Pass 2 evidence;
- system-wide ACLs.

**What it does:** step 2 creates one temporary service, `UDCSTokenExperiment`, which deletes itself, and one protected folder under `%ProgramData%`, which is removed. Both are made by the bundle's script while you watch. The experiment also uses its own window station name (`UDCSExperiment<pid>`), so it never opens the agent's `UDCSWorkloads` window station.

**Privacy:** the experiment checks whether the sandbox can read the **signed-in user's** registry hive. The V0 control *will* list key names from that hive (for example, which apps are registered under `_Classes`). Run it while signed in with **your own** account, never a student's. Keep the result file out of the repository; only aggregate counts get recorded.

## 0. Transfer

Copy `udcs-d5-bundle.zip` to the machine. Before extracting, compare its hash with the one printed when the bundle was built:

```powershell
Get-FileHash -Algorithm SHA256 .\udcs-d5-bundle.zip
```

Extract it into a folder in your own profile, for example `C:\Users\<you>\udcs-d5`. Another user must not be able to write there before the run, because the script snapshots the folder into a protected location before anything runs as SYSTEM.

## 1. Read-only checks (no changes; unelevated is fine)

```powershell
sc.exe qsidtype UDCSAgent
```
Expected: `SERVICE_SID_TYPE: UNRESTRICTED`. ADR 0004 assumes this. If it says `NONE`, stop: Option B would need a service configuration change, which is a separate decision.

```powershell
sc.exe qc UDCSAgent
```
```powershell
(Get-CimInstance Win32_OperatingSystem).BuildNumber
```
```powershell
Get-Service UDCSAgent
```

Paste all four outputs. Nothing is changed.

## 2. The experiment (elevated PowerShell, run by you)

```powershell
cd C:\Users\<you>\udcs-d5
```
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\experiments\restricted_token_experiment.ps1 -AsService -Staging C:\Users\<you>\udcs-d5\stage -Variants 'V0_production,V1_optionB,V5_users_everyone_grant_sid'
```

- **Expected:** about 10–15 minutes, then `Snapshot unchanged (per-file).`, `Service UDCSTokenExperiment removed.`, and the path of a `DIAGNOSTIC ONLY` result file.
- **The variants:**
  - V0 is today's token, the control; on build 26300 it reads the student hive;
  - V1 is Option B with broad groups;
  - V5 is the token ADR 0004 proposes.
- **If the script stops with an error, nothing is left half-done:** the service and folder are removed in `finally` blocks. Check with step 3 anyway.

## 3. Cleanup checks (both should print nothing)

```powershell
Get-Service UDCSTokenExperiment -ErrorAction SilentlyContinue
```
```powershell
Get-ChildItem $env:ProgramData -Directory -Filter 'UDCS-*'
```

## 4. Bring back

Bring back the console output and the result file, `%LOCALAPPDATA%\UDCS\diagnostics\restricted-token-experiment-service-*.json`, through a private channel, not the repository. Then delete the extracted folder and the zip.

## What decides the outcome (ADR 0004, open item 1)

- **B holds on that machine** if V5 shows 0 student-hive findings and 0 violations, the self-test passes 21/21, the kill tree passes, and the child token has only Users, Everyone and the service SID enabled.
- **CUDA:** on an old GPU (for example Kepler), a CUDA failure in *both* the sandbox and the host is a driver matter, not a token matter. Compare it with V0.
- **B fails** if V5 does not start (for example `0xC0000022`) while V0 does, or if V5 shows any student finding. In that case ADR 0004 falls back to option A, the dedicated account.
