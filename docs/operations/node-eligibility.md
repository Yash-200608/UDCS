# Operator procedure: user-code eligibility for a node

**Status (2026-11-27):** the procedure is implemented and tested against the controller and the `udcs admin` client. It has **not** yet been carried out on a real lab image or with the installed service. User-code execution stays disabled everywhere until it has, together with the other acceptance gates in DEVELOPMENT_STATUS.md.

A node runs researchers' packages only if **all** of these hold at the moment of scheduling, and again at every later step:

| # | Condition | Set by | Enforced in |
|---|---|---|---|
| 1 | The controller flag `UDCS_USER_CODE_ENABLED=true` | deployment configuration | dispatch, every node package endpoint, every sync |
| 2 | The agent was built with `USER_CODE_ENABLED = True` | the agent release | the agent's offer and refusal |
| 3 | The agent runs as **LocalSystem** (the installed service) | installation | the agent's offer. An interactive agent's sandbox can stop the student's per-user services and open the student's desktop (measured) |
| 4 | The node reports a **verified** AppContainer | the node itself (self-reported) | scheduler, sync, node endpoints |
| 5 | An administrator granted eligibility, bound to the node's **current OS image** | this procedure | scheduler, sync, node endpoints |

## Who may do this

- Only accounts with `manage_nodes` (the `admin` role) can record audits, grant and revoke. Researchers and students get 403. This is tested.
- Every action is in the audit log (`/admin/audit-events`) with the acting user and a reason:
  - `node.exposure_audit_recorded`;
  - `node.user_code_changed`;
  - `node.user_code_refused`, recording a refused grant and why;
  - `node.user_code_suspended`, an automatic suspension recorded with actor `system`.

## Approve

1. **Image.** Install the lab image on the node, and enroll and approve the node as usual. It must be ACTIVE.
2. **Audit, in the service context**, on that node, from an elevated PowerShell in a checkout of this repository:

   ```
   tools\acceptance\m3_exposure_audit.ps1 -AsSystem
   ```

   The script:
   - runs the probe as LocalSystem through a temporary scheduled task, which it deletes afterwards;
   - does not touch the installed UDCSAgent service;
   - writes the full report outside the repository, at `%ProgramData%\UDCS\exposure-audit\exposure-report.json`;
   - writes a summary without host or user names to `docs\acceptance\data\m3-exposure-audit-system.json`.
3. **Review** the report:
   - `violations` must be empty. These cover: write access outside the sandbox's own grants; sensitive data readable (user profiles, the UDCS data directory, `SAM\SAM`, `SECURITY`, other users' hives, an autologon password); other processes controllable; any network reachable; services stoppable or reconfigurable; the interactive window station or clipboard reachable; UDCS IPC reachable; an incomplete audit.
   - Also read the **reachable items** (`review_items`): listable directories, readable registry keys, connectable pipes, openable named objects, startable services. They are not automatic failures, but a lab image can expose something specific (a vendor pipe or service, campus software). Decide whether each is acceptable for this image, and record the decision outside UDCS.
4. **Record** the audit for the node:

   ```
   udcs admin audit-upload <node-id> %ProgramData%\UDCS\exposure-audit\exposure-report.json
   ```

   The controller judges the report again with the same rules; it never uses the uploader's verdict. It refuses:
   - a report from another host;
   - a report dated in the future;
   - a report for a node with no inventory.
5. **Grant**:

   ```
   udcs admin user-code allow <node-id> --reason "<ticket or review reference>"
   ```

   The controller refuses (409, with the reason, and audited) unless:
   - the node is ACTIVE;
   - it reports a verified AppContainer;
   - the latest audit **passed**, was **run as SYSTEM**, is of the node's **current image**, and is at most `UDCS_EXPOSURE_AUDIT_MAX_AGE_DAYS` old (default 90).

   The grant is bound to that image and audit.

**Known image finding:** an autologon password stored in `Winlogon\DefaultPassword` is readable from a UDCS AppContainer (found on GitHub's windows-latest image). Store autologon credentials as an LSA secret instead (for example Sysinternals Autologon), then re-audit.

## Audit periodically

- `udcs admin nodes` shows each node's eligibility. A grant that no longer applies shows `blocked:` with the reason.
- `udcs admin audits <node-id>` lists a node's audit history: image, context, verdict and the report's SHA-256.
- Re-audit after any change to the image: a feature update, campus software, a driver.

**Automatic suspension.** A new Windows build in the inventory suspends eligibility automatically (audited as `node.user_code_suspended`).

**Limit:** the image key is the OS release and build (for example `11|10.0.22000`). Installed software and monthly patches do not change it. Re-auditing after those changes is the operator's responsibility.

## Revoke

```
udcs admin user-code revoke <node-id> --reason "<why>"
```

- **Always accepted**, in any node state.
- **Effect:**
  - the node receives no new package jobs;
  - its package endpoints refuse at once (no further downloads, uploads or output reports);
  - at its next sync, any package job running there is **requeued for another eligible node**, and the node is told to cancel it. The agent kills the run's whole process tree and deletes its staging.
- **Other causes with the same effect:**
  - turning the controller flag off;
  - the node losing its verified AppContainer;
  - its image changing.

## Failure handling

| Situation | What happens | Operator action |
|---|---|---|
| Grant refused (409) | Nothing changes. The refusal and its reason are audited | Fix the cause (audit, image, node state) and repeat |
| Audit has violations | Recorded as failed; no grant is possible | Fix the image (ACLs, services, software), re-audit |
| The node is offline when you revoke | Its jobs are requeued when their lease expires. If it comes back, it is told to cancel; nothing it uploads is accepted | None |
| The node is reimaged | Eligibility is suspended automatically | Re-audit and grant again |
| The controller flag is switched off during runs | Package jobs are requeued at each node's next sync | Switch it on again when ready; jobs resume elsewhere |
| A node lies about its AppContainer support | The admin grant (5) and the SYSTEM-context audit are still required; node attestation is not built (T49) | Grant only to nodes you audited yourself |
| `-AsSystem` audit cannot read the repository | OneDrive online-only files: `m3_preflight.ps1` reports them | Keep the folder on this device, or use a local checkout |
