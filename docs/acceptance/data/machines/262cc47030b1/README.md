# Acceptance machine `262cc47030b1`

Designated as the M1.5 acceptance machine on 2026-11-28 (decision D-6), after the original build 22000 machine was retired. The label is the first 12 hex characters of SHA-256 of the lower-cased host name; the host name itself is not recorded.

| Fact | Value (read 2026-11-28) |
|---|---|
| Edition | Windows 11 Home Single Language (`CoreSingleLanguage`), 26H2 |
| Build | 10.0.26300 (UBR 26300.10075) |
| CPU | Intel Core i5-14400F, 10 cores / 16 threads |
| RAM | 31.7 GiB |
| GPU | NVIDIA GeForce RTX 3060, driver 32.0.16.2124 |

`m15-service-acceptance.json` is written here by `tools/acceptance/m15_service_acceptance.ps1` (pass 1, then pass 2 after a reboot), and it records the same facts in its `machine` field.

## Pass 1: 2026-11-28, founder-run, elevated, agent built from commit e71d7bd. **All 8 checks PASS.**

| Check | Result |
|---|---|
| `service_starts` | started in 0.41 s; first governor status after 5.6 s |
| `session0_localsystem` | session 0, LocalSystem, Auto (delayed) |
| `no_visible_windows` | 0 windowed processes |
| `service_overhead` | **79.5 MiB RSS against an 80 MiB limit** (63.7 MiB private), 0.21% of one core |
| `helper_and_presence` | helper reports `active`; level `shared` (`user_active`) |
| `workload_managed` | `accept-cpu` throttled under protection, 811 units |
| `crash_recovery` | service restarted after 5.5 s; workload resumed after 0.8 s from unit 891 |
| `e1_completed` | E1 finished in 2.6 s (see below) |
| `graceful_stop` | stopped in 0.27 s, 0 workload processes left |

- **E1 (CUDA from the service), RTX 3060, CC 8.6:**
  - the service process (session 0) and its child worker both work: contexts of 124 and 73 ms, kernels around 20 ms;
  - so does a SYSTEM worker in the interactive session (session 1);
  - the worker as the logged-on *user* fails with "probe produced no result" (exit 1). That arrangement failed the same way on the retired machine and is excluded by design: UDCS never runs work as the student. Not investigated.
- **Weak point: service overhead passed with a 0.5 MiB margin.** The retired machine measured 55.6 MiB, with older agent code. Why RSS grew, and whether 80 MiB is the right limit, is an open question. The limit was not changed.
- **Redaction (2026-11-28, before the first commit):**
  - The E1 probe recorded its `account` as `os.environ["USERNAME"]`. For LocalSystem that is the machine account, `HOSTNAME$`, so the host name was in the file.
  - The three occurrences were replaced with `"<host>$"` by exact text replacement; nothing else changed.
  - The probe now records `NT AUTHORITY\SYSTEM` or `<user>`, taken from the token SID.
  - `tests/test_acceptance_evidence.py` fails on any machine-account name in per-machine evidence.
  - The installed service still runs the e71d7bd code with the old probe. Pass 2 does not run E1, so this file is not affected again.

**Pass 2 (start after a reboot): not run yet.**

**Scope.** This is new evidence for one machine, not proof of lab compatibility:
- lab images are Pro, Education or Enterprise, often domain-joined and under Deep Freeze;
- this PC runs Home edition;
- its GPU is a modern one.

The lab-image gate (ADR 0001 gate 2) and the second-machine check (ADR 0004 open item 1) stay open regardless of what is recorded here.

The retired machine's records in `../../m15-service-acceptance.json` and `../../m2-isolation-service.json` are history and are never written. `tests/test_acceptance_evidence.py` pins their content.
