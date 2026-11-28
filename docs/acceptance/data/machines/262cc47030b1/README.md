# Acceptance machine `262cc47030b1`

Designated as the M1.5 acceptance machine on 2026-11-28 (decision D-6), after the original build 22000 machine was retired. The label is the first 12 hex characters of SHA-256 of the lower-cased host name; the host name itself is not recorded.

| Fact | Value (read 2026-11-28) |
|---|---|
| Edition | Windows 11 Home Single Language (`CoreSingleLanguage`), 26H2 |
| Build | 10.0.26300 (UBR 26300.10075) |
| CPU | Intel Core i5-14400F, 10 cores / 16 threads |
| RAM | 31.7 GiB |
| GPU | NVIDIA GeForce RTX 3060, driver 32.0.16.2124 |

`m15-service-acceptance.json` is written here by `tools/acceptance/m15_service_acceptance.ps1` (pass 1, then pass 2 after a reboot), and it records the same facts in its `machine` field. **Neither pass has run yet:** pass 1 installs the UDCSAgent service, and that needs a separate approval.

**Scope.** This is new evidence for one machine, not proof of lab compatibility:
- lab images are Pro, Education or Enterprise, often domain-joined and under Deep Freeze;
- this PC runs Home edition;
- its GPU is a modern one.

The lab-image gate (ADR 0001 gate 2) and the second-machine check (ADR 0004 open item 1) stay open regardless of what is recorded here.

The retired machine's records in `../../m15-service-acceptance.json` and `../../m2-isolation-service.json` are history and are never written. `tests/test_acceptance_evidence.py` pins their content.
