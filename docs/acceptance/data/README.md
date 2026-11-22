# M1.5 benchmark raw data

These are the raw outputs of `tools/acceptance/m15_benchmarks.py` on the development PC. See [../milestone-1.5.md](../milestone-1.5.md).

The files are kept unedited, including the failed runs, so the report can be checked against them.

| File | What it contains | Used in the report? |
|---|---|---|
| `m15-benchmarks-2026-11-21.json` | First full run. Its all-core CPU figure (+33.5%) turned out to be noise, and its response trials failed with `TimeoutError` because of a harness bug: the wait was shorter than the 120 s grace plus 30 s relax period. | Only as the superseded run in "An earlier run that was wrong" |
| `m15-cpu-all-cap-diagnosis.json` | A 5-round interleaved retest of all-core CPU. It shows the +33.5% figure was noise. | Yes |
| `m15-benchmarks-2026-11-22.json` | B1 interference for cpu, cpu_all, memory and gpu. Its "student arrives" response trials hit the same harness timeout (`level open not reached`). | B1 only |
| `m15-benchmarks-2026-11-22-disk.json` | Isolated disk interference run. | B1 disk row (inconclusive) |
| `m15-benchmarks-2026-11-22-response.json` | B2 response latency after the harness wait was fixed (240 s). | B2 |

The `TimeoutError` entries are failures of the benchmark harness, not of the governor. They are kept so the record is complete.
