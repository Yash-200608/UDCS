"""I-2 memory attribution for the UDCS agent. Diagnostic only, current user, no elevation.

Run with a STAGED interpreter so the runtime matches the installed service:
    <stage>\\python\\python.exe -I -B agent_phases.py <stage> <workdir> <out.json> [--tracemalloc]

Phase A: incremental steps (imports, NVML, PDH query) in this one process.
Phase B: the real AgentApp in a thread (helper pipe channel OFF so it can never take the
installed service's pipe), sampled every 2 s through: idle, a synthetic cpu workload,
the E1 GPU matrix (in-process probe + child worker), and shutdown.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

stage, work, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
TRACE = "--tracemalloc" in sys.argv
import site  # noqa: E402

site.addsitedir(str(stage / "site"))  # as run_service.py does (also runs pywin32.pth)

if TRACE:
    import tracemalloc

    tracemalloc.start(25)

import psutil  # noqa: E402

ME = psutil.Process()
T0 = time.monotonic()
samples: list[dict] = []
steps: list[dict] = []


def snap(label: str) -> dict:
    m = ME.memory_info()
    row = {
        "t": round(time.monotonic() - T0, 1),
        "label": label,
        "ws_mib": round(m.rss / 2**20, 2),
        "peak_ws_mib": round(m.peak_wset / 2**20, 2),
        "private_mib": round(m.private / 2**20, 2),
        "handles": ME.num_handles(),
        "threads": ME.num_threads(),
    }
    if TRACE:
        cur, _peak = tracemalloc.get_traced_memory()
        row["py_traced_mib"] = round(cur / 2**20, 2)
    return row


def maps_top(n: int = 25) -> list[dict]:
    rows = []
    for mm in ME.memory_maps(grouped=True):
        rows.append({"path": os.path.basename(mm.path), "rss_mib": round(mm.rss / 2**20, 2)})
    rows.sort(key=lambda r: -r["rss_mib"])
    total = round(sum(r["rss_mib"] for r in rows), 2)
    return [{"mapped_files_total_mib": total}, *rows[:n]]


def step(label: str) -> None:
    row = snap(label)
    row["maps"] = maps_top()
    if TRACE:
        stats = tracemalloc.take_snapshot().statistics("filename")[:15]
        row["py_top"] = [
            {
                "file": str(s.traceback[0].filename).replace(str(stage), "<stage>"),
                "mib": round(s.size / 2**20, 2),
            }
            for s in stats
        ]
    steps.append(row)
    print(
        f"{row['label']:<38} ws={row['ws_mib']:7.2f} private={row['private_mib']:7.2f} "
        f"handles={row['handles']:5} threads={row['threads']:3}",
        flush=True,
    )


# ---- Phase A ---------------------------------------------------------------------------
step("A0 interpreter + site")
import servicemanager  # noqa: E402, F401

step("A1 pywin32 service modules")
import udcs_agent.app  # noqa: E402
import udcs_agent.service  # noqa: E402,F401

step("A2 import udcs_agent.app/service")
from udcs_agent.discovery.nvidia import Nvml  # noqa: E402

nv = Nvml()
nv.ensure_started()
step("A3 NVML started")
from udcs_agent.governor import signals  # noqa: E402
from udcs_agent.winplat.pdh import PdhQuery  # noqa: E402

q = PdhQuery(signals._COUNTERS)
q.collect()
time.sleep(1.1)
q.collect()
engines = len(q.array("gpu_engine") or [])
gpumem = len(q.array("gpu_memory") or [])
step(f"A4 PDH query x2 ({engines} engine, {gpumem} gpu-mem instances)")
q.close()
step("A5 PDH query closed")
nv.shutdown()

# ---- Phase B ---------------------------------------------------------------------------
from udcs_agent.app import AgentApp  # noqa: E402

data = work / "data"
data.mkdir(parents=True, exist_ok=True)
stop = threading.Event()
app = AgentApp(data, stop=stop, require_secure_data_dir=False, helper_channel=False)
phase = {"name": "B0 agent starting"}
done = threading.Event()


def sampler() -> None:
    while not done.is_set():
        samples.append(snap(phase["name"]))
        time.sleep(2.0)


threading.Thread(target=sampler, daemon=True).start()
runner = threading.Thread(target=app.run, name="agent", daemon=True)
runner.start()


def wait(seconds: float, name: str) -> None:
    phase["name"] = name
    time.sleep(seconds)


wait(45, "B1 idle (governor ticking)")
step("B1 end of idle")
# a synthetic cpu workload, added the way `run_agent.py workload add` does it
from udcs_agent.cli import main as cli_main  # noqa: E402

cli_main(
    ["--plain-logs", "--data-dir", str(data), "workload", "add", "--id", "mem-cpu", "--kind", "cpu"]
)
wait(45, "B2 workload running")
step("B2 end of workload")
(data / "diagnostics").mkdir(exist_ok=True)
(data / "diagnostics" / "gpu-request").touch()
phase["name"] = "B3 E1 GPU matrix"
deadline = time.monotonic() + 120
while not (data / "diagnostics" / "gpu-result.json").exists() and time.monotonic() < deadline:
    time.sleep(0.5)
e1 = (
    json.loads((data / "diagnostics" / "gpu-result.json").read_text(encoding="utf-8"))
    if (data / "diagnostics" / "gpu-result.json").exists()
    else {}
)
wait(20, "B4 after E1")
step("B4 after E1")
wait(30, "B5 idle after E1")
step("B5 idle after E1")
phase["name"] = "B6 shutdown"
stop.set()
runner.join(timeout=15)
done.set()
step("B6 after shutdown")

result = {
    "kind": "i2-memory-attribution",
    "evidence": False,
    "tracemalloc": TRACE,
    "runtime": sys.version,
    "cpu_count": os.cpu_count(),
    "steps": steps,
    "samples": samples,
    "e1_arrangements": {k: v.get("ok") for k, v in (e1.get("arrangements") or {}).items()},
}
out.write_text(json.dumps(result, indent=1), encoding="utf-8")
print("written", out)
os._exit(0)
