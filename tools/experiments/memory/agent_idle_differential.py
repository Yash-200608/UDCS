"""I-2 differential: same steps for any agent build (old or new). Diagnostic only, current user.

    <stage>\\python\\python.exe -I -B agent_idle_differential.py <stage> <workdir> [--no-nvml]

Steps: interpreter, pywin32, agent imports, NVML start, then the real AgentApp idle for 40 s
(helper pipe channel off when the build supports turning it off). --no-nvml makes
nvmlInit fail as "library not found", so the agent runs without NVML (as on a node with
no NVIDIA driver).
"""

import inspect
import json
import site
import sys
import threading
import time
from pathlib import Path

stage, work = Path(sys.argv[1]), Path(sys.argv[2])
NO_NVML = "--no-nvml" in sys.argv
site.addsitedir(str(stage / "site"))
import psutil  # noqa: E402

me = psutil.Process()
rows = []


def snap(label):
    m = me.memory_info()
    rows.append(
        {
            "label": label,
            "ws": round(m.rss / 2**20, 2),
            "private": round(m.private / 2**20, 2),
            "handles": me.num_handles(),
            "threads": me.num_threads(),
        }
    )


snap("interpreter + site")
import servicemanager  # noqa: E402, F401

snap("pywin32 service modules")
import udcs_agent.app as appmod  # noqa: E402
import udcs_agent.service  # noqa: E402,F401

snap("agent imports")
if NO_NVML:
    import pynvml

    pynvml.nvmlInit = lambda *a, **k: (_ for _ in ()).throw(
        pynvml.NVMLError(pynvml.NVML_ERROR_LIBRARY_NOT_FOUND)
    )
data = work / "data"
data.mkdir(parents=True, exist_ok=True)
stop = threading.Event()
kwargs = {"stop": stop}
params = inspect.signature(appmod.AgentApp.__init__).parameters
if "require_secure_data_dir" in params:
    kwargs["require_secure_data_dir"] = False
if "helper_channel" in params:
    kwargs["helper_channel"] = False
app = appmod.AgentApp(data, **kwargs)
t = threading.Thread(target=app.run, daemon=True)
t.start()
ws = []
for _ in range(20):
    time.sleep(2.0)
    m = me.memory_info()
    ws.append((m.rss / 2**20, m.private / 2**20))
snap("agent idle 40 s (last sample)")
stop.set()
t.join(timeout=15)
print(
    json.dumps(
        {
            "stage": stage.name,
            "no_nvml": NO_NVML,
            "helper_channel_off": "helper_channel" in params,
            "rows": rows,
            "idle_ws_min_max": [round(min(w for w, _ in ws), 2), round(max(w for w, _ in ws), 2)],
            "idle_private_min_max": [
                round(min(p for _, p in ws), 2),
                round(max(p for _, p in ws), 2),
            ],
        }
    ),
    flush=True,
)
import os  # noqa: E402

os._exit(0)
