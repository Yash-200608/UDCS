"""Isolate the memory cost of NVML in a bare interpreter (staged runtime). Diagnostic only."""

import json
import site
import sys
import time

site.addsitedir(sys.argv[1] + r"\site")
import psutil

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


snap("0 bare + psutil")
import pynvml  # noqa: E402

snap("1 import pynvml")
pynvml._LoadNvmlLibrary()
snap("2 nvml.dll loaded, not initialised")
pynvml.nvmlInit()
snap("3 nvmlInit")
h = pynvml.nvmlDeviceGetHandleByIndex(0)
(
    pynvml.nvmlDeviceGetName(h),
    pynvml.nvmlDeviceGetMemoryInfo(h),
    pynvml.nvmlDeviceGetTemperature(h, 0),
)
snap("4 device queries")
pynvml.nvmlShutdown()
time.sleep(0.5)
snap("5 nvmlShutdown")
pynvml.nvmlInit()
snap("6 nvmlInit again")
pynvml.nvmlShutdown()
snap("7 nvmlShutdown again")
print(json.dumps({"driver": None, "rows": rows}))
