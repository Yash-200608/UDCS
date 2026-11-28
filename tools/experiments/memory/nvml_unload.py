"""Does unloading nvml.dll after nvmlShutdown release NVML's memory? Diagnostic only."""

import ctypes
import json
import site
import sys
from ctypes import wintypes

site.addsitedir(sys.argv[1] + r"\site")
import psutil
import pynvml

me = psutil.Process()
rows = []
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.GetModuleHandleW.restype = wintypes.HMODULE
k32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
k32.FreeLibrary.argtypes = [wintypes.HMODULE]


def snap(label):
    m = me.memory_info()
    rows.append(
        {
            "label": label,
            "ws": round(m.rss / 2**20, 2),
            "private": round(m.private / 2**20, 2),
            "handles": me.num_handles(),
            "threads": me.num_threads(),
            "nvml_loaded": bool(k32.GetModuleHandleW("nvml.dll")),
        }
    )


snap("0 pynvml imported")
pynvml.nvmlInit()
snap("1 nvmlInit")
pynvml.nvmlShutdown()
snap("2 nvmlShutdown")
freed = 0
while k32.GetModuleHandleW("nvml.dll") and freed < 10:
    k32.FreeLibrary(k32.GetModuleHandleW("nvml.dll"))
    freed += 1
snap(f"3 FreeLibrary x{freed}")
print(json.dumps(rows), flush=True)
