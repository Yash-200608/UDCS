r"""Experiment E1: can a process create a CUDA context and allocate VRAM here?

Run it twice on each GPU model in the fleet:
  1. as the logged-on user (baseline), and
  2. as SYSTEM in session 0, which is how the UDCS service will run, e.g.:
       psexec -s -i 0 <python> cuda_context_probe.py C:\ProgramData\UDCS\e1.json
     or from a temporary scheduled task running as SYSTEM.

Uses only the CUDA driver API in nvcuda.dll, which ships with the NVIDIA driver,
so no CUDA toolkit or PyTorch is needed. Writes a JSON report and prints it.
Standard library only, so it runs with any Python 3.11+ interpreter.
"""

from __future__ import annotations

import ctypes
import json
import os
import sys
from ctypes import wintypes


def session_id() -> int | None:
    sid = wintypes.DWORD()
    kernel32 = ctypes.WinDLL("kernel32")
    if kernel32.ProcessIdToSessionId(kernel32.GetCurrentProcessId(), ctypes.byref(sid)):
        return sid.value
    return None


def probe() -> dict[str, object]:
    report: dict[str, object] = {"session_id": session_id(), "user": os.environ.get("USERNAME")}
    try:
        cuda = ctypes.WinDLL("nvcuda")
    except OSError as exc:
        report["error"] = f"nvcuda.dll not loadable: {exc}"
        return report

    def call(name: str, *args: object) -> int:
        result = getattr(cuda, name)(*args)
        report.setdefault("calls", []).append({name: result})  # type: ignore[union-attr]
        return result

    if call("cuInit", 0) != 0:
        report["ok"] = False
        return report
    version = ctypes.c_int()
    call("cuDriverGetVersion", ctypes.byref(version))
    report["driver_cuda_version"] = f"{version.value // 1000}.{(version.value % 1000) // 10}"
    count = ctypes.c_int()
    call("cuDeviceGetCount", ctypes.byref(count))
    report["device_count"] = count.value
    if count.value < 1:
        report["ok"] = False
        return report
    device = ctypes.c_int()
    call("cuDeviceGet", ctypes.byref(device), 0)
    name = ctypes.create_string_buffer(256)
    call("cuDeviceGetName", name, 256, device)
    report["device_name"] = name.value.decode(errors="replace")
    context = ctypes.c_void_p()
    if call("cuCtxCreate_v2", ctypes.byref(context), 0, device) != 0:
        report["ok"] = False
        return report
    pointer = ctypes.c_uint64()
    allocated = call("cuMemAlloc_v2", ctypes.byref(pointer), ctypes.c_size_t(64 * 2**20)) == 0
    if allocated:
        call("cuMemFree_v2", pointer)
    call("cuCtxDestroy_v2", context)
    report["ok"] = allocated
    return report


if __name__ == "__main__":
    result = probe()
    text = json.dumps(result, indent=2)
    if len(sys.argv) > 1:
        with open(sys.argv[1], "w", encoding="utf-8") as handle:
            handle.write(text)
    print(text)
