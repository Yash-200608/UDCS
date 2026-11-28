"""Experiment E1 probe: create a CUDA context, JIT a kernel, run it, report.

    python -m udcs_agent.diagnostics.gpu_probe OUT.json

Distinguishes "driver detected" from "CUDA work actually executes in this
process context". It still says nothing about framework (e.g. PyTorch) support.
"""

from __future__ import annotations

import ctypes
import json
import os
import sys
import time
import traceback
from pathlib import Path


def _is_local_system() -> bool | None:
    """True if this process's token user is LocalSystem; None if it cannot be read.

    ctypes only. The E1 child workers run `python -I`, where pywin32's DLLs are not on the
    search path, so importing win32api there fails (measured 2026-11-28: that ImportError
    killed every child probe)."""
    if sys.platform != "win32":
        return None
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.IsWellKnownSid.argtypes = [ctypes.c_void_p, ctypes.c_int]
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)
    ):  # TOKEN_QUERY
        return None
    try:
        buffer = ctypes.create_string_buffer(256)  # TOKEN_USER: SID_AND_ATTRIBUTES
        needed = wintypes.DWORD()
        if not advapi32.GetTokenInformation(
            token, 1, buffer, len(buffer), ctypes.byref(needed)
        ):  # TokenUser
            return None
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        return bool(advapi32.IsWellKnownSid(sid, 22))  # WinLocalSystemSid
    finally:
        kernel32.CloseHandle(token)


def _account() -> str:
    """Who the probe ran as, never a name, and never an exception: this runs outside the
    probe's error handling. The value lands in committed acceptance evidence, where
    LocalSystem's USERNAME (HOSTNAME$) leaked the host name and a user worker's USERNAME
    would be a student's account name."""
    try:
        system = _is_local_system()
    except Exception:  # noqa: BLE001 -- identity is a label; it must never stop the probe
        system = None
    if system is None:
        return "<unknown>"
    return "NT AUTHORITY\\SYSTEM" if system else "<user>"


def probe() -> dict[str, object]:
    from udcs_agent.winplat.api import current_session_id

    result: dict[str, object] = {
        "session_id": current_session_id(),
        "pid": os.getpid(),
        "account": _account(),
    }
    try:
        from udcs_agent.workloads.cudadrv import CudaDevice

        started = time.perf_counter()
        device = CudaDevice()
        result.update(
            device=device.name,
            compute_capability=device.compute_capability,
            context_ms=round((time.perf_counter() - started) * 1000, 1),
        )
        iters = device.calibrate(0.02)
        times = [device.run_kernel(iters) for _ in range(5)]
        device.close()
        result.update(ok=True, kernel_ms_median=round(sorted(times)[2] * 1000, 2))
    except Exception as exc:  # noqa: BLE001 — every failure mode is the experiment's data
        result.update(
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            code=getattr(exc, "code", None),
            trace=traceback.format_exc()[-800:],
        )
    return result


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    result = probe()
    text = json.dumps(result, indent=1)
    if args:
        Path(args[0]).write_text(text, encoding="utf-8")
    print(text)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
