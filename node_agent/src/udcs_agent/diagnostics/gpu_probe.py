"""Experiment E1 probe: create a CUDA context, JIT a kernel, run it, report.

    python -m udcs_agent.diagnostics.gpu_probe OUT.json

Distinguishes "driver detected" from "CUDA work actually executes in this
process context". It still says nothing about framework (e.g. PyTorch) support.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
from pathlib import Path


def _account() -> str:
    """Who the probe ran as, from the token SID, never a name. This lands in committed
    acceptance evidence: LocalSystem's USERNAME is the machine account (HOSTNAME$), which
    leaked the host name, and a user worker's USERNAME is a student's account name."""
    from udcs_agent.diagnostics.context import LOCAL_SYSTEM_SID, _sid

    sid = _sid()
    if sid == LOCAL_SYSTEM_SID:
        return "NT AUTHORITY\\SYSTEM"
    return "<user>" if sid else "<unknown>"


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
