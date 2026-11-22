"""Built-in synthetic workloads used to validate local protection (Milestone 1.5).

    python -m udcs_agent.workloads.synthetic --kind cpu|memory|disk|gpu --dir WORKDIR

They implement the cooperative workload contract (operating model §8):
- read  WORKDIR/control.json  {"seq": n, "command": "run" | "pause" | "checkpoint"}
- write WORKDIR/status.json   {"state", "units_done", "ack_seq", ...}
- keep  WORKDIR/checkpoint.json so a restarted run resumes where it stopped
- exit 0 when complete, EXIT_CHECKPOINTED after a requested checkpoint.
- on completion write WORKDIR/result.json {"units", "checksum"}, where checksum =
  sum(i*i) over every unit index processed. It is checkpointed with units_done, so a
  lost or repeated unit across resume is detectable (udcs_shared.jobs.expected_checksum).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

EXIT_CHECKPOINTED = 85
_UNIT_SECONDS = 0.05


def _atomic_write(path: Path, data: dict[str, object]) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, path)


def _enter_background_mode() -> None:
    """Lower this process's I/O and memory priority (only callable on oneself)."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # Declared types matter: without them the pseudo-handle -1 is passed as a 32-bit
        # 0xFFFFFFFF, an invalid handle. Windows ignored that silently on the host (so
        # background mode was never applied before this fix), and an AppContainer's
        # strict handle checking turned it into a crash.
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.SetPriorityClass.restype = wintypes.BOOL
        if not kernel32.SetPriorityClass(kernel32.GetCurrentProcess(), 0x00100000):  # BG_BEGIN
            raise OSError(ctypes.get_last_error(), "could not enter background mode")


class _Control:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._mtime = 0.0
        self.seq = 0
        self.command = "run"

    def poll(self) -> str:
        try:
            mtime = self.path.stat().st_mtime
        except FileNotFoundError:
            return self.command
        if mtime != self._mtime:
            self._mtime = mtime
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self.seq, self.command = int(data["seq"]), str(data["command"])
            except (ValueError, KeyError, OSError):
                pass  # partially written; read again next poll
        return self.command


def _make_unit(kind: str, workdir: Path, memory_mb: int):
    if kind == "cpu":

        def unit() -> None:
            end = time.perf_counter() + _UNIT_SECONDS
            x = 0
            while time.perf_counter() < end:
                for i in range(2000):
                    x += i * i

        return unit, lambda: None
    if kind == "memory":
        buffers: list[bytearray] = []

        def unit() -> bool:
            if not buffers:
                try:
                    buffers.append(bytearray(memory_mb * 2**20))
                except MemoryError:  # job commit limit reached: allocations are suspended
                    time.sleep(0.2)
                    return False  # no progress was made; don't count it
            bytes(buffers[0])  # stream the buffer: memory-bandwidth bound
            return True

        return unit, buffers.clear
    if kind == "disk":
        path = workdir / "scratch.bin"
        block = os.urandom(8 * 2**20)

        def unit() -> None:
            with open(path, "wb") as handle:
                for _ in range(4):
                    handle.write(block)
                handle.flush()
                os.fsync(handle.fileno())
            with open(path, "rb") as handle:
                while handle.read(4 * 2**20):
                    pass

        return unit, lambda: path.unlink(missing_ok=True)
    if kind == "gpu":
        try:
            from udcs_agent.workloads.cudadrv import CudaDevice
        except ImportError:  # isolated runtime: copied next to this file, no agent package
            from cudadrv import CudaDevice  # type: ignore[no-redef]

        device = CudaDevice()
        iters = device.calibrate(0.04)  # 40 ms kernels: far below the 2 s TDR limit
        return (lambda: device.run_kernel(iters)), device.close
    raise SystemExit(f"unknown kind {kind!r}")


def run(kind: str, workdir: Path, total_units: int, memory_mb: int) -> int:
    workdir.mkdir(parents=True, exist_ok=True)
    _enter_background_mode()
    checkpoint_path, status_path = workdir / "checkpoint.json", workdir / "status.json"
    control = _Control(workdir / "control.json")
    try:
        saved = json.loads(checkpoint_path.read_text())
        units_done = int(saved["units_done"])
        checksum = int(saved.get("checksum", 0))
    except (FileNotFoundError, ValueError, KeyError):
        units_done, checksum = 0, 0
    resumed_from = units_done

    def status(state: str) -> None:
        _atomic_write(
            status_path,
            {
                "state": state,
                "kind": kind,
                "units_done": units_done,
                "total_units": total_units,
                "resumed_from": resumed_from,
                "ack_seq": control.seq,
                "pid": os.getpid(),
                "updated": time.time(),
            },
        )

    def checkpoint() -> None:
        _atomic_write(checkpoint_path, {"units_done": units_done, "checksum": checksum})

    unit, cleanup = _make_unit(kind, workdir, memory_mb)
    last_save = time.monotonic()
    status("running")
    try:
        while units_done < total_units:
            command = control.poll()
            if command == "checkpoint":
                checkpoint()
                status("checkpointed")
                return EXIT_CHECKPOINTED
            if command == "pause":
                status("paused")
                time.sleep(0.1)  # GPU: no new kernels are submitted while paused
                continue
            if unit() is False:
                continue
            checksum += units_done * units_done
            units_done += 1
            if time.monotonic() - last_save >= 2.0:
                checkpoint()
                status("running")
                last_save = time.monotonic()
        checkpoint()
        _atomic_write(workdir / "result.json", {"units": units_done, "checksum": str(checksum)})
        status("completed")
        return 0
    finally:
        cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=["cpu", "memory", "disk", "gpu"], required=True)
    parser.add_argument("--dir", type=Path, required=True)
    parser.add_argument("--total-units", type=int, default=10**9)
    parser.add_argument("--memory-mb", type=int, default=256)
    args = parser.parse_args(argv)
    return run(args.kind, args.dir, args.total_units, args.memory_mb)


if __name__ == "__main__":
    sys.exit(main())
