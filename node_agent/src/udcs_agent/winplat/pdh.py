"""Performance Data Helper (PDH) counters, readable from session 0.

Used for the signals NVML can't give on GeForce/WDDM: per-process GPU engine
utilization and dedicated GPU memory (verified working on a GT 730 where NVML
reports utilization as Not Supported), plus disk and paging pressure.
English counter names are used so localized Windows installs still work.
"""

from __future__ import annotations

import ctypes
import re
from ctypes import wintypes
from dataclasses import dataclass

from udcs_agent.winplat.api import DWORD

pdh = ctypes.WinDLL("pdh")

PDH_FMT_DOUBLE = 0x00000200
PDH_FMT_NOCAP100 = 0x00008000
PDH_MORE_DATA = 0x800007D2
PDH_CSTATUS_VALID_DATA = 0x0
PDH_CSTATUS_NEW_DATA = 0x1


class PdhError(OSError):
    def __init__(self, function: str, status: int) -> None:
        super().__init__(status, f"{function} failed with PDH status 0x{status & 0xFFFFFFFF:08X}")
        self.status = status & 0xFFFFFFFF


class _CounterValue(ctypes.Structure):
    _fields_ = [("CStatus", DWORD), ("doubleValue", ctypes.c_double)]


class _CounterValueItem(ctypes.Structure):
    _fields_ = [("szName", wintypes.LPWSTR), ("FmtValue", _CounterValue)]


pdh.PdhOpenQueryW.argtypes = [wintypes.LPCWSTR, ctypes.c_size_t, ctypes.POINTER(wintypes.HANDLE)]
pdh.PdhAddEnglishCounterW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCWSTR,
    ctypes.c_size_t,
    ctypes.POINTER(wintypes.HANDLE),
]
pdh.PdhCollectQueryData.argtypes = [wintypes.HANDLE]
pdh.PdhGetFormattedCounterValue.argtypes = [
    wintypes.HANDLE,
    DWORD,
    ctypes.POINTER(DWORD),
    ctypes.POINTER(_CounterValue),
]
pdh.PdhGetFormattedCounterArrayW.argtypes = [
    wintypes.HANDLE,
    DWORD,
    ctypes.POINTER(DWORD),
    ctypes.POINTER(DWORD),
    ctypes.c_void_p,
]
pdh.PdhCloseQuery.argtypes = [wintypes.HANDLE]
for _fn in (
    pdh.PdhOpenQueryW,
    pdh.PdhAddEnglishCounterW,
    pdh.PdhCollectQueryData,
    pdh.PdhGetFormattedCounterValue,
    pdh.PdhGetFormattedCounterArrayW,
    pdh.PdhCloseQuery,
):
    _fn.restype = DWORD


def _ok(status: int, function: str) -> None:
    if status != 0:
        raise PdhError(function, status)


class PdhQuery:
    """A set of counters sampled together. Rate counters need two collections."""

    def __init__(self, counters: dict[str, str]) -> None:
        self._query = wintypes.HANDLE()
        _ok(pdh.PdhOpenQueryW(None, 0, ctypes.byref(self._query)), "PdhOpenQueryW")
        self._counters: dict[str, wintypes.HANDLE] = {}
        self.unavailable: dict[str, str] = {}
        for name, path in counters.items():
            handle = wintypes.HANDLE()
            status = pdh.PdhAddEnglishCounterW(self._query, path, 0, ctypes.byref(handle))
            if status == 0:
                self._counters[name] = handle
            else:  # e.g. no WDDM 2.x GPU counters on this machine
                self.unavailable[name] = f"0x{status & 0xFFFFFFFF:08X}"

    def collect(self) -> None:
        _ok(pdh.PdhCollectQueryData(self._query), "PdhCollectQueryData")

    def value(self, name: str) -> float | None:
        handle = self._counters.get(name)
        if handle is None:
            return None
        result = _CounterValue()
        status = pdh.PdhGetFormattedCounterValue(
            handle, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, None, ctypes.byref(result)
        )
        if status != 0 or result.CStatus not in (PDH_CSTATUS_VALID_DATA, PDH_CSTATUS_NEW_DATA):
            return None
        return result.doubleValue

    def array(self, name: str) -> list[tuple[str, float]] | None:
        """[] = genuinely no instances; None = the read failed (callers must fail safe)."""
        handle = self._counters.get(name)
        if handle is None:
            return None
        size, count = DWORD(0), DWORD(0)
        status = pdh.PdhGetFormattedCounterArrayW(
            handle, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, ctypes.byref(size), ctypes.byref(count), None
        )
        if status == 0:
            return []  # success with an empty buffer: no instances
        if status != PDH_MORE_DATA:
            return None
        buffer = ctypes.create_string_buffer(size.value)
        status = pdh.PdhGetFormattedCounterArrayW(
            handle,
            PDH_FMT_DOUBLE | PDH_FMT_NOCAP100,
            ctypes.byref(size),
            ctypes.byref(count),
            buffer,
        )
        if status != 0:
            return None
        items = ctypes.cast(buffer, ctypes.POINTER(_CounterValueItem))
        out = []
        for i in range(count.value):
            item = items[i]
            if item.FmtValue.CStatus in (PDH_CSTATUS_VALID_DATA, PDH_CSTATUS_NEW_DATA):
                out.append((item.szName, item.FmtValue.doubleValue))
        return out

    def close(self) -> None:
        if self._query:
            pdh.PdhCloseQuery(self._query)
            self._query = wintypes.HANDLE()


_ENGINE = re.compile(r"pid_(\d+)_luid_(0x[0-9a-fA-F]+_0x[0-9a-fA-F]+)_phys_(\d+)_eng_(\d+)")
_PROCESS_MEMORY = re.compile(r"pid_(\d+)_luid_(0x[0-9a-fA-F]+_0x[0-9a-fA-F]+)")


@dataclass(frozen=True)
class GpuUsage:
    """Per-adapter busy fraction, split by process ownership.

    An engine's utilization is the sum over the processes using it; a GPU is as
    busy as its busiest engine (the same model Task Manager uses).
    """

    adapter: str
    total_percent: float
    udcs_percent: float
    other_percent: float
    udcs_dedicated_bytes: int
    other_dedicated_bytes: int


def gpu_usage(
    engine_samples: list[tuple[str, float]],
    memory_samples: list[tuple[str, float]],
    udcs_pids: set[int],
) -> list[GpuUsage]:
    engines: dict[tuple[str, str, str], list[float]] = {}  # (luid, phys, eng) -> [udcs, other]
    for instance, value in engine_samples:
        match = _ENGINE.search(instance)
        if not match:
            continue
        pid, luid, phys, eng = int(match[1]), match[2], match[3], match[4]
        slot = engines.setdefault((luid, phys, eng), [0.0, 0.0])
        slot[0 if pid in udcs_pids else 1] += value
    memory: dict[str, list[int]] = {}
    for instance, value in memory_samples:
        match = _PROCESS_MEMORY.search(instance)
        if not match:
            continue
        slot = memory.setdefault(match[2], [0, 0])
        slot[0 if int(match[1]) in udcs_pids else 1] += int(value)
    adapters = {key[0] for key in engines} | set(memory)
    result = []
    for luid in sorted(adapters):
        rows = [v for k, v in engines.items() if k[0] == luid]
        mem = memory.get(luid, [0, 0])
        result.append(
            GpuUsage(
                adapter=luid,
                total_percent=min(100.0, max((u + o for u, o in rows), default=0.0)),
                udcs_percent=min(100.0, max((u for u, _ in rows), default=0.0)),
                other_percent=min(100.0, max((o for _, o in rows), default=0.0)),
                udcs_dedicated_bytes=mem[0],
                other_dedicated_bytes=mem[1],
            )
        )
    return result
