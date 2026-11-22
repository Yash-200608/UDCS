"""Job Objects: the agent's control surface over every UDCS workload process.

Verified on Windows 11 Pro 22000 (2026-11-21): hard CPU caps apply and can be
changed while the job runs; processes must be *created* inside the job
(see launch.py), because children spawned before assignment escape it.
"""

from __future__ import annotations

import ctypes
import logging
from dataclasses import dataclass

from udcs_agent.winplat import api

logger = logging.getLogger(__name__)

_100NS = 10_000_000


@dataclass(frozen=True)
class JobAccounting:
    cpu_seconds: float
    active_processes: int
    total_processes: int
    read_bytes: int
    write_bytes: int
    peak_job_memory_bytes: int


class JobObject:
    """An anonymous job. KILL_ON_JOB_CLOSE: if the agent dies, its workloads die too.

    That is the Phase-1 crash-safety choice (operating model §9): an orphaned
    workload with nobody enforcing its limits is worse than a lost workload that
    resumes from its checkpoint.
    """

    def __init__(self) -> None:
        self.handle = api.check(api.CreateJobObjectW(None, None), "CreateJobObjectW")
        self._limit_flags = (
            api.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | api.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION  # no crash dialogs for students
            | api.JOB_OBJECT_LIMIT_PRIORITY_CLASS  # workloads cannot raise their class
        )
        self._job_memory_limit = 0
        self.cpu_cap_percent: float | None = None
        self._apply_limits()

    # -- limits -----------------------------------------------------------------

    def _apply_limits(self) -> None:
        info = api.JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = self._limit_flags
        info.BasicLimitInformation.PriorityClass = api.IDLE_PRIORITY_CLASS
        info.JobMemoryLimit = self._job_memory_limit
        api.check(
            api.SetInformationJobObject(
                self.handle,
                api.JobObjectExtendedLimitInformation,
                ctypes.byref(info),
                ctypes.sizeof(info),
            ),
            "SetInformationJobObject(ExtendedLimit)",
        )

    def set_memory_limit(self, job_bytes: int | None) -> None:
        """Commit limit for the whole job. Over-limit allocations fail; nothing is killed."""
        if job_bytes is None:
            self._limit_flags &= ~api.JOB_OBJECT_LIMIT_JOB_MEMORY
            self._job_memory_limit = 0
        else:
            self._limit_flags |= api.JOB_OBJECT_LIMIT_JOB_MEMORY
            self._job_memory_limit = max(int(job_bytes), 16 * 2**20)
        self._apply_limits()

    def set_cpu_cap(self, percent: float | None) -> None:
        """Hard cap as a percentage of *all* logical processors (None = uncapped)."""
        info = api.JOBOBJECT_CPU_RATE_CONTROL_INFORMATION()
        if percent is not None:
            rate = round(min(100.0, max(0.01, percent)) * 100)
            info.ControlFlags = (
                api.JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | api.JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
            )
            info.CpuRate = max(1, rate)
        api.check(
            api.SetInformationJobObject(
                self.handle,
                api.JobObjectCpuRateControlInformation,
                ctypes.byref(info),
                ctypes.sizeof(info),
            ),
            "SetInformationJobObject(CpuRateControl)",
        )
        self.cpu_cap_percent = percent

    # -- membership and accounting ------------------------------------------------

    def assign(self, process_handle: int) -> None:
        api.check(
            api.AssignProcessToJobObject(self.handle, process_handle), "AssignProcessToJobObject"
        )

    def contains(self, process_handle: int) -> bool:
        result = api.BOOL()
        api.check(
            api.IsProcessInJob(process_handle, self.handle, ctypes.byref(result)), "IsProcessInJob"
        )
        return bool(result.value)

    def process_ids(self) -> list[int]:
        capacity = 64
        while True:

            class _List(ctypes.Structure):
                _fields_ = [
                    ("Assigned", api.DWORD),
                    ("InList", api.DWORD),
                    ("Ids", api.ULONG_PTR * capacity),
                ]

            buf = _List()
            ok = api.QueryInformationJobObject(
                self.handle,
                api.JobObjectBasicProcessIdList,
                ctypes.byref(buf),
                ctypes.sizeof(buf),
                None,
            )
            if ok and buf.Assigned <= capacity:
                return [int(buf.Ids[i]) for i in range(buf.InList)]
            if not ok and ctypes.get_last_error() not in (234,):  # ERROR_MORE_DATA
                raise api.WinApiError("QueryInformationJobObject(ProcessIdList)")
            capacity *= 4

    def accounting(self) -> JobAccounting:
        acct = api.JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION()
        api.check(
            api.QueryInformationJobObject(
                self.handle,
                api.JobObjectBasicAndIoAccountingInformation,
                ctypes.byref(acct),
                ctypes.sizeof(acct),
                None,
            ),
            "QueryInformationJobObject(Accounting)",
        )
        limits = api.JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        api.check(
            api.QueryInformationJobObject(
                self.handle,
                api.JobObjectExtendedLimitInformation,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
                None,
            ),
            "QueryInformationJobObject(ExtendedLimit)",
        )
        basic = acct.BasicInfo
        return JobAccounting(
            cpu_seconds=(basic.TotalUserTime + basic.TotalKernelTime) / _100NS,
            active_processes=basic.ActiveProcesses,
            total_processes=basic.TotalProcesses,
            read_bytes=acct.IoInfo.ReadTransferCount,
            write_bytes=acct.IoInfo.WriteTransferCount,
            peak_job_memory_bytes=limits.PeakJobMemoryUsed,
        )

    # -- suspension ------------------------------------------------------------------

    def _thread_ids(self) -> list[int]:
        pids = set(self.process_ids())
        if not pids:
            return []
        snapshot = api.CreateToolhelp32Snapshot(api.TH32CS_SNAPTHREAD, 0)
        if snapshot == api.INVALID_HANDLE_VALUE:
            raise api.WinApiError("CreateToolhelp32Snapshot")
        try:
            entry = api.THREADENTRY32()
            entry.dwSize = ctypes.sizeof(entry)
            threads = []
            ok = api.Thread32First(snapshot, ctypes.byref(entry))
            while ok:
                if entry.th32OwnerProcessID in pids:
                    threads.append(entry.th32ThreadID)
                ok = api.Thread32Next(snapshot, ctypes.byref(entry))
            return threads
        finally:
            api.CloseHandle(snapshot)

    def _for_each_thread(self, operation) -> int:
        count = 0
        for tid in self._thread_ids():
            thread = api.OpenThread(api.THREAD_SUSPEND_RESUME, False, tid)
            if not thread:
                continue  # thread exited between snapshot and open
            try:
                if operation(thread) != 0xFFFFFFFF:
                    count += 1
            finally:
                api.CloseHandle(thread)
        return count

    def suspend(self) -> int:
        """Suspend every thread (the documented route BOINC also uses).

        Keeps RAM and VRAM allocated, so it is only a short-term rung of the
        action ladder. Returns the number of threads suspended.
        """
        return self._for_each_thread(api.SuspendThread)

    def resume(self) -> int:
        """Undo one suspend() (resume counts are per thread, so calls must be paired)."""
        return self._for_each_thread(api.ResumeThread)

    def terminate(self, exit_code: int = 1) -> None:
        api.check(api.TerminateJobObject(self.handle, exit_code), "TerminateJobObject")

    def close(self) -> None:
        if self.handle:
            api.CloseHandle(self.handle)  # kill-on-close terminates any survivors
            self.handle = None
