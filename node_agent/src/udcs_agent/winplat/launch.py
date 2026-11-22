"""Launch a process *inside* a job, already demoted, before it runs any code.

Python's subprocess cannot do this: it doesn't expose the primary thread handle,
so a child could start (and spawn its own children) before assignment.
Sequence: CreateProcessW(CREATE_SUSPENDED) -> assign to job -> disable priority
boost and lower memory priority -> ResumeThread.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from udcs_agent.winplat import api
from udcs_agent.winplat.jobs import JobObject


@dataclass
class LaunchedProcess:
    pid: int
    handle: int = field(repr=False)

    def exit_code(self) -> int | None:
        """None while running."""
        code = api.DWORD()
        api.check(api.GetExitCodeProcess(self.handle, ctypes.byref(code)), "GetExitCodeProcess")
        return None if code.value == api.STILL_ACTIVE else int(code.value)

    def wait(self, timeout_seconds: float) -> int | None:
        api.WaitForSingleObject(self.handle, int(timeout_seconds * 1000))
        return self.exit_code()

    def close(self) -> None:
        if self.handle:
            api.CloseHandle(self.handle)
            self.handle = 0


def _environment_block(env: dict[str, str]) -> ctypes.Array[ctypes.c_wchar]:
    text = "".join(f"{k}={v}\0" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper()))
    return ctypes.create_unicode_buffer(text + "\0")


def launch_in_job(
    argv: list[str],
    job: JobObject,
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    memory_priority: int = api.MEMORY_PRIORITY_VERY_LOW,
) -> LaunchedProcess:
    if not argv or not Path(argv[0]).is_absolute():
        raise ValueError("argv[0] must be an absolute executable path (no PATH search)")
    command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
    startup = api.STARTUPINFOW()
    startup.cb = ctypes.sizeof(startup)
    info = api.PROCESS_INFORMATION()
    flags = (
        api.CREATE_SUSPENDED
        | api.CREATE_NO_WINDOW
        | api.CREATE_NEW_PROCESS_GROUP
        | api.CREATE_UNICODE_ENVIRONMENT
        | api.IDLE_PRIORITY_CLASS
    )
    block = _environment_block(env if env is not None else dict(os.environ))
    api.check(
        api.CreateProcessW(
            argv[0],
            command_line,
            None,
            None,
            False,
            flags,
            ctypes.cast(block, ctypes.c_void_p),
            str(cwd),
            ctypes.byref(startup),
            ctypes.byref(info),
        ),
        "CreateProcessW",
    )
    try:
        job.assign(info.hProcess)
        api.SetProcessPriorityBoost(info.hProcess, True)  # never preempt the student via boosts
        priority = api.MEMORY_PRIORITY_INFORMATION(memory_priority)
        api.SetProcessInformation(
            info.hProcess,
            api.ProcessMemoryPriority,
            ctypes.byref(priority),
            ctypes.sizeof(priority),
        )
        if api.ResumeThread(info.hThread) == 0xFFFFFFFF:
            raise api.WinApiError("ResumeThread")
    except BaseException:
        api.TerminateProcess(info.hProcess, 1)  # works whether or not it joined the job
        api.TerminateJobObject(job.handle, 1)
        api.CloseHandle(info.hProcess)
        raise
    finally:
        api.CloseHandle(info.hThread)
    return LaunchedProcess(pid=int(info.dwProcessId), handle=info.hProcess)
