"""Launch a process into an interactive session from a LocalSystem service.

DIAGNOSTICS ONLY (experiment E1). Two variants:
  as_user=True  -> the logged-on user's own token (WTSQueryUserToken). A workload
                   started this way runs *as the student* and can read their files:
                   never acceptable for UDCS workloads; tested only to answer E1.
  as_user=False -> the service's own SYSTEM token, re-targeted at the session
                   (SetTokenInformation TokenSessionId; needs SeTcbPrivilege).
                   Isolates the *session* variable from the *account* variable.
A production design would use a dedicated low-privilege account's token instead.
"""

from __future__ import annotations

import ctypes
import subprocess
from ctypes import wintypes
from pathlib import Path

from udcs_agent.winplat.api import (
    CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT,
    PROCESS_INFORMATION,
    STARTUPINFOW,
    CloseHandle,
    WinApiError,
)

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
userenv = ctypes.WinDLL("userenv", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_TOKEN_ALL_ACCESS = 0xF01FF
_TokenSessionId = 12
_SecurityImpersonation = 2
_TokenPrimary = 1

advapi32.OpenProcessToken.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
]
advapi32.DuplicateTokenEx.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.POINTER(wintypes.HANDLE),
]
advapi32.SetTokenInformation.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
]
advapi32.CreateProcessAsUserW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.BOOL,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
]
wtsapi32.WTSQueryUserToken.argtypes = [wintypes.ULONG, ctypes.POINTER(wintypes.HANDLE)]
userenv.CreateEnvironmentBlock.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),
    wintypes.HANDLE,
    wintypes.BOOL,
]
userenv.DestroyEnvironmentBlock.argtypes = [ctypes.c_void_p]
kernel32.GetCurrentProcess.restype = wintypes.HANDLE


def _token_for(session_id: int, *, as_user: bool) -> wintypes.HANDLE:
    token = wintypes.HANDLE()
    if as_user:
        if not wtsapi32.WTSQueryUserToken(session_id, ctypes.byref(token)):
            raise WinApiError("WTSQueryUserToken")
        return token
    own = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_ALL_ACCESS, ctypes.byref(own)
    ):
        raise WinApiError("OpenProcessToken")
    try:
        if not advapi32.DuplicateTokenEx(
            own, _TOKEN_ALL_ACCESS, None, _SecurityImpersonation, _TokenPrimary, ctypes.byref(token)
        ):
            raise WinApiError("DuplicateTokenEx")
    finally:
        CloseHandle(own)
    sid = wintypes.DWORD(session_id)
    if not advapi32.SetTokenInformation(
        token, _TokenSessionId, ctypes.byref(sid), ctypes.sizeof(sid)
    ):
        CloseHandle(token)
        raise WinApiError("SetTokenInformation(TokenSessionId)")
    return token


def launch_in_session(
    argv: list[str], session_id: int, *, as_user: bool, cwd: Path, timeout_seconds: float = 120.0
) -> int | None:
    """Start argv in `session_id` inside a kill-on-close job at IDLE priority.

    Returns the exit code, or None if it was killed at the timeout.
    """
    from udcs_agent.winplat.api import CREATE_SUSPENDED, IDLE_PRIORITY_CLASS, ResumeThread
    from udcs_agent.winplat.jobs import JobObject

    token = _token_for(session_id, as_user=as_user)
    job = JobObject()
    environment = ctypes.c_void_p()
    try:
        if not userenv.CreateEnvironmentBlock(ctypes.byref(environment), token, False):
            raise WinApiError("CreateEnvironmentBlock")
        startup = STARTUPINFOW()
        startup.cb = ctypes.sizeof(startup)
        startup.lpDesktop = "winsta0\\default"
        info = PROCESS_INFORMATION()
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
        if not advapi32.CreateProcessAsUserW(
            token,
            argv[0],
            command,
            None,
            None,
            False,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED | IDLE_PRIORITY_CLASS,
            environment,
            str(cwd),
            ctypes.byref(startup),
            ctypes.byref(info),
        ):
            raise WinApiError("CreateProcessAsUserW")
        try:
            job.assign(info.hProcess)  # before it runs: nothing escapes the job
            ResumeThread(info.hThread)
        finally:
            CloseHandle(info.hThread)
        waited = kernel32.WaitForSingleObject(info.hProcess, int(timeout_seconds * 1000))
        code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        CloseHandle(info.hProcess)
        return None if waited == 0x102 else int(code.value)  # WAIT_TIMEOUT -> killed below
    finally:
        job.close()  # kill-on-close: nothing outlives the diagnostic
        if environment:
            userenv.DestroyEnvironmentBlock(environment)
        CloseHandle(token)
