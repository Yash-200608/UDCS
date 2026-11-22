"""Win32 structures and function prototypes (kernel32, wtsapi32, pdh)."""

from __future__ import annotations

import ctypes
from ctypes import wintypes

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

HANDLE = wintypes.HANDLE
DWORD = wintypes.DWORD
BOOL = wintypes.BOOL
LARGE_INTEGER = ctypes.c_longlong
ULONGLONG = ctypes.c_ulonglong
SIZE_T = ctypes.c_size_t
ULONG_PTR = ctypes.c_size_t


class WinApiError(OSError):
    def __init__(self, function: str, code: int | None = None) -> None:
        code = ctypes.get_last_error() if code is None else code
        super().__init__(code, f"{function} failed: {ctypes.FormatError(code).strip()} ({code})")
        self.function = function
        self.code = code


def check(result: int, function: str) -> int:
    if not result:
        raise WinApiError(function)
    return result


# --- processes / threads -------------------------------------------------------

CREATE_SUSPENDED = 0x00000004
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_UNICODE_ENVIRONMENT = 0x00000400
CREATE_NO_WINDOW = 0x08000000
IDLE_PRIORITY_CLASS = 0x00000040
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000

PROCESS_TERMINATE = 0x0001
PROCESS_SET_QUOTA = 0x0100
PROCESS_SET_INFORMATION = 0x0200
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
THREAD_SUSPEND_RESUME = 0x0002
TH32CS_SNAPTHREAD = 0x00000004
INVALID_HANDLE_VALUE = HANDLE(-1).value


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", DWORD),
        ("cntUsage", DWORD),
        ("th32ThreadID", DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", DWORD),
    ]


class MEMORY_PRIORITY_INFORMATION(ctypes.Structure):
    _fields_ = [("MemoryPriority", wintypes.ULONG)]


ProcessMemoryPriority = 0
MEMORY_PRIORITY_VERY_LOW = 1
MEMORY_PRIORITY_LOW = 2

# --- job objects -------------------------------------------------------------

JobObjectBasicAccountingInformation = 1
JobObjectBasicProcessIdList = 3
JobObjectBasicAndIoAccountingInformation = 8
JobObjectExtendedLimitInformation = 9
JobObjectCpuRateControlInformation = 15

JOB_OBJECT_LIMIT_PRIORITY_CLASS = 0x00000020
JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x1
JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        (n, ULONGLONG)
        for n in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", LARGE_INTEGER),
        ("PerJobUserTimeLimit", LARGE_INTEGER),
        ("LimitFlags", DWORD),
        ("MinimumWorkingSetSize", SIZE_T),
        ("MaximumWorkingSetSize", SIZE_T),
        ("ActiveProcessLimit", DWORD),
        ("Affinity", ULONG_PTR),
        ("PriorityClass", DWORD),
        ("SchedulingClass", DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", SIZE_T),
        ("JobMemoryLimit", SIZE_T),
        ("PeakProcessMemoryUsed", SIZE_T),
        ("PeakJobMemoryUsed", SIZE_T),
    ]


class JOBOBJECT_BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", LARGE_INTEGER),
        ("TotalKernelTime", LARGE_INTEGER),
        ("ThisPeriodTotalUserTime", LARGE_INTEGER),
        ("ThisPeriodTotalKernelTime", LARGE_INTEGER),
        ("TotalPageFaultCount", DWORD),
        ("TotalProcesses", DWORD),
        ("ActiveProcesses", DWORD),
        ("TotalTerminatedProcesses", DWORD),
    ]


class JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION(ctypes.Structure):
    _fields_ = [("BasicInfo", JOBOBJECT_BASIC_ACCOUNTING_INFORMATION), ("IoInfo", IO_COUNTERS)]


class JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(ctypes.Structure):
    # The union's CpuRate member (1/100 of a percent of *all* processors).
    _fields_ = [("ControlFlags", DWORD), ("CpuRate", DWORD)]


class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD),
        ("CommitTotal", SIZE_T),
        ("CommitLimit", SIZE_T),
        ("CommitPeak", SIZE_T),
        ("PhysicalTotal", SIZE_T),
        ("PhysicalAvailable", SIZE_T),
        ("SystemCache", SIZE_T),
        ("KernelTotal", SIZE_T),
        ("KernelPaged", SIZE_T),
        ("KernelNonpaged", SIZE_T),
        ("PageSize", SIZE_T),
        ("HandleCount", DWORD),
        ("ProcessCount", DWORD),
        ("ThreadCount", DWORD),
    ]


def _proto(fn, restype, *argtypes):
    fn.restype = restype
    fn.argtypes = list(argtypes)
    return fn


CreateJobObjectW = _proto(kernel32.CreateJobObjectW, HANDLE, ctypes.c_void_p, wintypes.LPCWSTR)
SetInformationJobObject = _proto(
    kernel32.SetInformationJobObject, BOOL, HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD
)
QueryInformationJobObject = _proto(
    kernel32.QueryInformationJobObject,
    BOOL,
    HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    DWORD,
    ctypes.POINTER(DWORD),
)
AssignProcessToJobObject = _proto(kernel32.AssignProcessToJobObject, BOOL, HANDLE, HANDLE)
TerminateJobObject = _proto(kernel32.TerminateJobObject, BOOL, HANDLE, wintypes.UINT)
IsProcessInJob = _proto(kernel32.IsProcessInJob, BOOL, HANDLE, HANDLE, ctypes.POINTER(BOOL))
CloseHandle = _proto(kernel32.CloseHandle, BOOL, HANDLE)
CreateProcessW = _proto(
    kernel32.CreateProcessW,
    BOOL,
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    BOOL,
    DWORD,
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
)
ResumeThread = _proto(kernel32.ResumeThread, DWORD, HANDLE)
SuspendThread = _proto(kernel32.SuspendThread, DWORD, HANDLE)
OpenThread = _proto(kernel32.OpenThread, HANDLE, DWORD, BOOL, DWORD)
CreateToolhelp32Snapshot = _proto(kernel32.CreateToolhelp32Snapshot, HANDLE, DWORD, DWORD)
Thread32First = _proto(kernel32.Thread32First, BOOL, HANDLE, ctypes.POINTER(THREADENTRY32))
Thread32Next = _proto(kernel32.Thread32Next, BOOL, HANDLE, ctypes.POINTER(THREADENTRY32))
SetProcessPriorityBoost = _proto(kernel32.SetProcessPriorityBoost, BOOL, HANDLE, BOOL)
SetPriorityClass = _proto(kernel32.SetPriorityClass, BOOL, HANDLE, DWORD)
SetProcessInformation = _proto(
    kernel32.SetProcessInformation, BOOL, HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD
)
TerminateProcess = _proto(kernel32.TerminateProcess, BOOL, HANDLE, wintypes.UINT)
GetExitCodeProcess = _proto(kernel32.GetExitCodeProcess, BOOL, HANDLE, ctypes.POINTER(DWORD))
WaitForSingleObject = _proto(kernel32.WaitForSingleObject, DWORD, HANDLE, DWORD)
ProcessIdToSessionId = _proto(kernel32.ProcessIdToSessionId, BOOL, DWORD, ctypes.POINTER(DWORD))
GetCurrentProcess = _proto(kernel32.GetCurrentProcess, HANDLE)
GetCurrentProcessId = _proto(kernel32.GetCurrentProcessId, DWORD)

psapi = ctypes.WinDLL("psapi", use_last_error=True)
GetPerformanceInfo = _proto(
    psapi.GetPerformanceInfo, BOOL, ctypes.POINTER(PERFORMANCE_INFORMATION), DWORD
)

STILL_ACTIVE = 259
WAIT_TIMEOUT = 0x102


def current_session_id() -> int:
    session = DWORD()
    check(
        ProcessIdToSessionId(GetCurrentProcessId(), ctypes.byref(session)), "ProcessIdToSessionId"
    )
    return session.value


def performance_info() -> PERFORMANCE_INFORMATION:
    info = PERFORMANCE_INFORMATION()
    info.cb = ctypes.sizeof(info)
    check(GetPerformanceInfo(ctypes.byref(info), info.cb), "GetPerformanceInfo")
    return info
