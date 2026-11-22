"""AppContainer (lowbox) process isolation via Win32, for UDCS workloads.

How the boundary works (Windows access checks; verified by the probe tests, not assumed):
- An AppContainer process carries a *package SID* plus capability SIDs, and runs at
  low integrity. Every access check is made twice: once for the normal token, and
  once requiring that the object also grants the package SID, a capability the token
  holds, or ALL APPLICATION PACKAGES. Student profiles, the agent's data directory
  and other users' objects grant none of these, so access is denied by default.
- LPAC ("less privileged AppContainer", ALL_APPLICATION_PACKAGES opt-out) also ignores
  ALL APPLICATION PACKAGES grants, so only explicitly granted paths are reachable,
  plus the system files Windows grants to ALL RESTRICTED APPLICATION PACKAGES.
- No network capability is granted: no internet, no private network, no loopback.
- The token is first restricted (DISABLE_MAX_PRIVILEGE, Administrators deny-only), so
  the workload holds no privilege of its parent. That matters when the parent is
  the LocalSystem service.

Each workload gets its own AppContainer profile, and therefore its own package SID,
so workloads cannot read each other's directories. A shared *capability* SID grants
read/execute on the runtime (interpreter and catalog code) only.
"""

from __future__ import annotations

import ctypes
import subprocess
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from udcs_agent.winplat import api
from udcs_agent.winplat.jobs import JobObject
from udcs_agent.winplat.launch import LaunchedProcess, _environment_block

_userenv = ctypes.WinDLL("userenv", use_last_error=True)
_advapi = ctypes.WinDLL("advapi32", use_last_error=True)
_kernelbase = ctypes.WinDLL("kernelbase", use_last_error=True)
_kernel32 = api.kernel32

PSID = ctypes.c_void_p
RUNTIME_CAPABILITY = "udcsWorkloadRuntime"

PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY = 0x0002000F
PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT = 0x01
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
SE_GROUP_ENABLED = 0x00000004
DISABLE_MAX_PRIVILEGE = 0x1
TOKEN_ALL_NEEDED = 0x0001 | 0x0002 | 0x0008 | 0x0080 | 0x0100  # assign, dup, query, adj default
E_ALREADY_EXISTS = ctypes.c_long(0x800700B7).value
E_NOT_FOUND = ctypes.c_long(0x80070002).value
JobObjectBasicUIRestrictions = 4
UI_RESTRICT_ALL = 0xFF  # handles, clipboard r/w, system params, display, atoms, desktop, exit
READ_EXECUTE = 0x001200A9  # FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
MODIFY = 0x001301BF  # read, write, execute, delete (no WRITE_DAC / WRITE_OWNER)
INHERITED_ACE = 0x10


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", PSID), ("Attributes", wintypes.DWORD)]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", PSID),
        ("Capabilities", ctypes.POINTER(SID_AND_ATTRIBUTES)),
        ("CapabilityCount", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
    ]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", api.STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]


class JOBOBJECT_BASIC_UI_RESTRICTIONS(ctypes.Structure):
    _fields_ = [("UIRestrictionsClass", wintypes.DWORD)]


def _proto(fn, restype, *argtypes):
    fn.restype = restype
    fn.argtypes = list(argtypes)


_proto(
    _userenv.CreateAppContainerProfile,
    ctypes.c_long,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    ctypes.POINTER(SID_AND_ATTRIBUTES),
    wintypes.DWORD,
    ctypes.POINTER(PSID),
)
_proto(
    _userenv.DeriveAppContainerSidFromAppContainerName,
    ctypes.c_long,
    wintypes.LPCWSTR,
    ctypes.POINTER(PSID),
)
_proto(_userenv.DeleteAppContainerProfile, ctypes.c_long, wintypes.LPCWSTR)
_proto(
    _kernelbase.DeriveCapabilitySidsFromName,
    wintypes.BOOL,
    wintypes.LPCWSTR,
    ctypes.POINTER(ctypes.POINTER(PSID)),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(ctypes.POINTER(PSID)),
    ctypes.POINTER(wintypes.DWORD),
)
_proto(_advapi.ConvertSidToStringSidW, wintypes.BOOL, PSID, ctypes.POINTER(wintypes.LPWSTR))
_proto(_advapi.ConvertStringSidToSidW, wintypes.BOOL, wintypes.LPCWSTR, ctypes.POINTER(PSID))
_proto(_advapi.FreeSid, ctypes.c_void_p, PSID)
_proto(
    _advapi.OpenProcessToken,
    wintypes.BOOL,
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.HANDLE),
)
_proto(
    _advapi.CreateRestrictedToken,
    wintypes.BOOL,
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(SID_AND_ATTRIBUTES),
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.HANDLE),
)
_proto(
    _advapi.CreateProcessAsUserW,
    wintypes.BOOL,
    wintypes.HANDLE,
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.BOOL,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.c_void_p,
    ctypes.POINTER(api.PROCESS_INFORMATION),
)
_proto(
    _kernel32.InitializeProcThreadAttributeList,
    wintypes.BOOL,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.POINTER(ctypes.c_size_t),
)
_proto(
    _kernel32.UpdateProcThreadAttribute,
    wintypes.BOOL,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_void_p,
)
_proto(_kernel32.DeleteProcThreadAttributeList, None, ctypes.c_void_p)
_proto(_kernel32.LocalFree, ctypes.c_void_p, ctypes.c_void_p)
_proto(_kernel32.GetCurrentProcess, wintypes.HANDLE)
_proto(
    _kernel32.SetInformationJobObject,
    wintypes.BOOL,
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
)


class AppContainerError(OSError):
    pass


def _hr_check(hr: int, what: str) -> None:
    if hr != 0:
        code = hr & 0xFFFFFFFF
        raise AppContainerError(code, f"{what} failed: HRESULT 0x{code:08X}")


def sid_to_string(sid: int) -> str:
    out = wintypes.LPWSTR()
    api.check(_advapi.ConvertSidToStringSidW(sid, ctypes.byref(out)), "ConvertSidToStringSidW")
    try:
        return out.value or ""
    finally:
        _kernel32.LocalFree(out)


class _Sid:
    """A PSID owned by us (freed with LocalFree)."""

    def __init__(self, text: str) -> None:
        self.ptr = PSID()
        api.check(_advapi.ConvertStringSidToSidW(text, ctypes.byref(self.ptr)), "ConvertStringSid")

    def close(self) -> None:
        if self.ptr:
            _kernel32.LocalFree(self.ptr)
            self.ptr = PSID()


# -- profiles and SIDs ----------------------------------------------------------------------


def ensure_profile(name: str) -> str:
    """Create (or reuse) the AppContainer profile `name`; return its package SID."""
    sid = PSID()
    hr = _userenv.CreateAppContainerProfile(name, name, "UDCS workload", None, 0, ctypes.byref(sid))
    if hr == E_ALREADY_EXISTS:
        _hr_check(
            _userenv.DeriveAppContainerSidFromAppContainerName(name, ctypes.byref(sid)),
            "DeriveAppContainerSidFromAppContainerName",
        )
    else:
        _hr_check(hr, "CreateAppContainerProfile")
    try:
        return sid_to_string(sid.value)
    finally:
        _advapi.FreeSid(sid)


def delete_profile(name: str) -> None:
    hr = _userenv.DeleteAppContainerProfile(name)
    if hr not in (0, E_NOT_FOUND):
        _hr_check(hr, "DeleteAppContainerProfile")


def list_profiles(prefix: str) -> list[str]:
    """AppContainer profiles of the current user whose name starts with `prefix`.
    DeleteAppContainerProfile reports success even for unknown names, so this registry
    mapping is the reliable way to see which profiles exist."""
    import winreg

    key = (
        r"Software\Classes\Local Settings\Software\Microsoft\Windows"
        r"\CurrentVersion\AppContainer\Mappings"
    )
    names: list[str] = []
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as mappings:
            for i in range(winreg.QueryInfoKey(mappings)[0]):
                with winreg.OpenKey(mappings, winreg.EnumKey(mappings, i)) as entry:
                    try:
                        moniker = winreg.QueryValueEx(entry, "Moniker")[0]
                    except OSError:
                        continue
                if isinstance(moniker, str) and moniker.startswith(prefix):
                    names.append(moniker)
    except OSError:
        return []
    return sorted(names)


def capability_sid(name: str) -> str:
    """The capability SID Windows derives from a capability name (stable per name)."""
    groups = ctypes.POINTER(PSID)()
    caps = ctypes.POINTER(PSID)()
    n_groups, n_caps = wintypes.DWORD(), wintypes.DWORD()
    api.check(
        _kernelbase.DeriveCapabilitySidsFromName(
            name,
            ctypes.byref(groups),
            ctypes.byref(n_groups),
            ctypes.byref(caps),
            ctypes.byref(n_caps),
        ),
        "DeriveCapabilitySidsFromName",
    )
    try:
        if n_caps.value < 1:
            raise AppContainerError(0, f"no capability SID derived for {name!r}")
        return sid_to_string(caps[0])
    finally:
        for array, count in ((groups, n_groups.value), (caps, n_caps.value)):
            for i in range(count):
                _kernel32.LocalFree(array[i])
            _kernel32.LocalFree(array)


# -- filesystem grants ----------------------------------------------------------------------


def grant(path: Path, sid: str, access: int) -> None:
    """Add an inheritable allow ACE for `sid` on `path` (directory or file)."""
    import ntsecuritycon as con
    import win32security as ws

    flags = (con.OBJECT_INHERIT_ACE | con.CONTAINER_INHERIT_ACE) if path.is_dir() else 0
    sd = ws.GetNamedSecurityInfo(str(path), ws.SE_FILE_OBJECT, ws.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    target = ws.ConvertStringSidToSid(sid)
    for i in range(dacl.GetAceCount()):
        (_ace_type, ace_flags), mask, ace_sid = dacl.GetAce(i)
        if ace_sid == target and mask == access and not ace_flags & INHERITED_ACE:
            return  # already granted
    dacl.AddAccessAllowedAceEx(ws.ACL_REVISION_DS, flags, access, target)
    ws.SetNamedSecurityInfo(
        str(path), ws.SE_FILE_OBJECT, ws.DACL_SECURITY_INFORMATION, None, None, dacl, None
    )


def revoke(path: Path, sid: str) -> None:
    """Remove every explicit ACE for `sid` from `path` (inherited copies follow)."""
    import win32security as ws

    if not path.exists():
        return
    sd = ws.GetNamedSecurityInfo(str(path), ws.SE_FILE_OBJECT, ws.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    target = ws.ConvertStringSidToSid(sid)
    changed = False
    for i in reversed(range(dacl.GetAceCount())):
        (_ace_type, ace_flags), _mask, ace_sid = dacl.GetAce(i)
        if ace_sid == target and not ace_flags & INHERITED_ACE:
            dacl.DeleteAce(i)
            changed = True
    if changed:
        ws.SetNamedSecurityInfo(
            str(path), ws.SE_FILE_OBJECT, ws.DACL_SECURITY_INFORMATION, None, None, dacl, None
        )


# -- launch ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SandboxSpec:
    package_sid: str
    capability_sids: tuple[str, ...] = ()
    lpac: bool = True  # also ignore ALL APPLICATION PACKAGES grants


def _fix_owner_and_default_dacl(token: int, package_sid: str) -> None:
    """An elevated administrator's (and LocalSystem's) token names the Administrators
    group as owner and in its default DACL. With that group deny-only, the new process
    cannot open its own process and thread objects, so its DLLs fail to initialise
    (0xC0000142, measured on the CI runner). Owner and default DACL are therefore set to
    the user SID, SYSTEM and the workload's own package SID."""
    import ntsecuritycon as con
    import win32security as ws

    user_sid, _attrs = ws.GetTokenInformation(token, ws.TokenUser)
    ws.SetTokenInformation(token, ws.TokenOwner, user_sid)
    dacl = ws.ACL()
    for sid in (
        user_sid,
        ws.ConvertStringSidToSid("S-1-5-18"),
        ws.ConvertStringSidToSid(package_sid),
    ):
        dacl.AddAccessAllowedAce(ws.ACL_REVISION, con.GENERIC_ALL, sid)
    ws.SetTokenInformation(token, ws.TokenDefaultDacl, dacl)


def _restricted_token(package_sid: str | None = None) -> wintypes.HANDLE:
    own = wintypes.HANDLE()
    api.check(
        _advapi.OpenProcessToken(
            _kernel32.GetCurrentProcess(), TOKEN_ALL_NEEDED, ctypes.byref(own)
        ),
        "OpenProcessToken",
    )
    admins = _Sid("S-1-5-32-544")
    try:
        disable = (SID_AND_ATTRIBUTES * 1)(SID_AND_ATTRIBUTES(admins.ptr, 0))
        restricted = wintypes.HANDLE()
        api.check(
            _advapi.CreateRestrictedToken(
                own, DISABLE_MAX_PRIVILEGE, 1, disable, 0, None, 0, None, ctypes.byref(restricted)
            ),
            "CreateRestrictedToken",
        )
        if package_sid is not None:
            try:
                _fix_owner_and_default_dacl(restricted.value, package_sid)
            except Exception:
                api.CloseHandle(restricted)
                raise
        return restricted
    finally:
        admins.close()
        api.CloseHandle(own)


# -- private window station / desktop -------------------------------------------------------
#
# AppContainer processes need access to the window station and desktop they start on, or
# user32 initialisation fails (STATUS_DLL_INIT_FAILED, 0xC0000142). The interactive
# WinSta0 grants AppContainers access; a service's session-0 window station does not.
# CI (a service-hosted runner) hit exactly this. So workloads get their own window
# station and desktop where possible, and a private desktop otherwise, with access granted
# only to the UDCS runtime capability. They are then also off the student's desktop.

_user32 = ctypes.WinDLL("user32", use_last_error=True)
_proto(
    _user32.CreateWindowStationW,
    wintypes.HANDLE,
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
)
_proto(_user32.GetProcessWindowStation, wintypes.HANDLE)
_proto(_user32.SetProcessWindowStation, wintypes.BOOL, wintypes.HANDLE)
_proto(
    _user32.CreateDesktopW,
    wintypes.HANDLE,
    wintypes.LPCWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
)
_proto(
    _user32.GetUserObjectInformationW,
    wintypes.BOOL,
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
)
_WINSTA_ALL = 0x37F | 0x000F0000
_DESKTOP_ALL = 0x01FF | 0x000F0000
# What a windowless workload needs: enough for user32/gdi32 initialisation, no more.
# Shared (service) window station: enumdesktops, readattributes, global atoms, enumerate,
# READ_CONTROL. No clipboard, no screen reading, no desktop creation.
_WINSTA_FOR_WORKLOADS = 0x0001 | 0x0002 | 0x0020 | 0x0100 | 0x00020000
# Only UDCS workloads live on this private desktop, so they get full rights to it (user32
# initialisation failed with narrower masks, measured). Nothing of the student or service.
_DESKTOP_FOR_WORKLOADS = _DESKTOP_ALL
_desktop_state: dict[str, object] = {}


def _object_name(handle: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    needed = wintypes.DWORD()
    api.check(
        _user32.GetUserObjectInformationW(handle, 2, buf, ctypes.sizeof(buf), ctypes.byref(needed)),
        "GetUserObjectInformationW",
    )
    return buf.value


def _grant_window_object(handle: int, sid: str, mask: int) -> None:
    import win32security as ws

    sd = ws.GetSecurityInfo(int(handle), ws.SE_WINDOW_OBJECT, ws.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    dacl.AddAccessAllowedAce(ws.ACL_REVISION, mask, ws.ConvertStringSidToSid(sid))
    ws.SetSecurityInfo(
        int(handle), ws.SE_WINDOW_OBJECT, ws.DACL_SECURITY_INFORMATION, None, None, dacl, None
    )


def workload_desktop(capability: str, *, name: str = "UDCSWorkloads") -> str:
    """`winsta\\desktop` for workloads, created once per process. Handles stay open for
    the life of the agent (closing the last one destroys the object)."""
    cached = _desktop_state.get("path")
    if isinstance(cached, str):
        return cached
    winsta = _user32.CreateWindowStationW(name, 0, _WINSTA_ALL, None)
    own_winsta = bool(winsta)
    if own_winsta:  # LocalSystem (the service): a private window station
        _grant_window_object(winsta, capability, _WINSTA_ALL)  # holds only workloads
        previous = _user32.GetProcessWindowStation()
        api.check(_user32.SetProcessWindowStation(winsta), "SetProcessWindowStation")
        try:
            desktop = _user32.CreateDesktopW("Workloads", None, None, 0, _DESKTOP_ALL, None)
        finally:
            _user32.SetProcessWindowStation(previous)
        station_name = name
    else:  # no right to create window stations: a private desktop on the current one
        current = _user32.GetProcessWindowStation()
        station_name = _object_name(current)
        if station_name.lower() != "winsta0":
            # A service's window station (e.g. Service-0x0-3e7$) grants AppContainers
            # nothing. The interactive WinSta0 already does, and the student's window
            # station is never modified.
            _grant_window_object(current, capability, _WINSTA_FOR_WORKLOADS)
        desktop = _user32.CreateDesktopW(name, None, None, 0, _DESKTOP_ALL, None)
    if not desktop:
        raise api.WinApiError("CreateDesktopW")
    _grant_window_object(desktop, capability, _DESKTOP_FOR_WORKLOADS)
    path = f"{station_name}\\{'Workloads' if own_winsta else name}"
    _desktop_state.update(path=path, winsta=winsta, desktop=desktop, private_station=own_winsta)
    return path


def set_ui_restrictions(job: JobObject) -> None:
    """No clipboard, desktop, global atoms or handles of other processes' windows."""
    limits = JOBOBJECT_BASIC_UI_RESTRICTIONS(UI_RESTRICT_ALL)
    api.check(
        _kernel32.SetInformationJobObject(
            job.handle, JobObjectBasicUIRestrictions, ctypes.byref(limits), ctypes.sizeof(limits)
        ),
        "SetInformationJobObject(UI restrictions)",
    )


def launch_in_appcontainer(
    argv: list[str],
    job: JobObject,
    sandbox: SandboxSpec,
    *,
    cwd: Path,
    env: dict[str, str],
    memory_priority: int = api.MEMORY_PRIORITY_VERY_LOW,
    desktop: str | None = None,
) -> LaunchedProcess:
    """Create the process suspended, inside the AppContainer *and* the job, then resume.
    Any failure raises: there is no fallback to an unrestricted process."""
    if not argv or not Path(argv[0]).is_absolute():
        raise ValueError("argv[0] must be an absolute executable path (no PATH search)")
    # Windows derives the container's own folder from these. Without them process creation
    # fails with ERROR_ENVVAR_NOT_FOUND (203), measured on build 22000. They name the
    # *parent's* profile; the container still cannot access it (no grant to its SID).
    import os

    env = dict(env)
    for key in ("USERPROFILE", "LOCALAPPDATA"):
        if key not in env and key in os.environ:
            env[key] = os.environ[key]
    package = _Sid(sandbox.package_sid)
    caps = [_Sid(s) for s in sandbox.capability_sids]
    token = _restricted_token(sandbox.package_sid)
    attr_list = None
    info = api.PROCESS_INFORMATION()
    try:
        cap_array = (SID_AND_ATTRIBUTES * max(1, len(caps)))(
            *[SID_AND_ATTRIBUTES(c.ptr, SE_GROUP_ENABLED) for c in caps]
        )
        security = SECURITY_CAPABILITIES(package.ptr, cap_array if caps else None, len(caps), 0)
        opt_out = wintypes.DWORD(PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT)
        count = 2 if sandbox.lpac else 1
        size = ctypes.c_size_t()
        _kernel32.InitializeProcThreadAttributeList(None, count, 0, ctypes.byref(size))
        attr_list = ctypes.create_string_buffer(size.value)
        api.check(
            _kernel32.InitializeProcThreadAttributeList(attr_list, count, 0, ctypes.byref(size)),
            "InitializeProcThreadAttributeList",
        )
        api.check(
            _kernel32.UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                ctypes.byref(security),
                ctypes.sizeof(security),
                None,
                None,
            ),
            "UpdateProcThreadAttribute(security capabilities)",
        )
        if sandbox.lpac:
            api.check(
                _kernel32.UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                    ctypes.byref(opt_out),
                    ctypes.sizeof(opt_out),
                    None,
                    None,
                ),
                "UpdateProcThreadAttribute(LPAC)",
            )
        startup = STARTUPINFOEXW()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.lpAttributeList = ctypes.cast(attr_list, ctypes.c_void_p)
        desktop_name = ctypes.create_unicode_buffer(desktop) if desktop else None
        if desktop_name is not None:
            startup.StartupInfo.lpDesktop = ctypes.cast(desktop_name, wintypes.LPWSTR)
        command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
        block = _environment_block(env)
        flags = (
            api.CREATE_SUSPENDED
            | api.CREATE_NO_WINDOW
            | api.CREATE_NEW_PROCESS_GROUP
            | api.CREATE_UNICODE_ENVIRONMENT
            | api.IDLE_PRIORITY_CLASS
            | EXTENDED_STARTUPINFO_PRESENT
        )
        api.check(
            _advapi.CreateProcessAsUserW(
                token,
                argv[0],
                command_line,
                None,
                None,
                False,  # no handle inheritance
                flags,
                ctypes.cast(block, ctypes.c_void_p),
                str(cwd),
                ctypes.byref(startup),
                ctypes.byref(info),
            ),
            "CreateProcessAsUserW(AppContainer)",
        )
    finally:
        if attr_list is not None:
            _kernel32.DeleteProcThreadAttributeList(attr_list)
        api.CloseHandle(token)
        package.close()
        for c in caps:
            c.close()
    try:
        job.assign(info.hProcess)
        api.SetProcessPriorityBoost(info.hProcess, True)
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
        api.TerminateProcess(info.hProcess, 1)
        api.TerminateJobObject(job.handle, 1)
        api.CloseHandle(info.hProcess)
        raise
    finally:
        api.CloseHandle(info.hThread)
    return LaunchedProcess(pid=int(info.dwProcessId), handle=info.hProcess)
