"""Runs *inside* a UDCS AppContainer and records what it can reach (exposure audit).

Standard library only; it executes from the isolated runtime directory.

    python -I -S -c "...from exposure_probe import main..." PLAN.json RESULT.json

It never modifies anything it finds:
- filesystem write access is tested by opening the directory with FILE_ADD_FILE or
  FILE_ADD_SUBDIRECTORY, never by creating a file;
- registry write access by opening the key with KEY_SET_VALUE or KEY_CREATE_SUB_KEY;
- processes, services and objects by opening a handle with a given right, then closing.

Only successes are recorded as findings; denials are counted in `coverage`. The probe
makes no judgement: udcs_shared.exposure.violations() does.
"""

from __future__ import annotations

import ctypes
import json
import os
import socket
import sys
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

INVALID = wintypes.HANDLE(-1).value
k32.CreateFileW.restype = wintypes.HANDLE
k32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
k32.CloseHandle.argtypes = [wintypes.HANDLE]
k32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
user32.GetProcessWindowStation.restype = wintypes.HANDLE
user32.GetUserObjectInformationW.argtypes = [
    wintypes.HANDLE,
    ctypes.c_int,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
for name in ("OpenMutexW", "OpenEventW", "OpenSemaphoreW"):
    getattr(k32, name).restype = wintypes.HANDLE
    getattr(k32, name).argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
k32.OpenFileMappingW.restype = wintypes.HANDLE
k32.OpenFileMappingW.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.LPCWSTR]
adv.OpenSCManagerW.restype = wintypes.HANDLE
adv.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
adv.OpenServiceW.restype = wintypes.HANDLE
adv.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
adv.CloseServiceHandle.argtypes = [wintypes.HANDLE]
user32.OpenWindowStationW.restype = wintypes.HANDLE
user32.OpenWindowStationW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL, wintypes.DWORD]
user32.OpenDesktopW.restype = wintypes.HANDLE
user32.OpenDesktopW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
user32.GetClipboardData.restype = wintypes.HANDLE

SHARE_ALL = 0x7
OPEN_EXISTING = 3
BACKUP_SEMANTICS = 0x02000000
OPEN_REPARSE = 0x00200000
FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY = 0x2, 0x4
PROCESS_RIGHTS = {
    "query": 0x1000,
    "terminate": 0x0001,
    "create_thread": 0x0002,
    "vm_read": 0x0010,
    "vm_write": 0x0020,
    "dup_handle": 0x0040,
}
SERVICE_RIGHTS = {
    "query": 0x0004,
    "start": 0x0010,
    "stop": 0x0020,
    "change_config": 0x0002,
    "write_dac": 0x40000,
}


class Probe:
    def __init__(self, plan: dict) -> None:
        self.plan = plan
        self.findings: list[dict] = []
        self.coverage: dict[str, int] = {}
        self.truncated: set[str] = set()
        self.errors: list[str] = []
        self.deadline = time.monotonic() + float(plan.get("deadline_seconds", 300))
        self.skip = [p.lower().rstrip("\\") for p in plan.get("skip_prefixes", [])]

    def add(self, category, target, access, *, sensitive=False, detail=""):
        self.findings.append(
            {
                "category": category,
                "target": str(target)[:1024],
                "access": access,
                "sensitive": bool(sensitive),
                "detail": str(detail)[:300],
            }
        )

    def count(self, category: str, n: int = 1) -> None:
        self.coverage[category] = self.coverage.get(category, 0) + n

    def out_of_time(self, category: str) -> bool:
        if time.monotonic() > self.deadline:
            self.truncated.add(category)
            return True
        return False

    # -- filesystem --------------------------------------------------------------------

    def _skipped(self, path: str) -> bool:
        low = path.lower().rstrip("\\")
        return any(low == s or low.startswith(s + "\\") for s in self.skip)

    def _sensitive(self, path: str) -> bool:
        low = path.lower().rstrip("\\")
        return any(
            low == s or low.startswith(s + "\\")
            for s in (p.lower().rstrip("\\") for p in self.plan.get("sensitive_fs", []))
        )

    def _dir_access(self, path: str, right: int) -> bool:
        handle = k32.CreateFileW(
            path, right, SHARE_ALL, None, OPEN_EXISTING, BACKUP_SEMANTICS | OPEN_REPARSE, None
        )
        if handle in (None, INVALID):
            return False
        k32.CloseHandle(handle)
        return True

    def filesystem(self) -> None:
        max_dirs = int(self.plan.get("max_dirs", 50_000))
        seen = 0
        for root, depth in self.plan.get("fs_roots", []):
            stack = [(root, 0)]
            while stack:
                if self.out_of_time("filesystem"):
                    return
                path, level = stack.pop()
                if self._skipped(path):
                    continue
                seen += 1
                if seen > max_dirs:
                    self.truncated.add("filesystem")
                    return
                self.count("filesystem")
                sensitive = self._sensitive(path)
                for access, right in (
                    ("add_file", FILE_ADD_FILE),
                    ("add_subdirectory", FILE_ADD_SUBDIRECTORY),
                ):
                    if self._dir_access(path, right):
                        self.add("filesystem", path, access, sensitive=sensitive)
                try:
                    with os.scandir(path) as listing:
                        entries = list(listing)
                except OSError:
                    continue
                self.add("filesystem", path, "list", sensitive=sensitive)
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if level < depth:
                                stack.append((entry.path, level + 1))
                        elif sensitive:
                            self._read_file(entry.path)
                    except OSError:
                        continue

    def _read_file(self, path: str) -> None:
        self.count("filesystem_files")
        try:
            with open(path, "rb") as handle:
                handle.read(1)
        except OSError:
            return
        self.add("filesystem", path, "read", sensitive=True)

    # -- registry ----------------------------------------------------------------------

    def registry(self) -> None:
        import winreg

        roots = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKU": winreg.HKEY_USERS,
            "HKCU": winreg.HKEY_CURRENT_USER,
        }
        sensitive = [s.lower() for s in self.plan.get("sensitive_reg", [])]
        max_keys = int(self.plan.get("max_keys", 50_000))
        seen = 0
        for hive, base, depth in self.plan.get("reg_roots", []):
            stack = [(base, 0)]
            while stack:
                if self.out_of_time("registry"):
                    return
                path, level = stack.pop()
                seen += 1
                if seen > max_keys:
                    self.truncated.add("registry")
                    return
                self.count("registry")
                name = f"{hive}\\{path}" if path else hive
                is_sensitive = any(
                    name.lower() == s or name.lower().startswith(s + "\\") for s in sensitive
                )
                # An empty subkey returns the predefined root handle itself, without an
                # access check (measured: a false "writable HKU/HKCU"). Roots are only
                # enumerated; their subkeys are checked.
                if path:
                    for access, right in (
                        ("set_value", winreg.KEY_SET_VALUE),
                        ("create_subkey", winreg.KEY_CREATE_SUB_KEY),
                    ):
                        try:
                            winreg.OpenKey(roots[hive], path, 0, right).Close()
                            self.add("registry", name, access, sensitive=is_sensitive)
                        except OSError:
                            pass
                try:
                    key = winreg.OpenKey(roots[hive], path, 0, winreg.KEY_READ)
                except OSError:
                    continue
                with key:
                    if path:
                        self.add("registry", name, "read", sensitive=is_sensitive)
                    if level < depth:
                        i = 0
                        while True:
                            try:
                                sub = winreg.EnumKey(key, i)
                            except OSError:
                                break
                            stack.append((f"{path}\\{sub}" if path else sub, level + 1))
                            i += 1
        for hive, path, value in self.plan.get("sensitive_values", []):
            self.count("registry_values")
            try:
                with winreg.OpenKey(roots[hive], path, 0, winreg.KEY_QUERY_VALUE) as key:
                    winreg.QueryValueEx(key, value)
                self.add("registry", f"{hive}\\{path}\\{value}", "read_value", sensitive=True)
            except OSError:
                pass

    # -- processes ---------------------------------------------------------------------

    def processes(self) -> None:
        pids = set(self.plan.get("pids", []))
        array = (wintypes.DWORD * 8192)()
        needed = wintypes.DWORD()
        if psapi.EnumProcesses(array, ctypes.sizeof(array), ctypes.byref(needed)):
            pids.update(array[i] for i in range(needed.value // 4))
        me = os.getpid()
        for pid in sorted(pids):
            if pid in (0, me) or self.out_of_time("process"):
                continue
            self.count("process")
            if _same_container(pid):
                continue  # the sandbox's own processes (e.g. its conhost.exe), not a leak
            image = self.plan.get("pid_names", {}).get(str(pid)) or _image_name(pid)
            for access, right in PROCESS_RIGHTS.items():
                handle = k32.OpenProcess(right, False, pid)
                if handle:
                    k32.CloseHandle(handle)
                    self.add("process", f"pid {pid}", access, detail=image)

    # -- IPC: named pipes and named objects ----------------------------------------------

    def _sensitive_name(self, name: str) -> bool:
        low = name.lower()
        return any(word in low for word in self.plan.get("sensitive_words", []))

    def pipes(self) -> None:
        for name in self.plan.get("pipes", []):
            if self.out_of_time("pipe"):
                return
            self.count("pipe")
            path = "\\\\.\\pipe\\" + name
            handle = k32.CreateFileW(
                path, 0x80000000, 0, None, OPEN_EXISTING, 0, None
            )  # GENERIC_READ
            if handle not in (None, INVALID):
                k32.CloseHandle(handle)
                self.add("pipe", name, "connect", sensitive=self._sensitive_name(name))
            elif (
                ctypes.get_last_error() == 231
            ):  # ERROR_PIPE_BUSY: access allowed, no instance free
                self.add(
                    "pipe", name, "connect", sensitive=self._sensitive_name(name), detail="busy"
                )

    def objects(self) -> None:
        openers = {
            "Mutant": lambda n: k32.OpenMutexW(0x100000, False, n),  # SYNCHRONIZE
            "Event": lambda n: k32.OpenEventW(0x100000, False, n),
            "Semaphore": lambda n: k32.OpenSemaphoreW(0x100000, False, n),
            "Section": lambda n: k32.OpenFileMappingW(0x4, False, n),  # FILE_MAP_READ
        }
        for kind, name in self.plan.get("objects", []):
            opener = openers.get(kind)
            if opener is None or self.out_of_time("object"):
                continue
            self.count("object")
            handle = opener("Global\\" + name)
            if handle:
                k32.CloseHandle(handle)
                self.add(
                    "object",
                    f"Global\\{name}",
                    "open",
                    sensitive=self._sensitive_name(name),
                    detail=kind,
                )

    # -- network, services, interactive session ------------------------------------------

    def network(self) -> None:
        for host, port in [*self.plan.get("ports", []), *self.plan.get("external", [])]:
            if self.out_of_time("network"):
                return
            self.count("network")
            try:
                with socket.create_connection((host, int(port)), timeout=1.5):
                    self.add("network", f"{host}:{port}", "connect")
            except OSError:
                pass
        try:
            socket.getaddrinfo(self.plan.get("dns_name", "example.com"), 443)
            self.add("network", "dns", "resolve")
        except OSError:
            pass
        self.count("network")

    def services(self) -> None:
        scm = adv.OpenSCManagerW(None, None, 0x0001)  # SC_MANAGER_CONNECT
        if not scm:
            self.count("service")
            return
        try:
            for name in self.plan.get("services", []):
                if self.out_of_time("service"):
                    return
                self.count("service")
                for access, right in SERVICE_RIGHTS.items():
                    handle = adv.OpenServiceW(scm, name, right)
                    if handle:
                        adv.CloseServiceHandle(handle)
                        self.add("service", name, access)
        finally:
            adv.CloseServiceHandle(scm)

    def interactive(self) -> None:
        self.count("window", 3)
        self.own_station = _station_name()
        station = user32.OpenWindowStationW("WinSta0", False, 0x0001 | 0x0002)
        if station:
            user32.CloseWindowStation(station)
            self.add("window", "WinSta0", "open", detail=f"sandbox station {self.own_station}")
        desktop = user32.OpenDesktopW("Default", 0, False, 0x0001 | 0x0040)
        if desktop:
            user32.CloseDesktop(desktop)
            # OpenDesktopW opens on the sandbox's own window station. It matters only if
            # that station is the interactive WinSta0, where Default is the student's.
            if self.own_station.lower() == "winsta0":
                self.add("window", "WinSta0\\Default", "open", detail="sandbox shares WinSta0")
        if user32.OpenClipboard(None):
            try:
                if user32.GetClipboardData(13):  # CF_UNICODETEXT
                    self.add("window", "clipboard", "read")
            finally:
                user32.CloseClipboard()

    def run(self) -> dict:
        from isolation_probe import _token  # shipped beside this file in the runtime

        result: dict = {}
        try:
            result["token"] = _token()
        except Exception as exc:  # noqa: BLE001 -- recorded, not fatal
            self.errors.append(f"token: {type(exc).__name__}: {exc}")
            result["token"] = {}
        for step in (
            self.filesystem,
            self.registry,
            self.processes,
            self.pipes,
            self.objects,
            self.network,
            self.services,
            self.interactive,
        ):
            try:
                step()
            except Exception as exc:  # noqa: BLE001 -- one failing category must not hide the rest
                self.errors.append(f"{step.__name__}: {type(exc).__name__}: {exc}"[:300])
                self.truncated.add(step.__name__)
        result.update(
            window_station=getattr(self, "own_station", ""),
            findings=self.findings,
            coverage=self.coverage,
            truncated=sorted(self.truncated),
            errors=self.errors,
        )
        return result


def _image_name(pid: int) -> str:
    handle = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return ""
    try:
        buffer = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(1024)
        if k32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value
        return ""
    finally:
        k32.CloseHandle(handle)


def _container_sid(token) -> bytes | None:
    """The AppContainer SID of a token (TokenAppContainerSid), as raw bytes."""
    size = wintypes.DWORD()
    adv.GetTokenInformation(token, 31, None, 0, ctypes.byref(size))
    if not size.value:
        return None
    buffer = ctypes.create_string_buffer(size.value)
    if not adv.GetTokenInformation(token, 31, buffer, size, ctypes.byref(size)):
        return None
    sid = ctypes.c_void_p.from_buffer(buffer).value
    if not sid:
        return None
    length = adv.GetLengthSid(ctypes.c_void_p(sid))
    return ctypes.string_at(sid, length)


_OWN_SID: list = []


def _same_container(pid: int) -> bool:
    adv.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    adv.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    adv.GetLengthSid.argtypes = [ctypes.c_void_p]
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    if not _OWN_SID:
        token = wintypes.HANDLE()
        adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008, ctypes.byref(token))
        _OWN_SID.append(_container_sid(token))
        k32.CloseHandle(token)
    handle = k32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        token = wintypes.HANDLE()
        if not adv.OpenProcessToken(handle, 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
            return False
        try:
            other = _container_sid(token)
        finally:
            k32.CloseHandle(token)
    finally:
        k32.CloseHandle(handle)
    return other is not None and other == _OWN_SID[0]


def _station_name() -> str:
    station = user32.GetProcessWindowStation()
    buffer = ctypes.create_unicode_buffer(256)
    needed = wintypes.DWORD()
    if user32.GetUserObjectInformationW(
        station, 2, buffer, ctypes.sizeof(buffer), ctypes.byref(needed)
    ):
        return buffer.value  # UOI_NAME
    return ""


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    plan = json.loads(open(args[0], encoding="utf-8").read())
    result = Probe(plan).run()
    with open(args[1], "w", encoding="utf-8") as handle:
        json.dump(result, handle)
    return 0
