"""Runs *inside* a sandbox and tries what a hostile workload would try.

Standard library only: it executes from the isolated runtime directory, with no
access to the agent package.

    python -I -S -c "...from isolation_probe import main..." PLAN.json RESULT.json

The plan lists the operations to attempt. The result records, for each one, whether
it succeeded and the error if not. The probe makes no judgement; the self-test
compares the results with the expected outcomes.
"""

from __future__ import annotations

import ctypes
import json
import os
import socket
import subprocess
import sys
import time
from ctypes import wintypes


def _attempt(fn) -> dict:
    try:
        detail = fn()
        return {"ok": True, "detail": str(detail)[:200] if detail is not None else ""}
    except Exception as exc:  # noqa: BLE001 -- every failure is a result here
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}


def _read(path: str):
    with open(path, "rb") as handle:
        return len(handle.read(64))


def _write(path: str):
    with open(path, "ab") as handle:
        handle.write(b"probe\n")
    return "written"


def _list(path: str):
    return len(os.listdir(path))


def _connect(host: str, port: int):
    with socket.create_connection((host, port), timeout=3):
        return "connected"


def _resolve(name: str):
    return socket.gethostbyname(name)


def _open_process(pid: int, access: int):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(access, False, pid)
    if not handle:
        raise OSError(ctypes.get_last_error(), "OpenProcess denied")
    kernel32.CloseHandle(handle)
    return "opened"


def _registry(hive: str, key: str, value: str):
    import winreg

    root = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}[hive]
    with winreg.OpenKey(root, key) as handle:
        return winreg.QueryValueEx(handle, value)[0]


def _token() -> dict:
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p]
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    token = wintypes.HANDLE()
    advapi.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token))

    def info(cls: int):
        size = wintypes.DWORD()
        advapi.GetTokenInformation(token, cls, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(max(size.value, 4))
        if not advapi.GetTokenInformation(token, cls, buf, size, ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation")
        return buf

    is_app = int.from_bytes(info(29).raw[:4], "little")  # TokenIsAppContainer
    raw = info(3).raw  # TokenPrivileges: DWORD count, then LUID_AND_ATTRIBUTES[]
    count = int.from_bytes(raw[:4], "little")
    privileges = []
    advapi.LookupPrivilegeNameW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.LPWSTR,
        ctypes.c_void_p,
    ]
    for i in range(count):
        offset = 4 + i * 12
        luid = ctypes.create_string_buffer(raw[offset : offset + 8], 8)
        attrs = int.from_bytes(raw[offset + 8 : offset + 12], "little")
        name = ctypes.create_unicode_buffer(64)
        size = wintypes.DWORD(64)
        advapi.LookupPrivilegeNameW(None, luid, name, ctypes.byref(size))
        privileges.append({"name": name.value, "enabled": bool(attrs & 0x2)})
    il = info(25)  # TokenIntegrityLevel: SID_AND_ATTRIBUTES; the SID's last RID is the level
    sid_ptr = ctypes.c_void_p.from_buffer(il).value
    advapi.GetSidSubAuthorityCount.argtypes = [ctypes.c_void_p]
    advapi.GetSidSubAuthorityCount.restype = ctypes.POINTER(ctypes.c_ubyte)
    advapi.GetSidSubAuthority.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    advapi.GetSidSubAuthority.restype = ctypes.POINTER(wintypes.DWORD)
    n = advapi.GetSidSubAuthorityCount(sid_ptr).contents.value
    rid = advapi.GetSidSubAuthority(sid_ptr, n - 1).contents.value
    kernel32.CloseHandle(token)
    return {"is_appcontainer": bool(is_app), "integrity_rid": rid, "privileges": privileges}


def _cuda():
    nvcuda = ctypes.WinDLL("nvcuda")
    result = nvcuda.cuInit(0)
    if result != 0:
        raise OSError(result, f"cuInit returned {result}")
    count = ctypes.c_int()
    nvcuda.cuDeviceGetCount(ctypes.byref(count))
    return f"devices={count.value}"


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    with open(args[0], encoding="utf-8") as handle:
        plan = json.load(handle)
    results: dict[str, dict] = {}
    for name, path in plan.get("read", {}).items():
        results[f"read:{name}"] = _attempt(lambda p=path: _read(p))
    for name, path in plan.get("write", {}).items():
        results[f"write:{name}"] = _attempt(lambda p=path: _write(p))
    for name, path in plan.get("list", {}).items():
        results[f"list:{name}"] = _attempt(lambda p=path: _list(p))
    for name, (host, port) in plan.get("connect", {}).items():
        results[f"connect:{name}"] = _attempt(lambda h=host, p=port: _connect(h, p))
    for name, host in plan.get("resolve", {}).items():
        results[f"resolve:{name}"] = _attempt(lambda h=host: _resolve(h))
    for name, (pid, access) in plan.get("open_process", {}).items():
        results[f"open_process:{name}"] = _attempt(lambda p=pid, a=access: _open_process(p, a))
    for name, (hive, key, value) in plan.get("registry", {}).items():
        results[f"registry:{name}"] = _attempt(lambda h=hive, k=key, v=value: _registry(h, k, v))
    if plan.get("cuda"):
        results["cuda"] = _attempt(_cuda)
    try:
        results["token"] = {"ok": True, "detail": json.dumps(_token())}  # not truncated
    except Exception as exc:  # noqa: BLE001
        results["token"] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    results["env"] = {"ok": True, "detail": json.dumps(sorted(os.environ))}
    with open(args[1], "w", encoding="utf-8") as handle:
        json.dump(results, handle)
    if plan.get("spawn_child_and_sleep"):
        child = subprocess.Popen(
            [sys.executable, "-I", "-S", "-c", "import time; time.sleep(300)"],
            creationflags=0x08000000,
        )
        with open(args[1] + ".child", "w", encoding="utf-8") as handle:
            handle.write(str(child.pid))
        time.sleep(300)
    return 0


if __name__ == "__main__":
    sys.exit(main())
