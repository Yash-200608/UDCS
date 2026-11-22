"""Diagnose AppContainer launch failures on a non-interactive host (CI runner, service).

    uv run python tools/experiments/appcontainer_ci_probe.py

It prints who and where this process runs, then tries `cmd /c exit 7` (and Python) in an
AppContainer under several variants, printing each exit code. The output is diagnostic
only and the probe changes nothing persistent: profiles are deleted at the end, and
window-station and desktop grants vanish with the objects or the session.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path

from udcs_agent.winplat import api
from udcs_agent.winplat import appcontainer as ac
from udcs_agent.winplat.jobs import JobObject
from udcs_agent.winplat.launch import _environment_block

SYSTEMROOT = os.environ.get("SystemRoot", r"C:\Windows")
CMD = str(Path(SYSTEMROOT) / "System32" / "cmd.exe")


def identity() -> None:
    import psutil

    session = ctypes.c_ulong()
    ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session))
    station = ac._object_name(ac._user32.GetProcessWindowStation())
    ac._user32.GetThreadDesktop.restype = wintypes.HANDLE
    thread = ctypes.windll.kernel32.GetCurrentThreadId()
    desktop = ac._object_name(ac._user32.GetThreadDesktop(thread))
    print(f"user={psutil.Process().username()} session={session.value}")
    print(f"station={station} desktop={desktop}")
    print(
        f"admin={bool(ctypes.windll.shell32.IsUserAnAdmin())} build={sys.getwindowsversion().build}"
    )
    test = ac._user32.CreateWindowStationW("UDCSProbeCanCreate", 0, ac._WINSTA_ALL, None)
    print(f"can_create_window_station={bool(test)} last_error={ctypes.get_last_error()}")


def _plain_createprocess(argv: list[str], sid: str, desktop: str | None) -> int:
    """CreateProcessW with the caller's own token (no restriction) for comparison."""
    package = ac._Sid(sid)
    security = ac.SECURITY_CAPABILITIES(package.ptr, None, 0, 0)
    size = ctypes.c_size_t()
    k32 = api.kernel32
    k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
    attrs = ctypes.create_string_buffer(size.value)
    k32.InitializeProcThreadAttributeList(attrs, 1, 0, ctypes.byref(size))
    k32.UpdateProcThreadAttribute(
        attrs,
        0,
        ac.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        ctypes.byref(security),
        ctypes.sizeof(security),
        None,
        None,
    )
    startup = ac.STARTUPINFOEXW()
    startup.StartupInfo.cb = ctypes.sizeof(startup)
    startup.lpAttributeList = ctypes.cast(attrs, ctypes.c_void_p)
    name = ctypes.create_unicode_buffer(desktop) if desktop else None
    if name is not None:
        startup.StartupInfo.lpDesktop = ctypes.cast(name, wintypes.LPWSTR)
    info = api.PROCESS_INFORMATION()
    env = {
        "SystemRoot": SYSTEMROOT,
        "USERPROFILE": os.environ.get("USERPROFILE", ""),
        "LOCALAPPDATA": os.environ.get("LOCALAPPDATA", ""),
    }
    block = _environment_block(env)
    cpw = ctypes.WinDLL("kernel32", use_last_error=True).CreateProcessW
    cpw.restype = wintypes.BOOL
    ok = cpw(
        argv[0],
        ctypes.create_unicode_buffer(subprocess.list2cmdline(argv)),
        None,
        None,
        False,
        0x08000000 | 0x400 | ac.EXTENDED_STARTUPINFO_PRESENT,
        ctypes.cast(block, ctypes.c_void_p),
        SYSTEMROOT,
        ctypes.byref(startup),
        ctypes.byref(info),
    )
    k32.DeleteProcThreadAttributeList(attrs)
    package.close()
    if not ok:
        raise OSError(ctypes.get_last_error(), "CreateProcessW")
    api.WaitForSingleObject(info.hProcess, 20000)
    code = api.DWORD()
    api.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    return code.value


def launch(label: str, argv: list[str], *, desktop: str | None, restricted: bool = True) -> None:
    sid = ac.ensure_profile("udcs.ciprobe")
    cap = ac.capability_sid(ac.RUNTIME_CAPABILITY)
    job = JobObject()
    try:
        if restricted:
            process = ac.launch_in_appcontainer(
                argv,
                job,
                ac.SandboxSpec(sid, (cap,), lpac=False),
                cwd=Path(SYSTEMROOT),
                env={"SystemRoot": SYSTEMROOT},
                desktop=desktop,
            )
            code = process.wait(20)
            process.close()
        else:
            code = _plain_createprocess(argv, sid, desktop)
        print(f"{label:<58} exit=0x{(code or 0) & 0xFFFFFFFF:08X}")
    except Exception as exc:  # noqa: BLE001 -- diagnostic
        print(f"{label:<58} ERROR {type(exc).__name__}: {exc}")
    finally:
        job.close()


def main() -> int:
    identity()
    cap = ac.capability_sid(ac.RUNTIME_CAPABILITY)
    py = getattr(sys, "_base_executable", sys.executable)
    cmd = [CMD, "/c", "exit", "7"]
    launch("A cmd, inherited desktop, restricted token", cmd, desktop=None)
    launch(
        "B cmd, inherited desktop, own token (CreateProcessW)", cmd, desktop=None, restricted=False
    )
    path = ac.workload_desktop(cap)
    print(f"workload_desktop -> {path} private_station={ac._desktop_state.get('private_station')}")
    launch("C cmd, workload desktop", cmd, desktop=path)
    # D: grant ALL APPLICATION PACKAGES full access on the current station and the desktop.
    # Diagnostic only: it shows whether window-object access is the cause at all.
    station = ac._object_name(ac._user32.GetProcessWindowStation())
    if station.lower() == "winsta0":
        print("D/E skipped: never modify the interactive WinSta0")
    else:
        ac._grant_window_object(ac._user32.GetProcessWindowStation(), "S-1-15-2-1", ac._WINSTA_ALL)
        ac._grant_window_object(ac._desktop_state["desktop"], "S-1-15-2-1", ac._DESKTOP_ALL)
        launch("D cmd, workload desktop + ALL_APP_PACKAGES on station", cmd, desktop=path)
        launch("E cmd, D grants, own token", cmd, desktop=path, restricted=False)
    try:
        ac.grant(Path(py).parent, cap, ac.READ_EXECUTE)
        launch(
            "F python -I -S -c pass, workload desktop", [py, "-I", "-S", "-c", "pass"], desktop=path
        )
    except OSError as exc:
        print("F skipped:", exc)
    ac.delete_profile("udcs.ciprobe")
    # G: the real catalog workload through the isolation adapter, with its traceback
    import tempfile

    from udcs_agent.workloads.isolation import AppContainerIsolation

    data = Path(tempfile.mkdtemp(prefix="udcs-probe-"))
    iso = AppContainerIsolation(data)
    workdir = data / "w"
    job = JobObject()
    try:
        process = iso.launch(
            "probe-cpu",
            "synthetic",
            ["--kind", "cpu", "--dir", str(workdir), "--total-units", "3", "--memory-mb", "16"],
            job,
            workdir,
        )
        print(
            f"G catalog cpu workload via adapter exit=0x{(process.wait(60) or 0) & 0xFFFFFFFF:08X}"
        )
        error = workdir / "workload-error.txt"
        print(error.read_text() if error.exists() else "G: no workload-error.txt")
    finally:
        job.close()
        iso.release("probe-cpu")
    return 0


if __name__ == "__main__":
    sys.exit(main())
