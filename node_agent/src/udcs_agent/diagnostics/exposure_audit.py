"""Exposure audit, host side (ADR 0001 gate 2, ADR 0003).

Builds the probe's plan from what the *host* can enumerate (named pipes, named kernel
objects, listening ports, services, processes, user profiles), launches
exposure_probe.py in a real UDCS AppContainer, the same way package runs are
launched, and turns the result into an ExposureReport judged by
udcs_shared.exposure.violations().

    udcs-agent audit-exposure --out report.json

It changes nothing on the machine apart from creating and deleting one AppContainer
profile and a scratch directory under the data directory. Pipe probing opens each pipe
read-only and closes it at once, which the pipe's server sees as a connection.
"""

from __future__ import annotations

import contextlib
import ctypes
import getpass
import json
import os
import platform
import shutil
import socket
import sys
import time
from ctypes import wintypes
from datetime import UTC, datetime
from pathlib import Path

from udcs_agent import __version__
from udcs_shared.exposure import ExposureFinding, ExposureReport

AUDIT_WORKLOAD_ID = "exposure-audit"
NON_PERSONAL_PROFILES = {"public", "default", "default user", "all users", "defaultapppool"}


def _build() -> int:
    return sys.getwindowsversion().build


def _system_drive() -> str:
    return os.environ.get("SystemDrive", "C:") + "\\"


def _user_profiles() -> list[str]:
    users = Path(_system_drive()) / "Users"
    try:
        return [
            str(p)
            for p in users.iterdir()
            if p.is_dir() and not p.is_symlink() and p.name.lower() not in NON_PERSONAL_PROFILES
        ]
    except OSError:
        return []


def _pipes() -> list[str]:
    try:
        return sorted(os.listdir("\\\\.\\pipe\\"))[:5000]
    except OSError:
        return []


class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", wintypes.LPWSTR),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("Length", wintypes.ULONG),
        ("RootDirectory", wintypes.HANDLE),
        ("ObjectName", ctypes.POINTER(_UnicodeString)),
        ("Attributes", wintypes.ULONG),
        ("SecurityDescriptor", wintypes.LPVOID),
        ("SecurityQualityOfService", wintypes.LPVOID),
    ]


class _DirectoryInfo(ctypes.Structure):
    _fields_ = [("Name", _UnicodeString), ("TypeName", _UnicodeString)]


def named_objects(
    directory: str = "\\BaseNamedObjects", limit: int = 20_000
) -> list[tuple[str, str]]:
    """(type, name) of the global named kernel objects the host can see."""
    ntdll = ctypes.WinDLL("ntdll")
    name = _UnicodeString(len(directory) * 2, len(directory) * 2 + 2, directory)
    attrs = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes), None, ctypes.pointer(name), 0x40, None, None
    )
    handle = wintypes.HANDLE()
    if ntdll.NtOpenDirectoryObject(ctypes.byref(handle), 0x0001, ctypes.byref(attrs)) != 0:  # QUERY
        return []
    out: list[tuple[str, str]] = []
    try:
        buffer = ctypes.create_string_buffer(1 << 16)
        context = wintypes.ULONG(0)
        returned = wintypes.ULONG(0)
        first = True
        while len(out) < limit:
            status = ntdll.NtQueryDirectoryObject(
                handle,
                buffer,
                len(buffer),
                False,
                first,
                ctypes.byref(context),
                ctypes.byref(returned),
            )
            first = False
            if status not in (0, 0x105):  # STATUS_SUCCESS, STATUS_MORE_ENTRIES
                break
            entries = ctypes.cast(buffer, ctypes.POINTER(_DirectoryInfo))
            i = 0
            while entries[i].Name.Length:
                out.append((entries[i].TypeName.Buffer, entries[i].Name.Buffer))
                i += 1
            if status == 0:
                break
    finally:
        ctypes.WinDLL("kernel32").CloseHandle(handle)
    return out


def _listening_ports() -> list[list]:
    import psutil

    ports = set()
    with contextlib.suppress(psutil.Error, OSError):
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                host = conn.laddr.ip
                host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host  # noqa: S104
                if ":" not in host:
                    ports.add((host, conn.laddr.port))
    return [list(p) for p in sorted(ports)][:300]


def _processes() -> tuple[list[int], dict[str, str]]:
    import psutil

    names = {}
    for p in psutil.process_iter(["pid", "name"]):
        names[str(p.info["pid"])] = p.info["name"] or ""
    return [int(k) for k in names], names


def _services() -> list[str]:
    import psutil

    with contextlib.suppress(psutil.Error, OSError, AttributeError):
        return sorted(s.name() for s in psutil.win_service_iter())
    return []


def build_plan(data_dir: Path, scratch: Path, profile_folder: str | None) -> dict:
    drive = _system_drive()
    program_data = os.environ.get("ProgramData", drive + "ProgramData")
    windows = os.environ.get("SystemRoot", drive + "Windows")
    pids, pid_names = _processes()
    fs_roots = [
        [drive, 1],
        [drive + "Users", 4],
        [program_data, 3],
        [os.environ.get("ProgramFiles", drive + "Program Files"), 1],
        [os.environ.get("ProgramFiles(x86)", drive + "Program Files (x86)"), 1],
        [windows, 1],
        [windows + "\\Temp", 1],
        [str(data_dir), 3],
    ]
    for letter in "DEFGHIJ":
        root = f"{letter}:\\"
        if os.path.isdir(root):
            fs_roots.append([root, 2])
    skip = [str(scratch)]
    if profile_folder:
        skip.append(profile_folder)  # the container's own storage, writable by design
    return {
        "deadline_seconds": 300,
        "max_dirs": 50_000,
        "max_keys": 50_000,
        "fs_roots": fs_roots,
        "skip_prefixes": skip,
        "sensitive_fs": [
            *_user_profiles(),
            str(Path(program_data) / "UDCS"),
            str(data_dir),
            windows + "\\System32\\config",
        ],
        "reg_roots": [
            ["HKLM", "SOFTWARE", 2],
            ["HKLM", "SYSTEM\\CurrentControlSet\\Services", 1],
            ["HKLM", "SAM", 1],
            ["HKLM", "SECURITY", 1],
            ["HKU", "", 2],
            ["HKCU", "", 2],
        ],
        # HKLM\SAM itself is world-readable by design; the account database is SAM\SAM.
        # HKU\S-1-5-21- is a SID prefix: every real user's hive and its _Classes hive.
        "sensitive_reg": ["HKLM\\SAM\\SAM", "HKLM\\SECURITY", "HKU\\S-1-5-21-"],
        "sensitive_values": [
            [
                "HKLM",
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                "DefaultPassword",
            ],
        ],
        "pids": pids,
        "pid_names": pid_names,
        "pipes": _pipes(),
        "objects": [list(o) for o in named_objects()],
        "sensitive_words": ["udcs"],
        "ports": _listening_ports(),
        "external": [["1.1.1.1", 443], ["8.8.8.8", 53]],
        "dns_name": "example.com",
        "services": _services(),
    }


def _runner() -> str:
    """Who ran the audit, from the process token (not USERNAME: for LocalSystem that is
    the machine account HOSTNAME$, which would leak the host name and hide SYSTEM)."""
    from udcs_agent.diagnostics.context import LOCAL_SYSTEM_SID, _session_id, _sid

    if _sid() == LOCAL_SYSTEM_SID:
        return f"NT AUTHORITY\\SYSTEM (session {_session_id()})"
    user = getpass.getuser()
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        admin = False
    return f"{user} ({'elevated' if admin else 'standard'})"


def run_audit(data_dir: Path, *, timeout: float = 450.0) -> tuple[ExposureReport, dict]:
    """Run the probe in a fresh UDCS AppContainer; return (report, raw plan)."""
    from udcs_agent.winplat.jobs import JobObject
    from udcs_agent.workloads.isolation import AppContainerIsolation

    isolation = AppContainerIsolation(data_dir)
    scratch = data_dir / "diagnostics" / "exposure"
    shutil.rmtree(scratch, ignore_errors=True)
    (scratch / "input").mkdir(parents=True)
    (scratch / "out").mkdir(parents=True)
    local = os.environ.get("LOCALAPPDATA")
    profile = isolation.profile_name(AUDIT_WORKLOAD_ID)
    profile_folder = str(Path(local) / "Packages" / profile) if local else None
    plan = build_plan(data_dir, scratch, profile_folder)
    plan_path = scratch / "input" / "plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    result_path = scratch / "out" / "result.json"
    job = JobObject()
    errors: list[str] = []
    raw: dict = {}
    try:
        process = isolation.launch(
            AUDIT_WORKLOAD_ID,
            "exposure_probe",
            [str(plan_path), str(result_path)],
            job,
            scratch / "out",
            read_only=(scratch / "input",),
        )
        started = time.monotonic()
        code = process.wait(timeout)
        process.close()
        if code is None:
            errors.append(f"probe did not finish within {timeout:.0f} s")
        raw = json.loads(result_path.read_text(encoding="utf-8")) if result_path.exists() else {}
        if not raw:
            error_file = scratch / "out" / "workload-error.txt"
            detail = error_file.read_text(encoding="utf-8")[-500:] if error_file.exists() else ""
            errors.append(f"probe produced no result (exit {code}) {detail}")
        raw.setdefault("seconds", round(time.monotonic() - started, 1))
    finally:
        job.close()
        isolation.release(AUDIT_WORKLOAD_ID, read_only=(scratch / "input",))
    token = raw.get("token") or {}
    findings = [ExposureFinding.model_validate(f) for f in raw.get("findings", [])]
    truncated = list(raw.get("truncated", []))
    if not raw:
        truncated.append("probe")
    report = ExposureReport(
        generated_at=datetime.now(UTC),
        hostname=socket.gethostname(),
        os_release=platform.release(),
        os_version=platform.version(),
        build=_build(),
        agent_version=__version__,
        runner=_runner(),
        appcontainer=bool(token.get("is_appcontainer")),
        integrity_rid=int(token.get("integrity_rid", 0x4000)),
        privileges=[p["name"] for p in token.get("privileges", [])],
        coverage=dict(raw.get("coverage", {})),
        truncated=sorted(set(truncated)),
        errors=[*errors, *raw.get("errors", [])][:200],
        findings=findings,
    )
    return report, plan
