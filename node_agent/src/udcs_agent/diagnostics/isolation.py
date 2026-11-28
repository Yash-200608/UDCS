"""Per-node isolation capability detection and the isolation self-test.

detect_isolation(): what *this* node can do, measured rather than assumed. Each
  backend is reported as available or not, and as verified (a real launch
  succeeded) or not. Lab PCs differ in build, edition and virtualisation, so this
  runs on every node.

run_selftest(): launches the hostile probe in an AppContainer, and the same probe
  as a plain host process as a control. It checks each permitted operation
  succeeded and each prohibited one failed, and that the host control *could* do
  the prohibited things, which shows each check is meaningful. It also checks that
  cancelling the job kills the whole process tree. The same function runs under
  pytest and inside the Windows service (an admin-requested diagnostic), so the
  service path is tested with the same expectations.
"""

from __future__ import annotations

import contextlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil

from udcs_shared.hardware import IsolationCapability

MXC_MIN_BUILD = 26100  # ProcessContainer: Windows 11 24H2+ (microsoft/mxc os-version-support)
PROCESS_TERMINATE, PROCESS_VM_READ = 0x0001, 0x0010
ALLOWED_PRIVILEGES = {"SeChangeNotifyPrivilege"}
REG_KEY = r"Software\UDCS-IsolationSelftest"


def _build() -> int:
    try:
        return int(platform.version().split(".")[2])
    except (IndexError, ValueError):
        return 0


def _find_wxc_exec(data_dir: Path | None) -> Path | None:
    candidates = [shutil.which("wxc-exec.exe")]
    if data_dir is not None:
        candidates.append(str(data_dir / "mxc" / "wxc-exec.exe"))
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate)
    return None


def _verify_appcontainer(lpac: bool) -> tuple[bool, str]:
    from udcs_agent.winplat import appcontainer as ac
    from udcs_agent.winplat.jobs import JobObject

    name = f"udcs.detect.{'lpac' if lpac else 'std'}"
    cmd = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe"
    job = JobObject()
    try:
        sid = ac.ensure_profile(name)
        started = time.perf_counter()
        process = ac.launch_in_appcontainer(
            [str(cmd), "/c", "exit", "7"],
            job,
            ac.SandboxSpec(sid, (), lpac=lpac),
            cwd=cmd.parent,
            env={"SystemRoot": os.environ.get("SystemRoot", r"C:\Windows")},
            desktop=ac.workload_desktop(ac.capability_sid(ac.RUNTIME_CAPABILITY)),
        )
        code = process.wait(15)
        process.close()
        elapsed = time.perf_counter() - started
        if code == 7:
            return True, f"launch verified ({elapsed * 1000:.0f} ms)"
        return False, f"test process exited with 0x{(code or 0) & 0xFFFFFFFF:08X}"
    except OSError as exc:
        return False, f"launch failed: {exc}"[:200]
    finally:
        job.close()
        with contextlib.suppress(OSError):
            ac.delete_profile(name)


def detect_isolation(data_dir: Path | None = None) -> list[IsolationCapability]:
    if sys.platform != "win32":
        return [IsolationCapability(name="appcontainer", available=False, detail="not Windows")]
    build = _build()
    caps: list[IsolationCapability] = []
    ok, detail = _verify_appcontainer(lpac=False)
    caps.append(IsolationCapability(name="appcontainer", available=ok, verified=ok, detail=detail))
    ok, detail = _verify_appcontainer(lpac=True)
    caps.append(
        IsolationCapability(
            name="appcontainer_lpac",
            # Workloads use LPAC plus registryRead (ADR 0001, 2026-11-28); this capability-less
            # cmd.exe check only shows the kernel supports LPAC.
            available=ok,
            verified=ok,
            detail=f"cmd.exe test: {detail}",
        )
    )
    wxc = _find_wxc_exec(data_dir)
    if wxc is None:
        mxc_detail = "wxc-exec.exe not installed"
    elif build < MXC_MIN_BUILD:
        mxc_detail = f"wxc-exec.exe found but build {build} < {MXC_MIN_BUILD} (24H2)"
    else:
        mxc_detail = "wxc-exec.exe found on a supported build; UDCS backend not integrated yet"
    caps.append(
        IsolationCapability(name="mxc_processcontainer", available=False, detail=mxc_detail)
    )
    system32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    caps.append(
        IsolationCapability(
            name="windows_sandbox",
            available=False,
            detail=(
                "WindowsSandbox.exe present; not orchestrated by UDCS"
                if (system32 / "WindowsSandbox.exe").exists()
                else "Windows Sandbox feature not installed"
            ),
        )
    )
    caps.append(
        IsolationCapability(
            name="hyperv",
            available=False,
            detail=(
                "Hyper-V host compute service present; not orchestrated by UDCS"
                if _service_exists("vmcompute")
                else "Hyper-V host compute service absent"
            ),
        )
    )
    caps.append(
        IsolationCapability(
            name="wsl",
            available=False,
            detail="wsl.exe present; not used" if (system32 / "wsl.exe").exists() else "absent",
        )
    )
    return caps


def _service_exists(name: str) -> bool:
    import winreg

    try:
        winreg.CloseKey(
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\{name}")
        )
        return True
    except OSError:
        return False


# -- self-test -------------------------------------------------------------------------------


def _expectations() -> dict[str, bool]:
    """Probe check -> must it succeed inside the sandbox?"""
    return {
        "read:approved_input": True,
        "read:runtime_code": True,
        "write:own_output": True,
        "write:approved_input": False,
        "write:runtime_code": False,
        "read:outside_secret": False,
        "read:other_workload": False,
        "write:other_workload": False,
        "read:agent_credential": False,
        "list:outside_dir": False,
        "registry:hkcu_secret": False,
        "connect:loopback": False,
        "connect:external": False,
        "resolve:dns": False,
        "open_process:agent_terminate": False,
        "open_process:agent_vm_read": False,
        "open_process:host_helper_terminate": False,
        "open_process:lsass_vm_read": False,
    }


def _profile_targets() -> dict[str, str]:
    """Every real user profile on this PC (a student's files live there)."""
    users = Path(os.environ.get("SystemDrive", "C:") + "\\") / "Users"
    skip = {"public", "default", "default user", "all users"}
    targets = {}
    try:
        for entry in users.iterdir():
            if entry.is_dir() and entry.name.lower() not in skip:
                targets[f"user_profile:{entry.name}"] = str(entry)
    except OSError:
        pass
    return targets


def _launch_probe(isolation, workload_id, job, workdir, plan_path, result_path, sandboxed):
    from udcs_agent.winplat.launch import launch_in_job

    if sandboxed:
        return isolation.launch(
            workload_id,
            "isolation_probe",
            [str(plan_path), str(result_path)],
            job,
            workdir,
            read_only=(plan_path.parent,),
        )
    argv = [
        isolation.python,
        "-I",
        "-S",
        "-c",
        isolation.bootstrap("isolation_probe"),
        str(plan_path),
        str(result_path),
    ]
    return launch_in_job(argv, job, cwd=workdir, env={"SystemRoot": os.environ["SystemRoot"]})


def run_selftest(
    scratch: Path,
    isolation,
    *,
    credential_file: Path | None = None,
    timeout: float = 60.0,
) -> dict:
    """Returns a report; report["passed"] is the verdict. Never raises for a failed check."""
    import winreg

    from udcs_agent.winplat.jobs import JobObject

    shutil.rmtree(scratch, ignore_errors=True)
    for sub in ("input", "out", "out_host", "other", "forbidden"):
        (scratch / sub).mkdir(parents=True, exist_ok=True)
    (scratch / "input" / "data.txt").write_text("input data")
    (scratch / "other" / "secret.txt").write_text("another workload's data")
    (scratch / "forbidden" / "secret.txt").write_text("not for workloads")
    if credential_file is None or not credential_file.exists():
        credential_file = scratch / "forbidden" / "credential.dat"
        credential_file.write_bytes(b"pretend-dpapi-blob")
    report: dict = {"build": _build(), "python": sys.version.split()[0], "checks": []}

    from udcs_agent.winplat import appcontainer as ac

    other_sid = ac.ensure_profile("udcs.wl.selftest-other")  # a second workload's identity
    ac.grant(scratch / "other", other_sid, ac.MODIFY)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    accepting = threading.Event()

    def accept_loop():
        listener.settimeout(0.5)
        while not accepting.is_set():
            with contextlib.suppress(OSError):
                conn, _ = listener.accept()
                conn.close()

    threading.Thread(target=accept_loop, daemon=True).start()
    helper = subprocess.Popen(  # noqa: S603 -- our own interpreter, fixed arguments
        [isolation.python, "-I", "-S", "-c", "import time; time.sleep(120)"],
        creationflags=0x08000000,
    )
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_KEY) as key:
        winreg.SetValueEx(key, "secret", 0, winreg.REG_SZ, "registry secret")
    lsass = next((p.pid for p in psutil.process_iter(["name"]) if p.info["name"] == "lsass.exe"), 0)
    runtime_code = isolation.runtime / "synthetic.py"
    plan = {
        "read": {
            "approved_input": str(scratch / "input" / "data.txt"),
            "runtime_code": str(runtime_code),
            "outside_secret": str(scratch / "forbidden" / "secret.txt"),
            "other_workload": str(scratch / "other" / "secret.txt"),
            "agent_credential": str(credential_file),
        },
        "write": {
            "own_output": "{OUT}/written.txt",
            "approved_input": str(scratch / "input" / "data.txt"),
            "runtime_code": str(runtime_code),
            "other_workload": str(scratch / "other" / "secret.txt"),
        },
        "list": {"outside_dir": str(scratch / "forbidden"), **_profile_targets()},
        "connect": {
            "loopback": ["127.0.0.1", listener.getsockname()[1]],
            "external": ["1.1.1.1", 443],
        },
        "resolve": {"dns": "example.com"},
        "open_process": {
            "agent_terminate": [os.getpid(), PROCESS_TERMINATE],
            "agent_vm_read": [os.getpid(), PROCESS_VM_READ],
            "host_helper_terminate": [helper.pid, PROCESS_TERMINATE],
            "lsass_vm_read": [lsass, PROCESS_VM_READ],
        },
        "registry": {"hkcu_secret": ["HKCU", REG_KEY, "secret"]},
        "cuda": True,
    }
    try:
        results = {}
        for mode, out in (("sandbox", scratch / "out"), ("host", scratch / "out_host")):
            mode_plan = json.loads(json.dumps(plan).replace("{OUT}", str(out).replace("\\", "/")))
            if mode == "host":
                # The unsandboxed control CAN write the runtime: point it at a decoy so the
                # self-test never modifies the code real workloads execute.
                decoy = scratch / "forbidden" / "runtime-decoy.py"
                shutil.copyfile(runtime_code, decoy)
                mode_plan["write"]["runtime_code"] = str(decoy)
            plan_path = scratch / "input" / f"plan-{mode}.json"
            plan_path.write_text(json.dumps(mode_plan))
            result_path = out / "result.json"
            job = JobObject()
            started = time.perf_counter()
            try:
                process = _launch_probe(
                    isolation,
                    "selftest-probe",
                    job,
                    out,
                    plan_path,
                    result_path,
                    sandboxed=mode == "sandbox",
                )
                code = process.wait(timeout)
                process.close()
                report[f"{mode}_seconds"] = round(time.perf_counter() - started, 3)
                report[f"{mode}_exit"] = code
                results[mode] = json.loads(result_path.read_text())
            except Exception as exc:  # noqa: BLE001
                results[mode] = {}
                report[f"{mode}_error"] = f"{type(exc).__name__}: {exc}"
            finally:
                job.close()
        _judge(report, results.get("sandbox", {}), results.get("host", {}))
        report["kill_tree"] = _kill_tree_check(isolation, scratch)
        report["cuda_in_sandbox"] = results.get("sandbox", {}).get("cuda")
        report["cuda_on_host"] = results.get("host", {}).get("cuda")
    finally:
        accepting.set()
        listener.close()
        helper.kill()
        with contextlib.suppress(OSError):
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REG_KEY)
        isolation.release("selftest-probe", read_only=(scratch / "input",))
        with contextlib.suppress(OSError):
            ac.delete_profile("udcs.wl.selftest-other")
    report["passed"] = (
        bool(report["checks"])
        and all(c["pass"] for c in report["checks"])
        and report["kill_tree"].get("pass", False)
    )
    return report


def _judge(report: dict, sandbox: dict, host: dict) -> None:
    checks = report["checks"]
    expected = _expectations()
    expected.update({k: False for k in sandbox if k.startswith("list:user_profile:")})
    for name, must_succeed in sorted(expected.items()):
        got = sandbox.get(name, {"ok": None, "error": "not run"})
        control = host.get(name, {})
        checks.append(
            {
                "name": name,
                "expected": "allowed" if must_succeed else "denied",
                "sandbox": "allowed" if got.get("ok") else f"denied ({got.get('error', '')})"[:160],
                # For a denied check: could the unsandboxed control do it? If not, the check
                # proves nothing on this machine (recorded, e.g. no internet in CI).
                "host_control": "allowed" if control.get("ok") else "denied",
                "pass": bool(got.get("ok")) == must_succeed and got.get("ok") is not None,
            }
        )
    token = json.loads(sandbox.get("token", {}).get("detail", "{}") or "{}")
    privileges = {p["name"] for p in token.get("privileges", [])}
    checks.append(
        {
            "name": "token:appcontainer_low_integrity_no_privileges",
            "expected": "AppContainer, integrity <= low, privileges <= SeChangeNotify",
            "sandbox": json.dumps(token)[:300],
            "host_control": "",
            "pass": bool(token.get("is_appcontainer"))
            and token.get("integrity_rid", 0x4000) <= 0x1000
            and privileges <= ALLOWED_PRIVILEGES,
        }
    )
    env = set(json.loads(sandbox.get("env", {}).get("detail", "[]") or "[]"))
    checks.append(
        {
            "name": "env:no_inherited_agent_environment",
            "expected": "only SystemRoot/TEMP/TMP/USERPROFILE/LOCALAPPDATA (+ Windows-added)",
            "sandbox": ",".join(sorted(env))[:300],
            "host_control": "",
            "pass": bool(env) and not any(k.upper().startswith("UDCS") for k in env),
        }
    )


def _kill_tree_check(isolation, scratch: Path) -> dict:
    """The probe spawns a child and sleeps; terminating the job must end both."""
    from udcs_agent.winplat.jobs import JobObject

    out = scratch / "out_tree"
    out.mkdir(exist_ok=True)
    plan_path = scratch / "input" / "plan-tree.json"
    plan_path.write_text(json.dumps({"spawn_child_and_sleep": True}))
    result_path = out / "result.json"
    job = JobObject()
    try:
        process = isolation.launch(
            "selftest-tree",
            "isolation_probe",
            [str(plan_path), str(result_path)],
            job,
            out,
            read_only=(plan_path.parent,),
        )
        child_file = Path(str(result_path) + ".child")
        deadline = time.monotonic() + 30
        while not child_file.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        if not child_file.exists():
            return {"pass": False, "error": "probe did not start its child"}
        child = int(child_file.read_text())
        members = set(job.process_ids())
        job.terminate(1)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and (
            psutil.pid_exists(process.pid) or psutil.pid_exists(child)
        ):
            time.sleep(0.1)
        alive = [p for p in (process.pid, child) if psutil.pid_exists(p)]
        process.close()
        return {
            "pass": {process.pid, child} <= members and not alive,
            "job_members": sorted(members),
            "still_alive": alive,
        }
    except Exception as exc:  # noqa: BLE001
        return {"pass": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        job.close()
        isolation.release("selftest-tree", read_only=(plan_path.parent,))
