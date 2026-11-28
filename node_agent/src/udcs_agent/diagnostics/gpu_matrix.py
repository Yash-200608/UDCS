"""Experiment E1: does CUDA work in each candidate execution arrangement?

Run *inside the service* (session 0, LocalSystem) on request. Arrangements:
  1. service_process        -- CUDA directly in the service process
  2. service_child_worker   -- child of the service in a UDCS Job Object (session 0)
  3. session_worker_system  -- worker in the interactive session, SYSTEM token
  4. session_worker_user    -- worker in the interactive session as the logged-on user
     (diagnostic only: running workloads as the student is never acceptable)
The service stays responsible for orchestration and protection in every case.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def _bootstrap(out: Path) -> list[str]:
    paths = [p for p in sys.path if p and Path(p).is_dir()]
    code = (
        f"import sys; sys.path[:0] = {paths!r}; "
        f"from udcs_agent.diagnostics.gpu_probe import main; sys.exit(main([{str(out)!r}]))"
    )
    return [getattr(sys, "_base_executable", sys.executable), "-I", "-B", "-c", code]


def _read(out: Path, exit_code: int | None) -> dict[str, object]:
    try:
        data = json.loads(out.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        data = {"ok": False, "error": "probe produced no result"}
    data["exit_code"] = exit_code
    return data


def run_matrix(workdir: Path, stop: object | None = None) -> dict[str, object]:
    from udcs_agent.diagnostics.gpu_probe import probe
    from udcs_agent.winplat.api import current_session_id
    from udcs_agent.winplat.sessions import list_sessions

    workdir.mkdir(parents=True, exist_ok=True)
    report: dict[str, object] = {
        "host_session_id": current_session_id(),
        "started": time.time(),
        "arrangements": {},
    }
    arrangements = report["arrangements"]
    arrangements["service_process"] = probe()

    from udcs_agent.winplat.jobs import JobObject
    from udcs_agent.winplat.launch import launch_in_job

    out = workdir / "child.json"
    out.unlink(missing_ok=True)
    job = JobObject()
    try:
        process = launch_in_job(_bootstrap(out), job, cwd=workdir)
        code = process.wait(60)
        process.close()
        arrangements["service_child_worker"] = _read(out, code)
    except OSError as exc:
        arrangements["service_child_worker"] = {"ok": False, "error": str(exc)}
    finally:
        job.close()

    interactive = [s for s in list_sessions() if s.interactive]
    if not interactive:
        for name in ("session_worker_system", "session_worker_user"):
            arrangements[name] = {"ok": None, "error": "no interactive session to test"}
    else:
        from udcs_agent.winplat.sessionlaunch import launch_in_session

        session = interactive[0].session_id
        for name, as_user in (("session_worker_system", False), ("session_worker_user", True)):
            if stop is not None and stop.is_set():
                arrangements[name] = {"ok": None, "error": "agent stopping"}
                continue
            out = workdir / f"{name}.json"
            out.unlink(missing_ok=True)
            try:
                code = launch_in_session(
                    _bootstrap(out), session, as_user=as_user, cwd=workdir, timeout_seconds=60
                )
                arrangements[name] = _read(out, code)
            except OSError as exc:
                arrangements[name] = {"ok": False, "error": str(exc)}
    report["finished"] = time.time()
    return report
