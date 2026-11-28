"""Composition of the node agent, shared by the Windows service and `udcs-agent run`.

Threads, each independent of the others:
  governor        local protection loop (~1 s). Never waits on the network.
  controller-link heartbeats/inventory; failures only delay telemetry.
  helper-channel  per-session helper reports (Windows).
  diagnostics     admin-requested experiment E1 (runs off the main thread).
The governor is the only component that can stop protection, and if it fails
repeatedly the whole agent exits (workloads die with it via kill-on-close and
the service manager restarts it). Losing the controller never weakens protection.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path

from udcs_agent.config import CREDENTIAL_FILENAME, ConfigError, load_config
from udcs_agent.credentials import CredentialStore, CredentialStoreError, NodeCredential
from udcs_agent.discovery import collect_inventory
from udcs_agent.discovery.nvidia import Nvml
from udcs_agent.governor.engine import Governor
from udcs_agent.governor.interactive import HelperReports, InteractiveMonitor
from udcs_agent.governor.signals import SignalCollector
from udcs_agent.jobs import JobSync
from udcs_agent.monitoring.telemetry import TelemetryCollector
from udcs_agent.runner import AgentRunner, ExitReason
from udcs_agent.winplat import IS_WINDOWS
from udcs_agent.workloads.manager import WorkloadManager
from udcs_shared.agent_api import HeartbeatResponse, NodeAdminState
from udcs_shared.protection import ProtectionPolicy

logger = logging.getLogger("udcs.agent")

EXIT_OK, EXIT_FATAL = 0, 1
_NO_WORK_STATES = {NodeAdminState.PENDING, NodeAdminState.MAINTENANCE, NodeAdminState.REVOKED}
_CONTROLLER_STATE_FILE = "controller-state.json"


class AgentApp:
    def __init__(
        self,
        data_dir: Path,
        *,
        stop: threading.Event | None = None,
        require_secure_data_dir: bool = False,
        helper_channel: bool = True,
        max_jobs: int = 2,
        checkpoint_upload_seconds: float = 15.0,
    ) -> None:
        self.data_dir = data_dir
        self.stop = stop or threading.Event()
        self._require_secure = require_secure_data_dir
        self._fatal: str | None = None
        self.governor: Governor | None = None
        self._client = None
        self._store = CredentialStore(data_dir / CREDENTIAL_FILENAME)
        self._credential: NodeCredential | None = None
        self._rotating = threading.Lock()
        self._diagnostic: threading.Thread | None = None
        self._helper_channel = helper_channel
        self._max_jobs = max_jobs
        self._checkpoint_upload_seconds = checkpoint_upload_seconds
        self.workloads: WorkloadManager | None = None

    # -- lifecycle -------------------------------------------------------------------------------

    def run(self) -> int:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        insecure = self._data_dir_problem() if self._require_secure else None
        # Not started here: NVML's only users are the controller link's inventory and
        # telemetry, which start it on first use. An unenrolled (local-only) agent never
        # pays nvmlInit's ~21-23 MiB, which is never released (I-2).
        nvml = Nvml()
        reports = HelperReports()
        isolation = None
        if IS_WINDOWS:
            from udcs_agent.workloads.isolation import AppContainerIsolation

            isolation = AppContainerIsolation(self.data_dir)
        workloads = self.workloads = WorkloadManager(self.data_dir, isolation=isolation)
        holder: dict[str, Governor] = {}
        monitor = InteractiveMonitor(
            reports, idle_after_seconds=lambda: holder["g"].policy.idle_after_seconds
        )
        governor = Governor(
            workloads,
            SignalCollector(monitor),
            status_path=self.data_dir / "status" / "governor.json",
            maintenance_flag=self.data_dir / "maintenance.flag",
        )
        holder["g"] = self.governor = governor
        governor.set_remote_policy(self._load_policy())
        # Fail closed: an admin's "lend nothing" survives restarts and controller outages,
        # and an enrolled node lends nothing until a heartbeat confirms it is ACTIVE.
        governor.set_controller_maintenance(self._load_no_work())
        if insecure:
            logger.critical("data directory is not protected (%s); lending nothing", insecure)
            governor.set_controller_maintenance(True)

        governor_thread = threading.Thread(
            target=governor.run, args=(self.stop, self._on_fatal), name="udcs-governor", daemon=True
        )
        others: list[threading.Thread] = []
        channel = None
        if IS_WINDOWS and self._helper_channel:
            from udcs_agent.governor.helper_channel import HelperChannel

            channel = HelperChannel(reports, threading.Event())
            others.append(channel)
        controller = None if insecure else self._controller_thread(nvml, governor, workloads)
        if controller is not None:
            others.append(controller)
        governor_thread.start()
        for thread in others:
            thread.start()
        logger.info("agent started", extra={"pid": os.getpid(), "data_dir": str(self.data_dir)})

        try:
            while not self.stop.wait(2.0):
                if not insecure:
                    self._check_diagnostics_request()
        finally:
            started = time.monotonic()
            governor.wake()  # end its wait now
            governor_thread.join(timeout=3.0)  # never tear workloads down mid-tick
            workloads.shutdown()  # checkpoints already exist; stop promptly (B5: < 2 s)
            if channel is not None:
                channel.stop()
            if self._client is not None:
                self._client.close()  # aborts an in-flight request instead of waiting on it
            for thread in others:
                thread.join(timeout=0.3)
            nvml.shutdown()
            logger.info(
                "agent stopped",
                extra={
                    "shutdown_ms": round((time.monotonic() - started) * 1000),
                    "reason": self._fatal or "stop requested",
                },
            )
        return EXIT_FATAL if self._fatal else EXIT_OK

    def wake(self) -> None:
        """Re-assess immediately (e.g. on a Windows session-change notification)."""
        if self.governor is not None:
            self.governor.wake()

    def _on_fatal(self, reason: str) -> None:
        logger.critical("fatal: %s", reason)
        self._fatal = reason
        self.stop.set()

    def _data_dir_problem(self) -> str | None:
        if not IS_WINDOWS:
            return None
        from udcs_agent.winplat.acl import insecure_reason

        try:
            return insecure_reason(self.data_dir)
        except OSError as exc:
            return f"cannot verify ACL ({exc})"

    # -- controller link -------------------------------------------------------------------------

    def _controller_thread(
        self, nvml: Nvml, governor: Governor, workloads: WorkloadManager
    ) -> threading.Thread | None:
        try:
            config = load_config(self.data_dir)
            self._credential = self._store.load()
        except (ConfigError, CredentialStoreError) as exc:
            logger.warning("not connected to a controller: %s", exc)
            return None
        if self._credential is None:
            logger.warning("not enrolled; running local protection only")
            return None
        from udcs_agent.communication.client import ControllerClient

        if not (self.data_dir / _CONTROLLER_STATE_FILE).exists():
            governor.set_controller_maintenance(True)  # enrolled: wait for the controller's word
        self._client = ControllerClient(config, credential=self._credential.secret)
        telemetry = TelemetryCollector(nvml, self.data_dir, governor=governor.snapshot)
        inventory = collect_inventory(nvml)
        jobs = JobSync(
            self.data_dir,
            snapshot=workloads.job_snapshot,
            admission=governor.admission_view,
            has_gpu=any(g.vendor == "nvidia" for g in inventory.gpus),
            max_jobs=self._max_jobs,
            checkpoint_upload_seconds=self._checkpoint_upload_seconds,
            isolation="host",  # until detection below has measured this node
        )
        client = self._client
        capabilities: list = []

        def detect() -> None:
            """Measure this node's isolation once, on this thread (not the governor's)."""
            from udcs_agent.diagnostics.isolation import detect_isolation

            try:
                capabilities[:] = detect_isolation(self.data_dir)
            except Exception:
                logger.exception("isolation detection failed; using host isolation only")
                capabilities[:] = []
            verified = any(c.name == "appcontainer" and c.verified for c in capabilities)
            jobs.set_isolation("appcontainer" if verified else "host")
            logger.info(
                "isolation capabilities",
                extra={"capabilities": [c.model_dump() for c in capabilities]},
            )

        def inventory_now():
            return collect_inventory(nvml).model_copy(update={"isolation": list(capabilities)})

        def sync_jobs(response: HeartbeatResponse) -> None:
            # Reports always go out (progress, results, cancellations). New work is only
            # offered when the node is ACTIVE *and* the local envelope allows it.
            jobs.sync_once(client)

        runner = AgentRunner(
            self._client,
            inventory_source=inventory_now,
            telemetry_source=telemetry.collect,
            stop_event=self.stop,
            on_response=self._on_response,
            after_heartbeat=sync_jobs,
        )

        def run() -> None:
            detect()
            reason = runner.run()
            if reason is ExitReason.CREDENTIAL_REJECTED:
                # Revoked or unknown: stop lending resources, but keep protecting locally.
                governor.set_controller_maintenance(True)
                self._save_no_work(True, "credential_rejected")
                logger.error("controller rejected this node; UDCS work stays paused")

        return threading.Thread(target=run, name="udcs-controller-link", daemon=True)

    def _on_response(self, response: HeartbeatResponse) -> None:
        governor = self.governor
        if governor is None:
            return
        no_work = response.admin_state in _NO_WORK_STATES
        governor.set_controller_maintenance(no_work)
        self._save_no_work(no_work, response.admin_state.value)
        if response.protection_policy is not None:
            governor.set_remote_policy(response.protection_policy)
            self._save_policy(response.protection_policy)
        if response.rotate_credential:
            self._rotate_credential()

    def _rotate_credential(self) -> None:
        if self._client is None or self._credential is None:
            return
        if not self._rotating.acquire(blocking=False):
            return
        try:
            new_secret = self._client.rotate_credential()
            updated = NodeCredential(node_id=self._credential.node_id, secret=new_secret)
            # Persist BEFORE using it: if we crash here, the restarted agent uses the new one
            # (promoting it); if saving fails, the old one is still valid.
            self._store.save(updated)
            self._credential = updated
            self._client.set_credential(new_secret)
            logger.info("node credential rotated")
        except Exception:
            logger.exception("credential rotation failed; keeping the current credential")
        finally:
            self._rotating.release()

    # -- persisted controller decisions (protection stays strict while offline) ----------------

    def _atomic_write(self, name: str, text: str) -> None:
        path = self.data_dir / name
        try:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            logger.warning("could not persist %s", name, exc_info=True)

    def _load_policy(self) -> ProtectionPolicy | None:
        try:
            return ProtectionPolicy.model_validate_json(
                (self.data_dir / "policy.json").read_text(encoding="utf-8")
            )
        except (FileNotFoundError, ValueError):
            return None

    def _save_policy(self, policy: ProtectionPolicy) -> None:
        self._atomic_write("policy.json", policy.model_dump_json())

    def _load_no_work(self) -> bool:
        try:
            data = json.loads((self.data_dir / _CONTROLLER_STATE_FILE).read_text("utf-8"))
            return bool(data["no_work"])
        except FileNotFoundError:
            return False  # never told anything (local-only or not yet enrolled)
        except (ValueError, KeyError, TypeError):
            return True  # unreadable: fail closed

    def _save_no_work(self, no_work: bool, state: str) -> None:
        self._atomic_write(
            _CONTROLLER_STATE_FILE, json.dumps({"no_work": no_work, "admin_state": state})
        )

    # -- diagnostics (experiment E1), requested by IT via a file in the protected data dir ---

    def _check_diagnostics_request(self) -> None:
        if self._diagnostic and self._diagnostic.is_alive():
            return
        if (self.data_dir / "diagnostics" / "isolation-request").exists():
            self._start_isolation_selftest()
            return
        request = self.data_dir / "diagnostics" / "gpu-request"
        if not request.exists():
            return
        request.unlink(missing_ok=True)
        workdir = self.data_dir / "diagnostics"

        def run() -> None:
            from udcs_agent.diagnostics.gpu_matrix import run_matrix

            level = None
            if self.governor is not None and self.governor.snapshot()[2] is not None:
                level = self.governor.snapshot()[2].level.value
            try:
                report = run_matrix(workdir / "work", stop=self.stop)
            except Exception as exc:  # noqa: BLE001 — a diagnostic must never take the agent down
                report = {"error": f"{type(exc).__name__}: {exc}"}
            report["protection_level_at_start"] = level
            (workdir / "gpu-result.json").write_text(json.dumps(report, indent=1), encoding="utf-8")
            logger.info("GPU execution-context diagnostic written")

        self._diagnostic = threading.Thread(target=run, name="udcs-diagnostic", daemon=True)
        self._diagnostic.start()

    def _start_isolation_selftest(self) -> None:
        """Admin-requested (a file in the protected data dir): run the isolation self-test
        from *this* process, i.e. from the real service (LocalSystem, session 0)."""
        workdir = self.data_dir / "diagnostics"
        (workdir / "isolation-request").unlink(missing_ok=True)

        def run() -> None:
            from udcs_agent.diagnostics.isolation import detect_isolation, run_selftest
            from udcs_agent.workloads.isolation import AppContainerIsolation

            try:
                report = run_selftest(
                    workdir / "isolation",
                    AppContainerIsolation(self.data_dir),
                    credential_file=self.data_dir / CREDENTIAL_FILENAME,
                )
                report["capabilities"] = [c.model_dump() for c in detect_isolation(self.data_dir)]
            except Exception as exc:  # noqa: BLE001 -- a diagnostic must never take the agent down
                report = {"passed": False, "error": f"{type(exc).__name__}: {exc}"}
            report["agent_identity"] = _identity()
            (workdir / "isolation-result.json").write_text(
                json.dumps(report, indent=1), encoding="utf-8"
            )
            logger.info("isolation self-test written", extra={"passed": report.get("passed")})

        self._diagnostic = threading.Thread(target=run, name="udcs-diagnostic", daemon=True)
        self._diagnostic.start()


def _identity() -> dict:
    """Who and where the agent runs (the service must show SYSTEM in session 0)."""
    import psutil

    info: dict = {"pid": os.getpid()}
    try:
        info["user"] = psutil.Process().username()
    except Exception:  # noqa: BLE001
        info["user"] = None
    if IS_WINDOWS:
        import ctypes

        session = ctypes.c_ulong()
        if ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
            info["session_id"] = session.value
    return info
