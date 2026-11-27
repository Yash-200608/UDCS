"""Controller jobs on the node: offer capacity, run assignments, report back.

This links the controller's scheduler to the local workload manager, and it never
overrides local protection:
- The capacity offer comes from the governor's current envelope. While the student
  needs the machine (pressure, CONSTRAINED, PROTECTED or MAINTENANCE), nothing new
  is accepted.
- An accepted job is just another workload to the governor. It throttles, pauses
  and evicts it exactly as it would any other workload.
- All changes to workloads go through the manager's request queue (single writer).
  This module only reads manager snapshots.

`DATA_DIR/jobs/assignments.json` is written before a workload is created. After an
agent restart, every job is therefore either still reported (and resumes from its
checkpoint) or recreated.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
import sys
import sysconfig
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from udcs_agent import package_runs
from udcs_agent.communication.client import ControllerUnavailable, ProtocolError
from udcs_agent.governor.engine import AdmissionView
from udcs_agent.packages import NodeCache
from udcs_agent.workloads.manager import WorkloadManager, WorkloadSpec
from udcs_shared.agent_api import PROTOCOL_VERSION
from udcs_shared.jobs import (
    MAX_ASSIGNMENTS_PER_SYNC,
    MAX_CHECKPOINT_BYTES,
    MAX_LOG_LINES_PER_REPORT,
    AgentJobReport,
    CheckpointDownload,
    CheckpointUpload,
    FailureKind,
    JobLogLine,
    JobResult,
    JobSyncRequest,
    JobSyncResponse,
    LocalJobState,
    NodeJobCapacity,
    PackageResult,
    PackageRunLimits,
    validate_catalog_checkpoint,
)
from udcs_shared.protection import ProtectionLevel, WorkloadClass

logger = logging.getLogger(__name__)

WORKLOAD_PREFIX = "job-"
# User code stays off on every node until ADR 0001's remaining gates pass. It is a
# constant, not configuration, so it cannot be switched on by a config file on a lab PC.
# Even when it is on, a node runs packages only with a verified AppContainer, and the
# controller sends them only to nodes an administrator made eligible (ADR 0003).
USER_CODE_ENABLED = False
NODE_PYTHON = f"{sys.version_info.major}.{sys.version_info.minor}"  # what packages run on
NODE_PLATFORM = sysconfig.get_platform().replace("-", "_").replace(".", "_")


def running_as_local_system() -> bool:
    """True when the agent runs as LocalSystem (the installed service).

    Measured with the exposure audit on Windows build 26300: an AppContainer launched by
    an agent running as the *interactive user* can stop that user's per-user services
    and open the student's WinSta0 Default desktop, because the user's SID is in the
    sandbox token. As SYSTEM, a private window station is created and the student's
    per-user services are not the token's. User code is therefore never offered from
    an interactive agent.
    """
    if sys.platform != "win32":
        return False
    try:
        from udcs_agent.winplat import appcontainer as ac

        return ac.current_user_sid() == "S-1-5-18"
    except OSError:
        return False


def user_code_offered(isolation: str) -> bool:
    return USER_CODE_ENABLED and isolation == "appcontainer" and running_as_local_system()


READD_AFTER_SECONDS = 10.0
_NO_NEW_WORK_LEVELS = {
    ProtectionLevel.CONSTRAINED,
    ProtectionLevel.PROTECTED,
    ProtectionLevel.MAINTENANCE,
}
_PRESSURE = ("cpu_pressure", "memory_pressure", "paging", "signals_unavailable")


class JobController(Protocol):
    def sync_jobs(self, request: JobSyncRequest) -> JobSyncResponse: ...
    def put_checkpoint(self, job_id: uuid.UUID, upload: CheckpointUpload) -> None: ...
    def get_checkpoint(self, job_id: uuid.UUID, attempt: int) -> CheckpointDownload: ...


def workload_id(job_id: uuid.UUID) -> str:
    return f"{WORKLOAD_PREFIX}{job_id.hex}"


class JobSync:
    def __init__(
        self,
        data_dir: Path,
        *,
        snapshot: Callable[[str], dict[str, dict[str, Any]]],
        admission: Callable[[], AdmissionView | None],
        has_gpu: bool,
        max_jobs: int = 2,
        checkpoint_upload_seconds: float = 15.0,
        isolation: str = "host",
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.data_dir = data_dir
        self._upload_every = checkpoint_upload_seconds
        # Measured on this node at start-up: "appcontainer" only if a real launch passed.
        self._isolation = isolation
        self._uploaded_units: dict[str, int] = {}  # per job, this process
        self._last_upload: dict[str, float] = {}
        self._notes: dict[str, list[str]] = {}  # extra log lines for the next report
        self._snapshot = snapshot
        self._admission = admission
        self._has_gpu = has_gpu
        self._max_jobs = max(0, min(max_jobs, MAX_ASSIGNMENTS_PER_SYNC))
        self._clock = clock
        self._wall = wall_clock
        self._path = data_dir / "jobs" / "assignments.json"
        self._assignments: dict[str, dict[str, Any]] = self._load()
        self._log_cursor: dict[str, float] = {}  # manager event times are per-process
        self._pending_cursor: dict[str, float] = {}
        self._last_offer = ""
        self._refused: dict[str, int] = {}  # user-code assignments refused, until acknowledged
        self._stale_staging: set[str] = set()
        self._staging_removal_due: set[str] = set()

    # -- persistence ---------------------------------------------------------------------------

    def _load(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return {str(uuid.UUID(k)): dict(v) for k, v in data.items()}
        except FileNotFoundError:
            return {}
        except (ValueError, TypeError, AttributeError):
            logger.error("job assignment file is corrupt; starting empty (jobs will be requeued)")
            return {}

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._assignments, indent=1), encoding="utf-8")
        os.replace(tmp, self._path)

    def set_isolation(self, level: str) -> None:
        """Applies to jobs accepted from now on; running jobs keep the level they began with."""
        self._isolation = level

    @property
    def job_ids(self) -> list[str]:
        return list(self._assignments)

    # -- request -------------------------------------------------------------------------------

    def capacity(self) -> NodeJobCapacity:
        def refuse(reason: str) -> NodeJobCapacity:
            return NodeJobCapacity(
                accept=False, slots=0, kinds=[], memory_available_mb=0, reason=reason
            )

        view = self._admission()
        if view is None:
            return refuse("not assessed yet")
        if view.maintenance:
            return refuse("maintenance")
        if view.level in _NO_NEW_WORK_LEVELS:
            return refuse(f"level {view.level.value}")
        pressure = next((r for r in _PRESSURE if r in view.reasons), None)
        if pressure:
            return refuse(pressure)
        env = view.envelope
        kinds: list[WorkloadClass] = []
        if env.cpu_cap_percent > 0:
            kinds.append(WorkloadClass.CPU)
            if env.allow_memory_class:
                kinds.append(WorkloadClass.MEMORY)
            if env.allow_disk_class and "disk_pressure" not in view.reasons:
                kinds.append(WorkloadClass.DISK)
            if env.allow_gpu_class and self._has_gpu and "gpu_demand" not in view.reasons:
                kinds.append(WorkloadClass.GPU)
        slots = max(0, self._max_jobs - len(self._assignments))
        budget = view.memory_total_bytes * env.udcs_memory_budget_percent / 100.0
        memory_mb = int(max(0.0, budget - view.udcs_memory_bytes) // 2**20)
        if not kinds:
            return refuse("no workload class allowed")
        if slots == 0:
            return refuse("all job slots in use")
        offered = user_code_offered(self._isolation)
        return NodeJobCapacity(
            accept=True,
            slots=slots,
            kinds=kinds,
            memory_available_mb=memory_mb,
            user_code=offered,
            python=NODE_PYTHON if offered else None,
            platform=NODE_PLATFORM if offered else None,
        )

    def build_request(self) -> JobSyncRequest:
        snapshot = self._snapshot(WORKLOAD_PREFIX)
        now = self._clock()
        reports: list[AgentJobReport] = []
        self._pending_cursor = {}
        known = {workload_id(uuid.UUID(j)) for j in self._assignments}
        for wid in snapshot:
            if wid not in known:  # left over from a lost assignment file: discard it
                WorkloadManager.queue_request(self.data_dir, "remove", workload_id=wid, purge=True)
        for job_id, entry in self._assignments.items():
            wid = workload_id(uuid.UUID(job_id))
            item = snapshot.get(wid)
            if entry.get("package"):
                reports.append(self._package_report(job_id, entry, item, now))
                continue
            if item is None:
                waiting_for_checkpoint = "resume" in entry
                if (
                    not waiting_for_checkpoint
                    and self._wall() - float(entry.get("added_at", 0)) > READD_AFTER_SECONDS
                ):
                    self._queue_add(job_id, entry)  # the add request was lost; idempotent
                reports.append(
                    AgentJobReport(
                        job_id=uuid.UUID(job_id),
                        attempt=int(entry["attempt"]),
                        state=LocalJobState.WAITING,
                        units_done=0,
                        logs=self._note_lines(job_id),
                    )
                )
                continue
            reports.append(self._report(job_id, entry, item, now))
        capacity = self.capacity()
        offer = "accepting" if capacity.accept else f"no new work: {capacity.reason}"
        if offer != self._last_offer:  # log changes only, not every sync
            logger.info("job offer: %s", offer)
            self._last_offer = offer
        for job_id, attempt in self._refused.items():
            reports.append(
                AgentJobReport(
                    job_id=uuid.UUID(job_id),
                    attempt=attempt,
                    state=LocalJobState.FAILED,
                    units_done=0,
                    error=(
                        "user code is not offered by this node "
                        "(disabled, or no verified AppContainer)"
                    ),
                )
            )
        return JobSyncRequest(protocol_version=PROTOCOL_VERSION, reports=reports, capacity=capacity)

    def _report(
        self, job_id: str, entry: dict[str, Any], item: dict[str, Any], now: float
    ) -> AgentJobReport:
        state = LocalJobState(str(item["state"]))
        result: JobResult | None = None
        error: str | None = None
        if state == LocalJobState.COMPLETED:
            try:
                raw = item.get("result") or {}
                result = JobResult(units=int(raw["units"]), checksum=str(raw["checksum"]))
            except (KeyError, TypeError, ValueError, ValidationError):
                state, error = LocalJobState.FAILED, "completed without a valid result file"
        elif state == LocalJobState.FAILED:
            error = (
                f"workload failed {item.get('failures')} times on this node "
                f"(last exit code {item.get('last_exit_code')})"
            )
        cursor = self._log_cursor.get(job_id, float("-inf"))
        events = [(t, what) for t, what in item.get("events", []) if t > cursor]
        events = events[-MAX_LOG_LINES_PER_REPORT:]
        if events:
            self._pending_cursor[job_id] = events[-1][0]
        return AgentJobReport(
            job_id=uuid.UUID(job_id),
            attempt=int(entry["attempt"]),
            state=state,
            units_done=min(int(item.get("units_done", 0)), int(entry["spec"]["total_units"])),
            cpu_seconds=float(item.get("cpu_seconds", 0.0)),
            memory_bytes=int(item.get("memory_bytes", 0)),
            result=result,
            error=error,
            logs=[
                *self._note_lines(job_id),
                *(
                    JobLogLine(
                        age_seconds=min(86_400.0, max(0.0, now - t)), message=str(what)[:200]
                    )
                    for t, what in events
                ),
            ][-MAX_LOG_LINES_PER_REPORT:],
        )

    def _package_report(
        self, job_id: str, entry: dict[str, Any], item: dict[str, Any] | None, now: float
    ) -> AgentJobReport:
        phase = entry.get("phase", "staging")
        base: dict[str, Any] = {
            "job_id": uuid.UUID(job_id),
            "attempt": int(entry["attempt"]),
            "units_done": 0,
            "logs": self._note_lines(job_id),
        }
        if item is not None:
            base["cpu_seconds"] = float(item.get("cpu_seconds", 0.0))
            base["memory_bytes"] = int(item.get("memory_bytes", 0))
        if phase == "failed":
            result = entry.get("result")
            return AgentJobReport(
                **base,
                state=LocalJobState.FAILED,
                failure=FailureKind(entry.get("failure", "infrastructure")),
                error=str(entry.get("error", "package run failed"))[:300],
                package_result=PackageResult.model_validate(result) if result else None,
            )
        if phase == "done":
            return AgentJobReport(
                **base,
                state=LocalJobState.COMPLETED,
                package_result=PackageResult.model_validate(entry["result"]),
            )
        if phase == "staging":
            return AgentJobReport(**base, state=LocalJobState.STAGING)
        if item is None:  # ready, but the workload is gone (lost add request): re-add
            if self._wall() - float(entry.get("added_at", 0)) > READD_AFTER_SECONDS:
                self._queue_add(job_id, entry)
            return AgentJobReport(**base, state=LocalJobState.WAITING)
        state = LocalJobState(str(item["state"]))
        if state in (LocalJobState.COMPLETED, LocalJobState.FAILED):
            state = LocalJobState.UPLOADING  # finished locally; outputs not yet uploaded
        report = self._report(job_id, entry, item, now)
        return report.model_copy(
            update={"state": state, "units_done": 0, "result": None, "error": None}
        )

    def _note(self, job_id: str, message: str) -> None:
        self._notes.setdefault(job_id, []).append(message[:200])
        del self._notes[job_id][:-10]
        logger.info("job %s: %s", job_id, message)

    def _note_lines(self, job_id: str) -> list[JobLogLine]:
        # Sent until a response is applied (like the event cursor), then cleared.
        return [JobLogLine(age_seconds=0, message=m) for m in self._notes.get(job_id, [])]

    # -- response ------------------------------------------------------------------------------

    def apply(self, response: JobSyncResponse) -> None:
        self._log_cursor.update(self._pending_cursor)
        self._pending_cursor = {}
        self._notes = {}  # delivered with the request this response answers
        for job_id in [*response.cancel, *response.acknowledged]:
            self._refused.pop(str(job_id), None)
        # Removals first, so a job that was acknowledged and then reassigned in the same
        # response starts from a clean directory.
        for job_id in [*response.cancel, *response.acknowledged]:
            key = str(job_id)
            if self._assignments.pop(key, None) is not None:
                self._save()
            self._log_cursor.pop(key, None)
            self._uploaded_units.pop(key, None)
            self._last_upload.pop(key, None)
            WorkloadManager.queue_request(
                self.data_dir, "remove", workload_id=workload_id(job_id), purge=True
            )
            self._stale_staging.add(key)  # deleted once the workload is gone (next sync)
            why = "cancelled by controller" if job_id in response.cancel else "done"
            logger.info("job %s %s", key, why)
        for assignment in response.assignments:
            key = str(assignment.job_id)
            if assignment.spec.package is not None and not user_code_offered(self._isolation):
                # Defence in depth: this node does not offer user code, so the controller
                # should never send it. If it does, refuse and run nothing.
                self._refused[key] = assignment.attempt
                logger.error("refused user-code job %s: user code is not offered here", key)
                continue
            entry = self._assignments.get(key)
            if entry is not None and entry.get("package"):
                if int(entry["attempt"]) < assignment.attempt:
                    # Re-assigned after a lease loss: outputs are bound to the attempt, so
                    # the run starts again from staging (its checkpoint, if any, is kept
                    # centrally and restored).
                    WorkloadManager.queue_request(
                        self.data_dir,
                        "remove",
                        workload_id=workload_id(assignment.job_id),
                        purge=True,
                    )
                    self._stale_staging.add(key)
                    entry = None
                    del self._assignments[key]
                else:
                    continue
            if entry is not None:
                if int(entry["attempt"]) < assignment.attempt:
                    # Re-assigned to us after a lease loss: keep the local progress.
                    entry["attempt"] = assignment.attempt
                    self._save()
                continue
            entry = {
                "attempt": assignment.attempt,
                "spec": assignment.spec.model_dump(mode="json"),
                "added_at": self._wall(),
                "isolation": self._isolation,
            }
            if assignment.spec.package is not None:
                entry["package"] = assignment.spec.package
                entry["phase"] = "staging"  # nothing runs until every byte verified
                if assignment.checkpoint is not None:
                    entry["resume"] = assignment.checkpoint.model_dump(mode="json")
                self._assignments[key] = entry
                self._save()
                self._stale_staging.discard(key)
                logger.info("package job %s accepted (attempt %s)", key, assignment.attempt)
                continue
            if assignment.checkpoint is not None:
                # Resume elsewhere-made progress: fetch and verify before the workload exists.
                entry["resume"] = assignment.checkpoint.model_dump(mode="json")
            self._assignments[key] = entry
            self._save()  # persisted before the workload exists
            if "resume" not in entry:
                self._queue_add(key, entry)
            logger.info(
                "job %s accepted (%s, %s)", key, assignment.spec.kind.value, self._isolation
            )

    def _queue_add(self, job_id: str, entry: dict[str, Any]) -> None:
        spec = entry["spec"]
        if entry.get("package"):
            run = entry["run"]
            limits = PackageRunLimits.model_validate(spec["limits"])
            WorkloadManager.queue_request(
                self.data_dir,
                "add",
                spec=WorkloadSpec(
                    id=workload_id(uuid.UUID(job_id)),
                    kind=spec["kind"],
                    total_units=1,
                    memory_mb=int(spec["memory_mb"]),
                    checkpointable=False,  # evicted runs are killed and restarted
                    isolation="appcontainer",  # never anything weaker for user code
                    package_root=run["root"],
                    entry=run["entry"],
                    args=list(run["args"]),
                    import_paths=list(run["import_paths"]),
                    read_only=list(run["read_only"]),
                    max_runtime_seconds=limits.max_runtime_seconds,
                    storage_bytes=package_runs.storage_budget(limits),
                ),
            )
            entry["added_at"] = self._wall()
            return
        WorkloadManager.queue_request(
            self.data_dir,
            "add",
            spec=WorkloadSpec(
                id=workload_id(uuid.UUID(job_id)),
                kind=spec["kind"],
                total_units=int(spec["total_units"]),
                memory_mb=int(spec["memory_mb"]),
                isolation=str(entry.get("isolation", "host")),
            ),
        )
        entry["added_at"] = self._wall()

    def sync_once(self, controller: JobController) -> JobSyncResponse:
        response = controller.sync_jobs(self.build_request())
        self.apply(response)
        self.clean_staging()
        self.resume_pending(controller)
        self.prepare_packages(controller)
        self.finish_packages(controller)
        self.upload_checkpoints(controller)
        return response

    # -- package runs (ADR 0003) ---------------------------------------------------------------

    def clean_staging(self) -> None:
        """Staging trees of jobs that are no longer ours. Deferred one sync after the
        workload's removal is queued, so the process tree is gone first."""
        for job_id in list(self._stale_staging):
            if job_id in self._assignments:
                self._stale_staging.discard(job_id)
                continue
            if job_id in self._staging_removal_due:
                package_runs.remove_runs(self.data_dir, job_id)
                self._staging_removal_due.discard(job_id)
                self._stale_staging.discard(job_id)
            else:
                self._staging_removal_due.add(job_id)

    def _fail_package(
        self, job_id: str, entry: dict[str, Any], error: str, kind: FailureKind
    ) -> None:
        entry["phase"] = "failed"
        entry["error"] = error[:300]
        entry["failure"] = kind.value
        self._save()
        self._note(job_id, error)

    def prepare_packages(self, controller) -> None:
        """Fetch, verify and stage packages that were accepted. A transient problem
        leaves the job staging (retried next sync); anything else fails the attempt."""
        if not hasattr(controller, "package_closure"):
            return
        if not any(
            e.get("package") and e.get("phase") == "staging" for e in self._assignments.values()
        ):
            return  # catalog-only syncs do no package work at all
        cache = NodeCache(self.data_dir)
        for job_id, entry in list(self._assignments.items()):
            if not entry.get("package") or entry.get("phase") != "staging":
                continue
            try:
                run = package_runs.prepare(
                    controller,
                    self.data_dir,
                    cache,
                    uuid.UUID(job_id),
                    int(entry["attempt"]),
                    entry["package"],
                    python=NODE_PYTHON,
                    platform=NODE_PLATFORM,
                )
            except package_runs.RetryLater as exc:
                logger.info("package job %s: staging delayed: %s", job_id, exc)
                continue
            except package_runs.RunFailed as exc:
                self._fail_package(job_id, entry, str(exc), exc.kind)
                continue
            if "resume" in entry:
                self._restore_package_checkpoint(controller, job_id, entry, run.root)
            entry["run"] = {
                "root": str(run.root),
                "entry": run.entry,
                "args": run.args,
                "import_paths": run.import_paths,
                "read_only": run.read_only,
            }
            entry["phase"] = "ready"
            self._save()
            self._queue_add(job_id, entry)
            self._note(job_id, "package verified and staged")

    def _restore_package_checkpoint(self, controller, job_id: str, entry, root: Path) -> None:
        ref = entry.pop("resume")
        try:
            download = controller.get_checkpoint(uuid.UUID(job_id), int(entry["attempt"]))
            payload = base64.b64decode(download.payload_b64, validate=True)
        except (ControllerUnavailable, ProtocolError, binascii.Error, ValueError) as exc:
            self._note(job_id, f"package checkpoint unavailable ({str(exc)[:80]}); starting fresh")
            return
        digest = hashlib.sha256(payload).hexdigest()
        if (
            digest != download.sha256
            or digest != ref["sha256"]
            or download.version != ref["version"]
        ):
            self._note(job_id, "package checkpoint failed verification; starting fresh")
            return
        package_runs.install_checkpoint(root, payload)
        entry["ckpt_sha"] = digest
        self._note(job_id, f"restored package checkpoint v{ref['version']} into state/")

    def finish_packages(self, controller) -> None:
        """After a run's process tree is gone: collect, upload and record the result."""
        if not hasattr(controller, "put_outputs"):
            return
        snapshot = self._snapshot(WORKLOAD_PREFIX)
        for job_id, entry in list(self._assignments.items()):
            if not entry.get("package") or entry.get("phase") != "ready":
                continue
            item = snapshot.get(workload_id(uuid.UUID(job_id)))
            if item is None or item.get("state") not in ("completed", "failed"):
                continue
            root = Path(entry["run"]["root"])
            limits = PackageRunLimits.model_validate(entry["spec"]["limits"])
            for line in package_runs.log_tail(root):
                self._note(job_id, line)
            outcome = str(item.get("outcome") or "")
            exit_code = item.get("last_exit_code")
            if item["state"] == "failed":
                if outcome == "runtime_limit":
                    message = f"runtime limit exceeded ({limits.max_runtime_seconds} s)"
                    self._fail_package(job_id, entry, message, FailureKind.WORKLOAD)
                elif outcome == "storage_limit":
                    message = "storage limit exceeded (out/, state/, logs/, tmp/)"
                    self._fail_package(job_id, entry, message, FailureKind.WORKLOAD)
                else:
                    message = f"package could not run on this node ({outcome or 'failed'})"
                    self._fail_package(job_id, entry, message, FailureKind.INFRASTRUCTURE)
                continue
            try:
                result = package_runs.finish(
                    controller, uuid.UUID(job_id), root, int(entry["attempt"]), limits, exit_code
                )
            except package_runs.RetryLater as exc:
                logger.info("package job %s: upload delayed: %s", job_id, exc)
                continue
            except package_runs.RunFailed as exc:
                self._fail_package(job_id, entry, str(exc), exc.kind)
                continue
            entry["phase"] = "done"
            entry["result"] = result.model_dump(mode="json")
            self._save()
            self._note(job_id, f"exited with code {exit_code}; {result.files} outputs uploaded")

    # -- central checkpoints -------------------------------------------------------------------

    def _workdir(self, job_id: str) -> Path:
        return self.data_dir / "workloads" / workload_id(uuid.UUID(job_id))

    def resume_pending(self, controller: JobController) -> None:
        """Fetch, verify and install central checkpoints for resumed assignments. A network
        failure leaves the job waiting (retried next sync). A checkpoint that fails
        verification is never used: the job then starts from zero, and its log says why."""
        for job_id, entry in list(self._assignments.items()):
            ref = entry.get("resume")
            if ref is None or entry.get("package"):
                continue  # package checkpoints are restored after staging
            problem: str | None
            try:
                download = controller.get_checkpoint(uuid.UUID(job_id), int(entry["attempt"]))
            except ControllerUnavailable:
                continue  # try again next sync; the workload is not started yet
            except ProtocolError as exc:
                problem = f"central checkpoint unavailable ({exc})"
                payload = b""
            else:
                payload, problem = self._verify_download(download, ref, entry)
            workdir = self._workdir(job_id)
            if problem is None:
                workdir.mkdir(parents=True, exist_ok=True)
                for stale in ("status.json", "result.json", "control.json"):
                    (workdir / stale).unlink(missing_ok=True)
                tmp = workdir / "checkpoint.tmp"
                tmp.write_bytes(payload)
                os.replace(tmp, workdir / "checkpoint.json")
                self._uploaded_units[job_id] = int(ref["units_done"])
                self._note(
                    job_id,
                    f"resumed from central checkpoint v{ref['version']} "
                    f"at {ref['units_done']} units",
                )
            else:
                (workdir / "checkpoint.json").unlink(missing_ok=True)
                self._note(job_id, f"{problem}; starting from 0")
            del entry["resume"]
            self._save()
            self._queue_add(job_id, entry)

    @staticmethod
    def _verify_download(
        download: CheckpointDownload, ref: dict[str, Any], entry: dict[str, Any]
    ) -> tuple[bytes, str | None]:
        try:
            payload = base64.b64decode(download.payload_b64, validate=True)
        except (binascii.Error, ValueError):
            return b"", "central checkpoint is not valid base64"
        digest = hashlib.sha256(payload).hexdigest()
        if digest != download.sha256 or digest != ref["sha256"]:
            return b"", "central checkpoint failed its sha256 check"
        if download.version != ref["version"] or download.units_done != ref["units_done"]:
            return b"", "central checkpoint changed since assignment (stale reference)"
        problem = validate_catalog_checkpoint(
            payload,
            units_done=int(ref["units_done"]),
            total_units=int(entry["spec"]["total_units"]),
        )
        return payload, problem

    def upload_checkpoints(self, controller: JobController) -> None:
        """Send each running job's newest local checkpoint when its progress has advanced.
        `version` is units_done, so it is monotonic per attempt and survives agent
        restarts; a retried upload is idempotent on the controller."""
        now = self._clock()
        for job_id, entry in self._assignments.items():
            if "resume" in entry:
                continue
            if now - self._last_upload.get(job_id, float("-inf")) < self._upload_every:
                continue
            if entry.get("package"):
                if self._upload_package_checkpoint(controller, job_id, entry) is False:
                    return
                self._last_upload[job_id] = now
                continue
            try:
                payload = (self._workdir(job_id) / "checkpoint.json").read_bytes()
                units = int(json.loads(payload)["units_done"])
            except (FileNotFoundError, ValueError, KeyError, TypeError, OSError):
                continue  # nothing checkpointed yet (or mid-write; read again next time)
            if units <= self._uploaded_units.get(job_id, 0) or len(payload) > MAX_CHECKPOINT_BYTES:
                continue
            upload = CheckpointUpload(
                attempt=int(entry["attempt"]),
                version=units,
                units_done=units,
                sha256=hashlib.sha256(payload).hexdigest(),
                payload_b64=base64.b64encode(payload).decode("ascii"),
            )
            try:
                controller.put_checkpoint(uuid.UUID(job_id), upload)
            except ControllerUnavailable:
                return  # the controller is gone; the heartbeat loop backs off
            except ProtocolError as exc:
                logger.warning("checkpoint upload for job %s rejected: %s", job_id, exc)
                self._uploaded_units[job_id] = units  # do not resend the same state
                continue
            self._uploaded_units[job_id] = units
            self._last_upload[job_id] = now

    def _upload_package_checkpoint(self, controller, job_id: str, entry) -> bool | None:
        """A package's own state/checkpoint.bin (opaque, at most 1 MiB), uploaded when its
        content changes. False if the controller is unreachable."""
        if entry.get("phase") != "ready" or "run" not in entry:
            return None
        path = package_runs.checkpoint_path(Path(entry["run"]["root"]))
        try:
            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_size > MAX_CHECKPOINT_BYTES
            ):
                return None
            payload = path.read_bytes()
        except OSError:
            return None
        if not payload or len(payload) > MAX_CHECKPOINT_BYTES:
            return None
        digest = hashlib.sha256(payload).hexdigest()
        if digest == entry.get("ckpt_sha"):
            return None
        version = int(entry.get("ckpt_version", 0)) + 1
        upload = CheckpointUpload(
            attempt=int(entry["attempt"]),
            version=version,
            units_done=0,
            sha256=digest,
            payload_b64=base64.b64encode(payload).decode("ascii"),
        )
        try:
            controller.put_checkpoint(uuid.UUID(job_id), upload)
        except ControllerUnavailable:
            return False
        except ProtocolError as exc:
            logger.warning("package checkpoint for job %s rejected: %s", job_id, exc)
        entry["ckpt_sha"], entry["ckpt_version"] = digest, version
        self._save()
        return None
