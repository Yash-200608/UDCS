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
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from udcs_agent.communication.client import ControllerUnavailable, ProtocolError
from udcs_agent.governor.engine import AdmissionView
from udcs_agent.workloads.manager import WorkloadManager, WorkloadSpec
from udcs_shared.agent_api import PROTOCOL_VERSION
from udcs_shared.jobs import (
    MAX_ASSIGNMENTS_PER_SYNC,
    MAX_CHECKPOINT_BYTES,
    MAX_LOG_LINES_PER_REPORT,
    AgentJobReport,
    CheckpointDownload,
    CheckpointUpload,
    JobLogLine,
    JobResult,
    JobSyncRequest,
    JobSyncResponse,
    LocalJobState,
    NodeJobCapacity,
    validate_catalog_checkpoint,
)
from udcs_shared.protection import ProtectionLevel, WorkloadClass

logger = logging.getLogger(__name__)

WORKLOAD_PREFIX = "job-"
# User code stays off on every node until ADR 0001's remaining gates pass. It is a
# constant, not configuration, so it cannot be switched on by a config file on a lab PC.
USER_CODE_ENABLED = False
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
        return NodeJobCapacity(accept=True, slots=slots, kinds=kinds, memory_available_mb=memory_mb)

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
                    error="user code execution is disabled on this node",
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
            why = "cancelled by controller" if job_id in response.cancel else "done"
            logger.info("job %s %s", key, why)
        for assignment in response.assignments:
            key = str(assignment.job_id)
            if assignment.spec.package is not None and not USER_CODE_ENABLED:
                # Defence in depth: this node never offers user code, so the controller
                # should never send it. If it does, refuse and run nothing.
                self._refused[key] = assignment.attempt
                logger.error("refused user-code job %s: user code is disabled", key)
                continue
            entry = self._assignments.get(key)
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
        self.resume_pending(controller)
        self.upload_checkpoints(controller)
        return response

    # -- central checkpoints -------------------------------------------------------------------

    def _workdir(self, job_id: str) -> Path:
        return self.data_dir / "workloads" / workload_id(uuid.UUID(job_id))

    def resume_pending(self, controller: JobController) -> None:
        """Fetch, verify and install central checkpoints for resumed assignments. A network
        failure leaves the job waiting (retried next sync). A checkpoint that fails
        verification is never used: the job then starts from zero, and its log says why."""
        for job_id, entry in list(self._assignments.items()):
            ref = entry.get("resume")
            if ref is None:
                continue
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
