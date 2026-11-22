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

import json
import logging
import os
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from pydantic import ValidationError

from udcs_agent.governor.engine import AdmissionView
from udcs_agent.workloads.manager import WorkloadManager, WorkloadSpec
from udcs_shared.agent_api import PROTOCOL_VERSION
from udcs_shared.jobs import (
    MAX_ASSIGNMENTS_PER_SYNC,
    MAX_LOG_LINES_PER_REPORT,
    AgentJobReport,
    JobLogLine,
    JobResult,
    JobSyncRequest,
    JobSyncResponse,
    LocalJobState,
    NodeJobCapacity,
)
from udcs_shared.protection import ProtectionLevel, WorkloadClass

logger = logging.getLogger(__name__)

WORKLOAD_PREFIX = "job-"
READD_AFTER_SECONDS = 10.0
_NO_NEW_WORK_LEVELS = {
    ProtectionLevel.CONSTRAINED,
    ProtectionLevel.PROTECTED,
    ProtectionLevel.MAINTENANCE,
}
_PRESSURE = ("cpu_pressure", "memory_pressure", "paging", "signals_unavailable")


class JobController(Protocol):
    def sync_jobs(self, request: JobSyncRequest) -> JobSyncResponse: ...


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
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.data_dir = data_dir
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
                if self._wall() - float(entry.get("added_at", 0)) > READD_AFTER_SECONDS:
                    self._queue_add(job_id, entry)  # the add request was lost; idempotent
                reports.append(
                    AgentJobReport(
                        job_id=uuid.UUID(job_id),
                        attempt=int(entry["attempt"]),
                        state=LocalJobState.WAITING,
                        units_done=0,
                    )
                )
                continue
            reports.append(self._report(job_id, entry, item, now))
        capacity = self.capacity()
        offer = "accepting" if capacity.accept else f"no new work: {capacity.reason}"
        if offer != self._last_offer:  # log changes only, not every sync
            logger.info("job offer: %s", offer)
            self._last_offer = offer
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
                JobLogLine(age_seconds=min(86_400.0, max(0.0, now - t)), message=str(what)[:200])
                for t, what in events
            ],
        )

    # -- response ------------------------------------------------------------------------------

    def apply(self, response: JobSyncResponse) -> None:
        self._log_cursor.update(self._pending_cursor)
        self._pending_cursor = {}
        # Removals first, so a job that was acknowledged and then reassigned in the same
        # response starts from a clean directory.
        for job_id in [*response.cancel, *response.acknowledged]:
            key = str(job_id)
            if self._assignments.pop(key, None) is not None:
                self._save()
            self._log_cursor.pop(key, None)
            WorkloadManager.queue_request(
                self.data_dir, "remove", workload_id=workload_id(job_id), purge=True
            )
            why = "cancelled by controller" if job_id in response.cancel else "done"
            logger.info("job %s %s", key, why)
        for assignment in response.assignments:
            key = str(assignment.job_id)
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
            }
            self._assignments[key] = entry
            self._save()  # persisted before the workload exists
            self._queue_add(key, entry)
            logger.info("job %s accepted (%s)", key, assignment.spec.kind.value)

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
            ),
        )
        entry["added_at"] = self._wall()

    def sync_once(self, controller: JobController) -> JobSyncResponse:
        response = controller.sync_jobs(self.build_request())
        self.apply(response)
        return response
