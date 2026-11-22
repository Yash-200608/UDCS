"""JobSync: the agent's side of the pipeline, without processes or a network."""

from __future__ import annotations

import json
import uuid

import pytest

from udcs_agent.governor.engine import AdmissionView
from udcs_agent.jobs import JobSync, workload_id
from udcs_shared.jobs import (
    JobAssignment,
    JobSpec,
    JobSyncResponse,
    LocalJobState,
    expected_checksum,
)
from udcs_shared.protection import ProtectionLevel, ProtectionPolicy, WorkloadClass

POLICY = ProtectionPolicy()
GiB = 2**30


def _view(level=ProtectionLevel.OPEN, reasons=(), maintenance=False, udcs_memory=0):
    return AdmissionView(
        level=level,
        reasons=frozenset(reasons),
        maintenance=maintenance,
        envelope=POLICY.envelopes[level],
        memory_total_bytes=16 * GiB,
        udcs_memory_bytes=udcs_memory,
    )


class Harness:
    def __init__(self, tmp_path, *, has_gpu=False, max_jobs=2):
        self.tmp_path = tmp_path
        self.snapshot: dict[str, dict] = {}
        self.view: AdmissionView | None = _view()
        self.now = [100.0]
        self.wall = [1_000_000.0]
        self.sync = self._make(has_gpu, max_jobs)

    def _make(self, has_gpu, max_jobs):
        return JobSync(
            self.tmp_path,
            snapshot=lambda prefix: {
                k: v for k, v in self.snapshot.items() if k.startswith(prefix)
            },
            admission=lambda: self.view,
            has_gpu=has_gpu,
            max_jobs=max_jobs,
            clock=lambda: self.now[0],
            wall_clock=lambda: self.wall[0],
        )

    def restart(self):
        self.sync = self._make(False, 2)

    def requests(self):
        folder = self.tmp_path / "workloads" / "requests"
        paths = sorted(folder.glob("*.json"), key=lambda p: p.name)
        return [json.loads(p.read_text()) for p in paths]


def _assign(job_id=None, attempt=1, kind="cpu", units=20):
    return JobAssignment(
        job_id=job_id or uuid.uuid4(),
        attempt=attempt,
        spec=JobSpec(kind=WorkloadClass(kind), total_units=units),
    )


def _response(assignments=(), cancel=(), acknowledged=()):
    return JobSyncResponse(
        assignments=list(assignments),
        cancel=list(cancel),
        acknowledged=list(acknowledged),
        lease_seconds=120,
    )


@pytest.mark.parametrize(
    ("view", "reason"),
    [
        (None, "not assessed yet"),
        (_view(maintenance=True), "maintenance"),
        (_view(ProtectionLevel.PROTECTED), "level protected"),
        (_view(ProtectionLevel.CONSTRAINED), "level constrained"),
        (_view(reasons=("cpu_pressure",)), "cpu_pressure"),
        (_view(reasons=("paging",)), "paging"),
    ],
)
def test_no_new_work_while_the_student_needs_the_machine(tmp_path, view, reason):
    h = Harness(tmp_path)
    h.view = view
    capacity = h.sync.capacity()
    assert not capacity.accept and capacity.slots == 0 and capacity.reason == reason


def test_offer_follows_the_local_envelope(tmp_path):
    h = Harness(tmp_path, has_gpu=True)
    open_offer = h.sync.capacity()
    assert open_offer.accept and set(open_offer.kinds) == set(WorkloadClass)
    budget = 16 * GiB * POLICY.envelopes[ProtectionLevel.OPEN].udcs_memory_budget_percent / 100
    assert open_offer.memory_available_mb == int(budget // 2**20)

    h.view = _view(ProtectionLevel.SHARED)  # student active: the envelope decides
    shared = POLICY.envelopes[ProtectionLevel.SHARED]
    kinds = set(h.sync.capacity().kinds)
    assert (WorkloadClass.MEMORY in kinds) == shared.allow_memory_class
    assert (WorkloadClass.GPU in kinds) == shared.allow_gpu_class
    assert WorkloadClass.CPU in kinds

    h.view = _view(reasons=("gpu_demand", "disk_pressure"))
    assert set(h.sync.capacity().kinds) == {WorkloadClass.CPU, WorkloadClass.MEMORY}

    no_gpu = Harness(tmp_path / "b", has_gpu=False)
    assert WorkloadClass.GPU not in no_gpu.sync.capacity().kinds


def test_assignment_is_persisted_before_the_workload_is_requested(tmp_path):
    h = Harness(tmp_path, max_jobs=1)
    a = _assign(units=7)
    h.sync.apply(_response([a]))
    saved = json.loads((tmp_path / "jobs" / "assignments.json").read_text())
    assert saved[str(a.job_id)]["attempt"] == 1
    [request] = h.requests()
    assert request["action"] == "add" and request["spec"]["id"] == workload_id(a.job_id)
    assert request["spec"]["total_units"] == 7
    # One slot, now used.
    assert h.sync.capacity().reason == "all job slots in use"
    # Not ingested yet: still reported, as waiting.
    [report] = h.sync.build_request().reports
    assert report.state == LocalJobState.WAITING and report.attempt == 1


def test_reports_progress_logs_once_and_a_verified_result(tmp_path):
    h = Harness(tmp_path)
    a = _assign(units=20)
    h.sync.apply(_response([a]))
    wid = workload_id(a.job_id)
    h.snapshot[wid] = {
        "state": "paused",
        "units_done": 8,
        "cpu_seconds": 1.5,
        "memory_bytes": 10,
        "failures": 0,
        "last_exit_code": None,
        "events": [(90.0, "started"), (95.0, "paused")],
        "result": None,
    }
    first = h.sync.build_request().reports[0]
    assert first.state == LocalJobState.PAUSED and first.units_done == 8
    assert [line.message for line in first.logs] == ["started", "paused"]
    assert first.logs[0].age_seconds == pytest.approx(10.0)
    # The response was lost (no apply): the same lines are sent again.
    assert len(h.sync.build_request().reports[0].logs) == 2
    h.sync.apply(_response())
    assert h.sync.build_request().reports[0].logs == []

    h.snapshot[wid].update(
        state="completed",
        units_done=20,
        result={"units": 20, "checksum": str(expected_checksum(20))},
    )
    done = h.sync.build_request().reports[0]
    assert done.state == LocalJobState.COMPLETED and done.result.units == 20


def test_missing_or_corrupt_result_and_local_failure_are_reported_as_failed(tmp_path):
    h = Harness(tmp_path)
    a, b = _assign(), _assign()
    h.sync.apply(_response([a, b]))
    base = {"units_done": 1, "events": [], "failures": 3, "last_exit_code": 2}
    h.snapshot[workload_id(a.job_id)] = {**base, "state": "completed", "result": {"units": "x"}}
    h.snapshot[workload_id(b.job_id)] = {**base, "state": "failed", "result": None}
    reports = {r.job_id: r for r in h.sync.build_request().reports}
    assert reports[a.job_id].state == LocalJobState.FAILED
    assert "valid result" in reports[a.job_id].error
    assert reports[b.job_id].state == LocalJobState.FAILED
    assert "exit code 2" in reports[b.job_id].error


def test_cancel_and_acknowledge_remove_and_purge(tmp_path):
    h = Harness(tmp_path)
    a, b = _assign(), _assign()
    h.sync.apply(_response([a, b]))
    h.sync.apply(_response(cancel=[a.job_id], acknowledged=[b.job_id]))
    assert h.sync.job_ids == []
    removes = [r for r in h.requests() if r["action"] == "remove"]
    assert {r["id"] for r in removes} == {workload_id(a.job_id), workload_id(b.job_id)}
    assert all(r["purge"] for r in removes)


def test_reassignment_after_lease_loss_keeps_local_progress(tmp_path):
    h = Harness(tmp_path)
    a = _assign()
    h.sync.apply(_response([a]))
    h.sync.apply(_response([_assign(a.job_id, attempt=3)]))
    assert [r["action"] for r in h.requests()] == ["add"]  # no second workload
    assert h.sync.build_request().reports[0].attempt == 3


def test_restart_reloads_assignments_and_drops_orphans(tmp_path):
    h = Harness(tmp_path)
    a = _assign()
    h.sync.apply(_response([a]))
    h.restart()
    orphan = workload_id(uuid.uuid4())
    h.snapshot[orphan] = {"state": "running", "events": [], "units_done": 0}
    request = h.sync.build_request()
    assert [r.job_id for r in request.reports] == [a.job_id]
    assert {"action": "remove", "id": orphan, "purge": True} in h.requests()


def test_lost_add_request_is_requeued(tmp_path):
    h = Harness(tmp_path)
    a = _assign()
    h.sync.apply(_response([a]))
    for path in (tmp_path / "workloads" / "requests").glob("*.json"):
        path.unlink()  # e.g. removed by cleanup before the governor ingested it
    h.wall[0] += 11
    h.sync.build_request()
    assert [r["action"] for r in h.requests()] == ["add"]


def test_corrupt_assignment_file_starts_empty(tmp_path):
    (tmp_path / "jobs").mkdir()
    (tmp_path / "jobs" / "assignments.json").write_text("{not json")
    assert Harness(tmp_path).sync.job_ids == []
