"""JobSync: the agent's side of the pipeline, without processes or a network."""

from __future__ import annotations

import base64
import hashlib
import json
import uuid

import pytest

from udcs_agent.communication.client import ControllerUnavailable, ProtocolError
from udcs_agent.governor.engine import AdmissionView
from udcs_agent.jobs import JobSync, workload_id
from udcs_shared.jobs import (
    CheckpointDownload,
    CheckpointRef,
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


# -- central checkpoints ----------------------------------------------------------------------


def _ckpt_bytes(units, checksum=None):
    value = expected_checksum(units) if checksum is None else checksum
    return json.dumps({"units_done": units, "checksum": value}).encode()


class FakeController:
    def __init__(self):
        self.uploads = []
        self.stored: dict[uuid.UUID, bytes] = {}
        self.get_error: Exception | None = None
        self.put_error: Exception | None = None
        self.tamper = False

    def put_checkpoint(self, job_id, upload):
        if self.put_error:
            raise self.put_error
        self.uploads.append((job_id, upload))

    def get_checkpoint(self, job_id, attempt):
        if self.get_error:
            raise self.get_error
        payload = self.stored[job_id]
        digest = hashlib.sha256(payload).hexdigest()
        units = json.loads(payload)["units_done"]
        if self.tamper:  # corrupted in transit or at rest: bytes no longer match the hash
            payload = payload.replace(b"units", b"unitz")
        return CheckpointDownload(
            version=1,
            units_done=units,
            sha256=digest,
            payload_b64=base64.b64encode(payload).decode(),
        )


def _resumed_assignment(fake, units=40, total=100, payload=None):
    job_id = uuid.uuid4()
    fake.stored[job_id] = payload if payload is not None else _ckpt_bytes(units)
    ref = CheckpointRef(
        version=1,
        units_done=units,
        sha256=hashlib.sha256(fake.stored[job_id]).hexdigest(),
        size=len(fake.stored[job_id]),
    )
    return JobAssignment(
        job_id=job_id,
        attempt=2,
        spec=JobSpec(kind=WorkloadClass.CPU, total_units=total),
        checkpoint=ref,
    )


def _installed(tmp_path, job_id):
    return tmp_path / "workloads" / workload_id(job_id) / "checkpoint.json"


def test_resumed_assignment_installs_a_verified_checkpoint_before_the_workload_starts(tmp_path):
    h, fake = Harness(tmp_path), FakeController()
    a = _resumed_assignment(fake, units=40)
    h.sync.apply(_response([a]))
    assert h.requests() == [], "no workload before the checkpoint is installed"
    assert h.sync.build_request().reports[0].state == LocalJobState.WAITING

    h.sync.resume_pending(fake)
    assert json.loads(_installed(tmp_path, a.job_id).read_text())["units_done"] == 40
    assert [r["action"] for r in h.requests()] == ["add"]  # only now
    logs = [line.message for line in h.sync.build_request().reports[0].logs]
    assert logs == ["resumed from central checkpoint v1 at 40 units"]
    saved = json.loads((tmp_path / "jobs" / "assignments.json").read_text())
    assert "resume" not in saved[str(a.job_id)]  # no second download after a restart


def test_controller_outage_during_download_keeps_the_job_waiting(tmp_path):
    h, fake = Harness(tmp_path), FakeController()
    a = _resumed_assignment(fake)
    h.sync.apply(_response([a]))
    fake.get_error = ControllerUnavailable("down")
    h.sync.resume_pending(fake)
    h.wall[0] += 60  # even long after: no blind re-add while a resume is pending
    h.sync.build_request()
    assert h.requests() == []
    fake.get_error = None
    h.sync.resume_pending(fake)
    assert [r["action"] for r in h.requests()] == ["add"]
    assert _installed(tmp_path, a.job_id).exists()


@pytest.mark.parametrize("failure", ["tampered", "inconsistent", "missing"])
def test_unusable_central_checkpoint_is_never_used(tmp_path, failure):
    h, fake = Harness(tmp_path), FakeController()
    if failure == "inconsistent":  # genuine hash, but the content contradicts itself
        a = _resumed_assignment(fake, payload=_ckpt_bytes(40, checksum=7))
    else:
        a = _resumed_assignment(fake)
    h.sync.apply(_response([a]))
    if failure == "tampered":
        fake.tamper = True
    if failure == "missing":
        fake.get_error = ProtocolError("HTTP 404: no checkpoint")
    h.sync.resume_pending(fake)
    assert not _installed(tmp_path, a.job_id).exists()
    assert [r["action"] for r in h.requests()] == ["add"]  # starts from zero instead
    [line] = h.sync.build_request().reports[0].logs
    expected = {"tampered": "sha256", "inconsistent": "checksum", "missing": "unavailable"}
    assert expected[failure] in line.message and line.message.endswith("starting from 0")


def _write_local_checkpoint(tmp_path, job_id, units):
    workdir = tmp_path / "workloads" / workload_id(job_id)
    workdir.mkdir(parents=True, exist_ok=True)
    (workdir / "checkpoint.json").write_bytes(_ckpt_bytes(units))


def _uploader(tmp_path, h, every):
    return JobSync(
        tmp_path,
        snapshot=lambda p: {},
        admission=lambda: None,
        has_gpu=False,
        checkpoint_upload_seconds=every,
        clock=lambda: h.now[0],
    )


def test_uploads_only_advancing_progress_with_monotonic_versions(tmp_path):
    h, fake = Harness(tmp_path), FakeController()
    h.sync = _uploader(tmp_path, h, every=0)
    a = _assign(units=100)
    h.sync.apply(_response([a]))
    h.sync.upload_checkpoints(fake)
    assert fake.uploads == []  # nothing checkpointed yet
    _write_local_checkpoint(tmp_path, a.job_id, 30)
    h.sync.upload_checkpoints(fake)
    h.sync.upload_checkpoints(fake)  # unchanged: not resent
    _write_local_checkpoint(tmp_path, a.job_id, 55)
    h.sync.upload_checkpoints(fake)
    assert [(u.units_done, u.version, u.attempt) for _, u in fake.uploads] == [
        (30, 30, 1),
        (55, 55, 1),
    ]
    _, last = fake.uploads[-1]
    assert hashlib.sha256(base64.b64decode(last.payload_b64)).hexdigest() == last.sha256


def test_upload_interval_and_rejection_handling(tmp_path):
    h, fake = Harness(tmp_path), FakeController()
    h.sync = _uploader(tmp_path, h, every=15)
    a = _assign(units=100)
    h.sync.apply(_response([a]))
    _write_local_checkpoint(tmp_path, a.job_id, 10)
    h.sync.upload_checkpoints(fake)
    _write_local_checkpoint(tmp_path, a.job_id, 20)
    h.now[0] += 5
    h.sync.upload_checkpoints(fake)  # too soon
    assert len(fake.uploads) == 1
    h.now[0] += 11
    fake.put_error = ProtocolError("HTTP 409: stale")
    h.sync.upload_checkpoints(fake)  # rejected (e.g. fenced): logged, not resent
    fake.put_error = None
    h.now[0] += 20
    h.sync.upload_checkpoints(fake)
    assert len(fake.uploads) == 1
