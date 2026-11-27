"""JobSync for package jobs (ADR 0003) against a fake controller: offer, refusal,
staging, substitution and corruption, failure classes, results and cleanup. The
process side is faked through the manager snapshot; test_package_runs_windows.py
covers real AppContainer runs and tests/e2e the whole path."""

from __future__ import annotations

import hashlib
import json
import uuid

import httpx
import pytest

import udcs_agent.jobs as agent_jobs
from udcs_agent.communication.client import ControllerUnavailable
from udcs_agent.governor.engine import AdmissionView
from udcs_agent.jobs import JobSync, workload_id
from udcs_shared.jobs import (
    FailureKind,
    JobAssignment,
    JobSpec,
    JobSyncResponse,
    LocalJobState,
    PackageRunLimits,
)
from udcs_shared.packages import OutputManifest, PackageManifest
from udcs_shared.protection import ProtectionLevel, ProtectionPolicy, WorkloadClass

POLICY = ProtectionPolicy()
LIMITS = PackageRunLimits(
    max_runtime_seconds=60,
    max_output_bytes=2**20,
    max_output_files=10,
    max_output_entries=100,
    max_output_depth=8,
)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest(files: dict[str, bytes], *, python: str = agent_jobs.NODE_PYTHON) -> PackageManifest:
    return PackageManifest.model_validate(
        {
            "schema_version": 1,
            "kind": "package",
            "name": "t",
            "version": "1",
            "python": python,
            "files": [
                {"path": p, "sha256": _sha(d), "size": len(d)} for p, d in sorted(files.items())
            ],
            "entry": {"script": "main.py"},
        }
    )


class FakeController:
    """Serves one package's closure and blobs; records outputs."""

    def __init__(self, manifest: PackageManifest, blobs: dict[str, bytes]) -> None:
        self.manifest = manifest
        self.blobs = blobs
        self.closure_override: dict | None = None
        self.unavailable = False
        self.outputs: list[dict] = []
        self.uploaded: dict[str, bytes] = {}
        self.output_status = 204

    def package_closure(self, job_id, attempt):
        if self.unavailable:
            raise ControllerUnavailable("down")
        if self.closure_override is not None:
            return self.closure_override
        digest = self.manifest.digest()
        return {"package": digest, "manifests": {digest: self.manifest.model_dump(mode="json")}}

    def transfer_http(self):
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if request.method == "GET" and path.startswith("/agent/blobs/"):
                return httpx.Response(200, content=self.blobs[path.rsplit("/", 1)[1]])
            if path == "/agent/blobs/uploads" and request.method == "POST":
                body = json.loads(request.content)
                self._pending = body
                return httpx.Response(
                    200,
                    json={
                        "upload_id": "u1",
                        "received": 0,
                        "size": body["size"],
                        "chunk_bytes": 1 << 20,
                        "state": "open",
                    },
                )
            if path == "/agent/blobs/uploads/u1" and request.method == "PUT":
                import zlib

                raw = request.content
                if request.headers.get("X-UDCS-Chunk-Encoding") == "zlib":
                    raw = zlib.decompress(raw)
                self.uploaded[self._pending["sha256"]] = raw
                return httpx.Response(200, json={"received": len(raw)})
            if path == "/agent/blobs/uploads/u1/complete":
                return httpx.Response(200, json={})
            return httpx.Response(404)

        return httpx.Client(base_url="https://c", transport=httpx.MockTransport(handler))

    def put_outputs(self, job_id, manifest):
        if self.output_status != 204:
            from udcs_agent.communication.client import ProtocolError

            raise ProtocolError(f"HTTP {self.output_status}: refused")
        self.outputs.append(manifest)

    def put_checkpoint(self, job_id, upload):
        self.checkpoint = upload

    def get_checkpoint(self, job_id, attempt):
        raise ControllerUnavailable("not in these tests")


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(agent_jobs, "USER_CODE_ENABLED", True)


def _sync(tmp_path, snapshot, *, isolation="appcontainer"):
    view = AdmissionView(
        level=ProtectionLevel.OPEN,
        reasons=frozenset(),
        maintenance=False,
        envelope=POLICY.envelopes[ProtectionLevel.OPEN],
        memory_total_bytes=16 * 2**30,
        udcs_memory_bytes=0,
    )
    return JobSync(
        tmp_path,
        snapshot=lambda prefix: {k: v for k, v in snapshot.items() if k.startswith(prefix)},
        admission=lambda: view,
        has_gpu=False,
        isolation=isolation,
    )


def _assignment(digest: str, attempt: int = 1, job_id=None) -> JobAssignment:
    return JobAssignment(
        job_id=job_id or uuid.uuid4(),
        attempt=attempt,
        spec=JobSpec(kind=WorkloadClass.CPU, total_units=1, package=digest, limits=LIMITS),
    )


def _response(*assignments, cancel=(), acknowledged=()):
    return JobSyncResponse(
        assignments=list(assignments),
        cancel=list(cancel),
        acknowledged=list(acknowledged),
        lease_seconds=60,
    )


def _reports(sync):
    return {str(r.job_id): r for r in sync.build_request().reports}


def test_user_code_is_offered_only_when_enabled_and_isolated(tmp_path, monkeypatch):
    assert not _sync(tmp_path, {}).capacity().user_code  # the shipped default
    monkeypatch.setattr(agent_jobs, "USER_CODE_ENABLED", True)
    assert not _sync(tmp_path, {}, isolation="host").capacity().user_code
    offer = _sync(tmp_path, {}).capacity()
    assert offer.user_code and offer.python == agent_jobs.NODE_PYTHON and offer.platform


def test_a_package_assignment_is_refused_when_not_offered(tmp_path):
    sync = _sync(tmp_path, {})
    a = _assignment("a" * 64)
    sync.apply(_response(a))
    report = _reports(sync)[str(a.job_id)]
    assert report.state == LocalJobState.FAILED
    assert "not offered by this node" in report.error
    assert not (tmp_path / "workloads" / "requests").exists()  # nothing was queued to run


def test_staging_verifies_then_queues_the_run(tmp_path, enabled):
    blobs = {"main.py": b"print(1)\n", "lib/u.py": b"X = 1\n"}
    manifest = _manifest(blobs)
    controller = FakeController(manifest, {_sha(d): d for d in blobs.values()})
    sync = _sync(tmp_path, {})
    a = _assignment(manifest.digest())
    sync.apply(_response(a))
    assert _reports(sync)[str(a.job_id)].state == LocalJobState.STAGING
    sync.prepare_packages(controller)
    entry = sync._assignments[str(a.job_id)]
    assert entry["phase"] == "ready"
    root = entry["run"]["root"]
    assert (tmp_path / "staging").is_dir() and root.endswith("-1")
    folder = tmp_path / "workloads" / "requests"
    [request] = [json.loads(p.read_text()) for p in sorted(folder.glob("*.json"))]
    assert (
        request["spec"]["isolation"] == "appcontainer"
        and request["spec"]["checkpointable"] is False
    )
    assert request["spec"]["max_runtime_seconds"] == 60


def test_a_substituted_manifest_is_refused(tmp_path, enabled):
    blobs = {"main.py": b"print(1)\n"}
    manifest = _manifest(blobs)
    evil = _manifest({"main.py": b"import os; os.system('evil')\n"})
    controller = FakeController(manifest, {})
    controller.closure_override = {
        "package": manifest.digest(),
        "manifests": {
            manifest.digest(): evil.model_dump(mode="json")
        },  # filed under the wrong digest
    }
    sync = _sync(tmp_path, {})
    a = _assignment(manifest.digest())
    sync.apply(_response(a))
    sync.prepare_packages(controller)
    report = _reports(sync)[str(a.job_id)]
    assert report.state == LocalJobState.FAILED and report.failure == FailureKind.INFRASTRUCTURE
    assert "does not match its digest" in report.error


def test_corrupted_package_bytes_never_reach_staging(tmp_path, enabled):
    blobs = {"main.py": b"print(1)\n"}
    manifest = _manifest(blobs)
    controller = FakeController(manifest, {_sha(blobs["main.py"]): b"print(2)\n"})  # same length
    sync = _sync(tmp_path, {})
    a = _assignment(manifest.digest())
    sync.apply(_response(a))
    sync.prepare_packages(controller)
    report = _reports(sync)[str(a.job_id)]
    assert report.state == LocalJobState.FAILED and "verification" in report.error
    assert not (tmp_path / "staging").exists() or not any((tmp_path / "staging").iterdir())


def test_a_python_mismatch_is_refused_on_the_node_too(tmp_path, enabled):
    blobs = {"main.py": b"print(1)\n"}
    manifest = _manifest(blobs, python="3.9")
    controller = FakeController(manifest, {_sha(d): d for d in blobs.values()})
    sync = _sync(tmp_path, {})
    a = _assignment(manifest.digest())
    sync.apply(_response(a))
    sync.prepare_packages(controller)
    report = _reports(sync)[str(a.job_id)]
    assert report.state == LocalJobState.FAILED and "needs Python 3.9" in report.error


def test_an_unreachable_controller_keeps_the_job_staging(tmp_path, enabled):
    manifest = _manifest({"main.py": b"1"})
    controller = FakeController(manifest, {})
    controller.unavailable = True
    sync = _sync(tmp_path, {})
    a = _assignment(manifest.digest())
    sync.apply(_response(a))
    sync.prepare_packages(controller)
    assert _reports(sync)[str(a.job_id)].state == LocalJobState.STAGING


def _ready(tmp_path, snapshot, enabled_flag=True):
    blobs = {"main.py": b"print(1)\n"}
    manifest = _manifest(blobs)
    controller = FakeController(manifest, {_sha(d): d for d in blobs.values()})
    sync = _sync(tmp_path, snapshot)
    a = _assignment(manifest.digest())
    sync.apply(_response(a))
    sync.prepare_packages(controller)
    return sync, controller, a, sync._assignments[str(a.job_id)]


def test_a_finished_run_is_uploaded_then_reported_with_its_outputs(tmp_path, enabled):
    snapshot: dict = {}
    sync, controller, a, entry = _ready(tmp_path, snapshot)
    from pathlib import Path

    root = Path(entry["run"]["root"])
    (root / "out").mkdir(exist_ok=True)
    (root / "out" / "r.txt").write_bytes(b"result")
    (root / "logs" / "stdout.txt").write_text("hello\n")
    wid = workload_id(a.job_id)
    snapshot[wid] = {"state": "running", "events": []}
    assert _reports(sync)[str(a.job_id)].state == LocalJobState.RUNNING
    snapshot[wid] = {"state": "completed", "outcome": "exited", "last_exit_code": 0, "events": []}
    assert _reports(sync)[str(a.job_id)].state == LocalJobState.UPLOADING  # not yet uploaded
    sync.finish_packages(controller)
    report = _reports(sync)[str(a.job_id)]
    assert report.state == LocalJobState.COMPLETED and report.package_result.exit_code == 0
    [reported] = controller.outputs
    manifest = OutputManifest.model_validate(reported)
    assert report.package_result.outputs_sha256 == manifest.digest()
    assert {f.path for f in manifest.files} == {"r.txt", "udcs-logs/stdout.txt"}
    assert controller.uploaded[_sha(b"result")] == b"result"


@pytest.mark.parametrize(
    ("outcome", "kind", "text"),
    [
        ("runtime_limit", FailureKind.WORKLOAD, "runtime limit"),
        ("storage_limit", FailureKind.WORKLOAD, "storage limit"),
        ("isolation_unavailable", FailureKind.INFRASTRUCTURE, "could not run"),
        ("tree_survived", FailureKind.INFRASTRUCTURE, "could not run"),
    ],
)
def test_how_a_run_ended_decides_who_owns_the_failure(tmp_path, enabled, outcome, kind, text):
    snapshot: dict = {}
    sync, controller, a, _ = _ready(tmp_path, snapshot)
    snapshot[workload_id(a.job_id)] = {"state": "failed", "outcome": outcome, "events": []}
    sync.finish_packages(controller)
    report = _reports(sync)[str(a.job_id)]
    assert report.state == LocalJobState.FAILED and report.failure == kind and text in report.error
    assert controller.outputs == []  # a failed run publishes nothing


def test_a_stale_upload_is_not_reported_as_success(tmp_path, enabled):
    snapshot: dict = {}
    sync, controller, a, _entry = _ready(tmp_path, snapshot)
    controller.output_status = 409
    snapshot[workload_id(a.job_id)] = {
        "state": "completed",
        "outcome": "exited",
        "last_exit_code": 0,
        "events": [],
    }
    sync.finish_packages(controller)
    report = _reports(sync)[str(a.job_id)]
    assert report.state == LocalJobState.FAILED and report.package_result is None


def test_cancel_removes_the_run_and_later_its_staging(tmp_path, enabled):
    snapshot: dict = {}
    sync, _controller, a, entry = _ready(tmp_path, snapshot)
    from pathlib import Path

    root = Path(entry["run"]["root"])
    assert root.exists()
    sync.apply(_response(cancel=[a.job_id]))
    sync.clean_staging()  # first pass: the workload's removal is queued, its tree may live
    assert root.exists()
    sync.clean_staging()
    assert not root.exists()


def test_reassignment_of_a_newer_attempt_restarts_from_staging(tmp_path, enabled):
    snapshot: dict = {}
    sync, _controller, a, entry = _ready(tmp_path, snapshot)
    newer = _assignment(a.spec.package, attempt=2, job_id=a.job_id)
    sync.apply(_response(newer))
    entry = sync._assignments[str(a.job_id)]
    assert entry["attempt"] == 2 and entry["phase"] == "staging"


def test_a_package_checkpoint_is_uploaded_when_it_changes(tmp_path, enabled):
    from pathlib import Path

    snapshot: dict = {}
    sync, controller, a, entry = _ready(tmp_path, snapshot)
    state = Path(entry["run"]["root"]) / "state" / "checkpoint.bin"
    state.write_bytes(b"epoch=3")
    sync.upload_checkpoints(controller)
    first = controller.checkpoint
    assert first.units_done == 0 and first.version == 1 and first.attempt == a.attempt
    del controller.checkpoint
    sync._last_upload.clear()
    sync.upload_checkpoints(controller)
    assert not hasattr(controller, "checkpoint")  # unchanged content is not re-sent
    state.write_bytes(b"epoch=4")
    sync._last_upload.clear()
    sync.upload_checkpoints(controller)
    assert controller.checkpoint.version == 2


def test_a_package_checkpoint_is_restored_into_state_after_staging(tmp_path, enabled):
    import base64

    from udcs_shared.jobs import CheckpointDownload, CheckpointRef

    payload = b"epoch=7"
    ref = CheckpointRef(version=3, units_done=0, sha256=_sha(payload), size=len(payload))
    blobs = {"main.py": b"print(1)\n"}
    manifest = _manifest(blobs)
    controller = FakeController(manifest, {_sha(d): d for d in blobs.values()})
    controller.get_checkpoint = lambda job_id, attempt: CheckpointDownload(
        version=3,
        units_done=0,
        sha256=_sha(payload),
        payload_b64=base64.b64encode(payload).decode(),
    )
    sync = _sync(tmp_path, {})
    a = _assignment(manifest.digest()).model_copy(update={"checkpoint": ref})
    sync.apply(_response(a))
    sync.prepare_packages(controller)
    from pathlib import Path

    entry = sync._assignments[str(a.job_id)]
    assert (Path(entry["run"]["root"]) / "state" / "checkpoint.bin").read_bytes() == payload
