"""End to end: user -> controller -> scheduler -> two real agents -> Job Objects -> result.

Everything runs for real on this machine: the TLS controller, two full AgentApp
instances (governor, workload manager, job sync), catalog workloads in Job Objects,
and checkpoint/resume. Both "nodes" share one PC, so each sees the other's work as
non-UDCS load. That is why each takes one job at a time, which keeps the measured
pressure low.
"""

from __future__ import annotations

import shutil
import sys
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from udcs_agent.app import AgentApp
from udcs_agent.communication.client import ControllerClient
from udcs_agent.config import CREDENTIAL_FILENAME, AgentConfig, save_config
from udcs_agent.credentials import CredentialStore, NodeCredential
from udcs_agent.discovery import collect_inventory
from udcs_agent.discovery.nvidia import Nvml
from udcs_agent.jobs import workload_id

pytestmark = [pytest.mark.e2e, pytest.mark.skipif(sys.platform != "win32", reason="Windows")]

LEASE = 30
# A freshly started agent starts at CONSTRAINED and offers no work until it has seen
# 30 s of continuous calm (by design: student first). Noise restarts that timer, so
# waits for a job to *start* allow for several of those windows.
START_WAIT = 240
RESEARCHER_PASSWORD = "researcher-password-e2e"


def _wait(predicate, timeout, interval=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return None


class Node:
    def __init__(self, controller, data_dir: Path, token: str, name: str) -> None:
        self.data_dir = data_dir
        config = AgentConfig(controller_url=controller.url, ca_bundle=controller.ca_file)
        save_config(data_dir, config)
        with Nvml() as nvml:
            inventory = collect_inventory(nvml)
        with ControllerClient(config) as client:
            enrolled = client.enroll(token, inventory, name)
        self.node_id = str(enrolled.node_id)
        CredentialStore(data_dir / CREDENTIAL_FILENAME).save(
            NodeCredential(node_id=enrolled.node_id, secret=enrolled.node_credential)
        )
        self.app: AgentApp | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        stop = threading.Event()
        self.app = AgentApp(
            self.data_dir,
            stop=stop,
            helper_channel=False,
            max_jobs=1,
            checkpoint_upload_seconds=0,  # upload on every sync where progress advanced
        )
        self.thread = threading.Thread(target=self.app.run, name=f"node-{self.node_id[:8]}")
        self.thread.start()

    def stop(self) -> None:
        if self.app is not None and self.thread is not None:
            self.app.stop.set()
            self.thread.join(timeout=20)
            assert not self.thread.is_alive(), "agent did not stop"
        self.app = self.thread = None


@pytest.fixture
def cluster(controller_factory, tmp_path):
    controller = controller_factory(tokens=2, heartbeat_interval_seconds=5, job_lease_seconds=LEASE)
    http = httpx.Client(base_url=f"{controller.url}/api/v1", verify=str(controller.ca_file))
    login = http.post(
        "/auth/login", json={"username": "itadmin", "password": controller.admin_password}
    )
    admin = {"Authorization": f"Bearer {login.json()['access_token']}"}
    created = http.post(
        "/admin/users",
        headers=admin,
        json={
            "username": "researcher1",
            "display_name": "Researcher",
            "password": RESEARCHER_PASSWORD,
            "role": "researcher",
        },
    )
    assert created.status_code == 201, created.text
    login = http.post(
        "/auth/login", json={"username": "researcher1", "password": RESEARCHER_PASSWORD}
    )
    nodes = [
        Node(controller, tmp_path / f"node{i}", controller.tokens[i], f"e2e-node-{i}")
        for i in range(2)
    ]
    cluster = SimpleNamespace(
        http=http,
        admin=admin,
        user={"Authorization": f"Bearer {login.json()['access_token']}"},
        nodes=nodes,
    )
    try:
        yield cluster
    finally:
        for node in nodes:
            node.stop()
        http.close()


def _submit(c, units, kind="cpu"):
    response = c.http.post("/jobs", headers=c.user, json={"kind": kind, "total_units": units})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _job(c, job_id, admin=False):
    return c.http.get(f"/jobs/{job_id}", headers=c.admin if admin else c.user).json()


def _messages(c, job_id):
    return [x["message"] for x in c.http.get(f"/jobs/{job_id}/logs", headers=c.user).json()]


def test_jobs_are_distributed_executed_and_verified_across_two_nodes(cluster):
    c = cluster
    for node in c.nodes:
        node.start()
    jobs = [_submit(c, units=30) for _ in range(4)]
    finished = _wait(
        lambda: all(_job(c, j)["state"] == "succeeded" for j in jobs), timeout=START_WAIT + 120
    )
    assert finished, (
        f"not all succeeded: {[(_job(c, j)['state'], _job(c, j)['error']) for j in jobs]}"
    )

    placements = {_job(c, j, admin=True)["node_id"] for j in jobs}
    assert placements == {n.node_id for n in c.nodes}, "work should spread over both nodes"
    for job_id in jobs:
        job = _job(c, job_id)
        assert job["progress"] == 1.0 and job["attempt"] == 1 and job["cpu_seconds"] > 0
        result = c.http.get(f"/jobs/{job_id}/result", headers=c.user).json()
        assert result["verified"] is True and result["result"]["units"] == 30
        messages = _messages(c, job_id)
        assert "started" in messages and "completed" in messages  # from the node's governor
        assert messages[-1] == "succeeded: result verified"
    # Acknowledged jobs are cleaned up on the nodes.
    for node in c.nodes:
        assert _wait(
            lambda n=node: not any((n.data_dir / "workloads").glob("job-*")), timeout=30
        ), "workload directories should be purged after acknowledgement"


def test_cancel_stops_the_workload_on_the_node(cluster):
    c = cluster
    node = c.nodes[0]
    node.start()
    job_id = _submit(c, units=100_000)  # far longer than the test
    assert _wait(lambda: _job(c, job_id)["units_done"] > 0, timeout=START_WAIT), _job(c, job_id)
    assert c.http.post(f"/jobs/{job_id}/cancel", headers=c.user).status_code == 200
    workdir = node.data_dir / "workloads" / workload_id(uuid.UUID(job_id))
    assert _wait(lambda: not workdir.exists(), timeout=40), "cancelled workload still on node"
    assert _job(c, job_id)["state"] == "cancelled"


def test_agent_restart_resumes_the_same_attempt_from_its_checkpoint(cluster):
    c = cluster
    node = c.nodes[0]
    node.start()
    job_id = _submit(c, units=200)  # ~10 s of work at full speed
    assert _wait(lambda: _job(c, job_id)["units_done"] >= 50, timeout=START_WAIT), _job(c, job_id)
    node.stop()  # service stop: workloads are terminated, checkpoints remain
    node.start()  # service start: the same attempt resumes from its checkpoint
    done = _wait(lambda: _job(c, job_id)["state"] == "succeeded", timeout=START_WAIT)
    job = _job(c, job_id)
    assert done, job
    assert job["attempt"] == 1 and job["requeues"] == 0, "resumed, not rescheduled"
    result = c.http.get(f"/jobs/{job_id}/result", headers=c.user).json()
    assert result["verified"] is True  # no unit lost or repeated across the restart
    assert _messages(c, job_id).count("started") >= 2


def test_lost_node_job_resumes_on_another_node_from_the_central_checkpoint(cluster):
    c = cluster
    first, second = c.nodes
    first.start()
    job_id = _submit(c, units=400)  # ~20 s of work at full speed
    assert _wait(lambda: _job(c, job_id)["units_done"] >= 100, timeout=START_WAIT), _job(c, job_id)
    assert _job(c, job_id, admin=True)["node_id"] == first.node_id
    first.stop()
    # The PC is gone for good: its disk too, so nothing local could help a resume.
    shutil.rmtree(first.data_dir)
    second.start()
    done = _wait(lambda: _job(c, job_id)["state"] == "succeeded", timeout=LEASE * 4 + START_WAIT)
    job = _job(c, job_id, admin=True)
    assert done, job
    assert job["node_id"] == second.node_id and job["attempt"] == 2 and job["requeues"] == 1
    messages = _messages(c, job_id)
    [requeued] = [m for m in messages if m.startswith("requeued: lease expired")]
    resumed_at = int(requeued.split("resumes from checkpoint at ")[1].split()[0])
    assert resumed_at >= 50, "completed progress must survive the node"
    # The new node's own log: it installed the verified checkpoint before starting, so it
    # continued from there rather than from zero (a restart would also verify).
    resumed = [m for m in messages if m.startswith("resumed from central checkpoint")]
    assert len(resumed) == 1 and resumed[0].endswith(f" at {resumed_at} units"), messages
    # Exactly-once over the units: the checksum covers every index once, so any unit
    # lost or repeated across the migration would fail verification.
    assert c.http.get(f"/jobs/{job_id}/result", headers=c.user).json()["verified"] is True
