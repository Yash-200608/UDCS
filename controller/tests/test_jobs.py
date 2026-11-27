"""Job pipeline on the controller: submission, pull scheduling, leases, fencing, results."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from udcs_shared.agent_api import PROTOCOL_VERSION
from udcs_shared.jobs import expected_checksum

API = "/api/v1"
LEASE = 120  # Settings default job_lease_seconds


def _sync(client, headers, reports=(), *, kinds=("cpu",), slots=2, memory_mb=8192, accept=True):
    response = client.post(
        f"{API}/agent/jobs/sync",
        headers=headers,
        json={
            "protocol_version": PROTOCOL_VERSION,
            "reports": list(reports),
            "capacity": {
                "accept": accept,
                "slots": slots,
                "kinds": list(kinds),
                "memory_available_mb": memory_mb,
            },
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _report(assignment, state, units=0, **extra):
    return {
        "job_id": assignment["job_id"],
        "attempt": assignment["attempt"],
        "state": state,
        "units_done": units,
        **extra,
    }


def _result(units):
    return {"units": units, "checksum": str(expected_checksum(units))}


@pytest.fixture
def submit(client):
    def _submit(headers, kind="cpu", units=10, **extra):
        response = client.post(
            f"{API}/jobs", headers=headers, json={"kind": kind, "total_units": units, **extra}
        )
        assert response.status_code == 201, response.text
        return response.json()

    return _submit


@pytest.fixture
def node(enroll):
    return enroll()[1]


def _job(client, headers, job_id):
    return client.get(f"{API}/jobs/{job_id}", headers=headers).json()


def test_full_lifecycle_submit_assign_run_succeed_and_fetch_result(
    client, student_headers, node, submit, clock
):
    job = submit(student_headers, units=25)
    assert job["state"] == "queued" and job["node_id"] is None

    sync = _sync(client, node)
    [assignment] = sync["assignments"]
    assert assignment["job_id"] == job["id"] and assignment["attempt"] == 1
    assert assignment["spec"] == {
        "kind": "cpu",
        "total_units": 25,
        "memory_mb": 256,
        "package": None,
        "limits": None,
    }
    assert _job(client, student_headers, job["id"])["state"] == "assigned"

    _sync(client, node, [_report(assignment, "waiting")], accept=False)
    assert _job(client, student_headers, job["id"])["state"] == "assigned"  # not started yet

    clock.advance(seconds=5)
    _sync(
        client,
        node,
        [
            _report(
                assignment,
                "paused",
                units=10,
                cpu_seconds=0.5,
                logs=[{"age_seconds": 1, "message": "paused"}],
            )
        ],
        accept=False,
    )
    running = _job(client, student_headers, job["id"])
    assert running["state"] == "running" and running["local_state"] == "paused"
    assert running["progress"] == pytest.approx(0.4) and running["cpu_seconds"] == 0.5

    done = _sync(
        client, node, [_report(assignment, "completed", 25, result=_result(25))], accept=False
    )
    assert done["acknowledged"] == [job["id"]]
    finished = _job(client, student_headers, job["id"])
    assert finished["state"] == "succeeded" and finished["progress"] == 1.0

    result = client.get(f"{API}/jobs/{job['id']}/result", headers=student_headers).json()
    assert result["verified"] is True and result["result"]["units"] == 25
    logs = client.get(f"{API}/jobs/{job['id']}/logs", headers=student_headers).json()
    messages = [line["message"] for line in logs]
    assert messages[0].startswith("submitted") and "paused" in messages
    assert messages[-1] == "succeeded: result verified"

    # A resent terminal report (lost acknowledgement) is acknowledged again, not cancelled.
    again = _sync(
        client, node, [_report(assignment, "completed", 25, result=_result(25))], accept=False
    )
    assert again["acknowledged"] == [job["id"]] and again["cancel"] == []


def test_wrong_checksum_is_a_failure_and_retried_then_failed(client, student_headers, node, submit):
    job = submit(student_headers, units=5)
    for attempt in (1, 2, 3):
        [assignment] = _sync(client, node)["assignments"]
        assert assignment["attempt"] == attempt
        bad = {"units": 5, "checksum": "1"}
        _sync(client, node, [_report(assignment, "completed", 5, result=bad)], accept=False)
    final = _job(client, student_headers, job["id"])
    assert final["state"] == "failed" and final["failures"] == 3
    assert "checksum" in final["error"]
    assert client.get(f"{API}/jobs/{job['id']}/result", headers=student_headers).status_code == 409


def test_stale_attempt_reports_are_fenced_and_cancelled(
    client, student_headers, node, submit, enroll, inventory_factory
):
    job = submit(student_headers)
    [first] = _sync(client, node)["assignments"]
    # The node loses the job (it is not reported), so it is requeued and goes to another node.
    _sync(client, node, [], accept=False)
    assert _job(client, student_headers, job["id"])["requeues"] == 1
    other = enroll(inventory_factory(hostname="lab-b-08"))[1]
    [second] = _sync(client, other)["assignments"]
    assert second["attempt"] == 2
    # The first node turns up again, claiming it finished attempt 1: ignored and cancelled.
    stale = _sync(client, node, [_report(first, "completed", 10, result=_result(10))])
    assert stale["cancel"] == [job["id"]] and stale["acknowledged"] == []
    assert _job(client, student_headers, job["id"])["state"] == "assigned"


def test_same_node_old_attempt_is_fenced_after_reassignment(
    client, student_headers, node, submit, clock, enroll, inventory_factory
):
    # Partition: the node keeps running attempt 1 while the controller requeues it, and
    # then the same node is given attempt 2. Attempt 1's result must not count.
    job = submit(student_headers, units=4)
    [first] = _sync(client, node)["assignments"]
    clock.advance(seconds=2 * LEASE + 1)
    _sync(client, enroll(inventory_factory(hostname="bystander"))[1], accept=False)  # reaps
    assert _job(client, student_headers, job["id"])["state"] == "queued"
    [second] = _sync(client, node, [], slots=1)["assignments"]
    assert second["attempt"] == first["attempt"] + 1
    stale = _sync(
        client,
        node,
        [_report(first, "completed", 4, result=_result(4)), _report(second, "waiting")],
        accept=False,
    )
    assert stale["cancel"] == [job["id"]] and stale["acknowledged"] == []
    assert _job(client, student_headers, job["id"])["state"] == "assigned"


def test_controller_restart_does_not_requeue_before_nodes_can_renew(
    client, app, student_headers, node, submit, clock, enroll, inventory_factory
):
    job = submit(student_headers)
    [assignment] = _sync(client, node)["assignments"]
    clock.advance(seconds=LEASE + 30)  # controller was down longer than a lease
    app.state.started_at = clock.now  # ...and has just restarted
    other = enroll(inventory_factory(hostname="lab-b-10"))[1]
    _sync(client, other, accept=False)  # another node's sync must not reap it yet
    assert _job(client, student_headers, job["id"])["state"] == "assigned"
    _sync(client, node, [_report(assignment, "running", 2)], accept=False)  # renewed
    clock.advance(seconds=LEASE - 1)
    _sync(client, other, accept=False)
    assert _job(client, student_headers, job["id"])["state"] == "running"


def test_expired_lease_is_requeued_but_not_right_after_a_controller_restart(
    client, student_headers, node, submit, clock, enroll, inventory_factory
):
    job = submit(student_headers)
    [assignment] = _sync(client, node)["assignments"]
    _sync(client, node, [_report(assignment, "running", 3)], accept=False)

    other = enroll(inventory_factory(hostname="lab-b-09"))[1]
    clock.advance(seconds=LEASE - 10)  # still within the controller's own start-up grace
    _sync(client, other, accept=False)
    assert _job(client, student_headers, job["id"])["state"] == "running"

    clock.advance(seconds=LEASE)  # the node has been silent for longer than a lease
    _sync(client, other, accept=False)
    requeued = _job(client, student_headers, job["id"])
    assert requeued["state"] == "queued" and requeued["requeues"] == 1
    assert requeued["units_done"] == 0


def test_capacity_offer_limits_kinds_slots_and_memory(
    client, student_headers, submit, enroll, inventory_factory, clock
):
    cpu_only = enroll(inventory_factory(hostname="cpu-node", gpus=()))[1]
    gpu_job = submit(student_headers, kind="gpu")
    clock.advance(seconds=1)
    big = submit(student_headers, kind="memory", memory_mb=2048)
    clock.advance(seconds=1)
    small = [submit(student_headers) for _ in range(3)]

    # A node without a GPU never gets GPU work, even if it (wrongly) offers it.
    got = _sync(client, cpu_only, kinds=("cpu", "memory", "gpu"), slots=2, memory_mb=1024)
    ids = [a["job_id"] for a in got["assignments"]]
    assert gpu_job["id"] not in ids and big["id"] not in ids  # 2048 MB does not fit 1024
    assert len(ids) == 2 and set(ids) <= {j["id"] for j in small}

    # A node that offers nothing gets nothing; a GPU node takes GPU work first.
    assert _sync(client, cpu_only, [], accept=False)["assignments"] == []
    gpu_node = enroll(inventory_factory(hostname="gpu-node"))[1]
    first = _sync(client, gpu_node, kinds=("gpu", "cpu"), slots=1)["assignments"]
    assert [a["job_id"] for a in first] == [gpu_job["id"]]


def test_two_nodes_never_receive_the_same_job_and_users_share_fairly(
    client, make_user, login, submit, enroll, inventory_factory, clock
):
    make_user("alice")
    make_user("bob")
    alice, bob = login("alice"), login("bob")
    alice_jobs = []
    for _ in range(4):
        alice_jobs.append(submit(alice))
        clock.advance(seconds=1)
    bob_job = submit(bob)  # submitted last
    a = enroll(inventory_factory(hostname="node-a"))[1]
    b = enroll(inventory_factory(hostname="node-b"))[1]

    first = [x["job_id"] for x in _sync(client, a, slots=1)["assignments"]]
    second = [x["job_id"] for x in _sync(client, b, slots=2)["assignments"]]
    assert first == [alice_jobs[0]["id"]]
    # Bob has nothing running yet, so his job goes before Alice's second one.
    assert second == [bob_job["id"], alice_jobs[1]["id"]]
    assert not set(first) & set(second)


def test_cancel_tells_the_node_to_stop(client, student_headers, node, submit):
    job = submit(student_headers)
    [assignment] = _sync(client, node)["assignments"]
    cancelled = client.post(f"{API}/jobs/{job['id']}/cancel", headers=student_headers)
    assert cancelled.status_code == 200 and cancelled.json()["state"] == "cancelled"
    response = _sync(client, node, [_report(assignment, "running", 2)], accept=False)
    assert response["cancel"] == [job["id"]]
    again = client.post(f"{API}/jobs/{job['id']}/cancel", headers=student_headers)
    assert again.status_code == 409


def test_maintenance_node_gets_no_work_and_hands_its_jobs_back(
    client, admin_headers, student_headers, enroll, submit
):
    body, node, _ = enroll()
    job = submit(student_headers)
    [assignment] = _sync(client, node)["assignments"]
    response = client.post(
        f"{API}/admin/nodes/{body['node_id']}/state",
        headers=admin_headers,
        json={"admin_state": "maintenance"},
    )
    assert response.status_code == 200, response.text
    out = _sync(client, node, [_report(assignment, "running", 1)])
    assert out["cancel"] == [job["id"]] and out["assignments"] == []
    assert _job(client, student_headers, job["id"])["state"] == "queued"


def test_visibility_and_permissions(client, student_headers, make_user, login, submit, node):
    job = submit(student_headers)
    make_user("other")
    other = login("other")
    assert client.get(f"{API}/jobs/{job['id']}", headers=other).status_code == 404
    assert client.post(f"{API}/jobs/{job['id']}/cancel", headers=other).status_code == 404
    assert client.get(f"{API}/jobs", headers=other).json() == []
    high = client.post(
        f"{API}/jobs",
        headers=student_headers,
        json={"kind": "cpu", "total_units": 1, "priority": 5},
    )
    assert high.status_code == 403
    # Node identities are hidden from job owners and visible to admins.
    _sync(client, node)
    assert _job(client, student_headers, job["id"])["node_id"] is None
    # Only catalog kinds exist: anything else is a validation error, never executed.
    bad = client.post(
        f"{API}/jobs", headers=student_headers, json={"kind": "python", "total_units": 1}
    )
    assert bad.status_code == 422
    # A node credential cannot submit jobs, and a user token cannot sync as a node.
    as_node = client.post(f"{API}/jobs", headers=node, json={"kind": "cpu", "total_units": 1})
    assert as_node.status_code == 401
    sync_as_user = client.post(
        f"{API}/agent/jobs/sync",
        headers=student_headers,
        json={
            "protocol_version": PROTOCOL_VERSION,
            "capacity": {"accept": True, "slots": 1, "kinds": ["cpu"], "memory_available_mb": 1},
        },
    )
    assert sync_as_user.status_code == 401


def test_admin_sees_placement(client, admin_headers, node, submit):
    job = submit(admin_headers)
    _sync(client, node)
    seen = client.get(f"{API}/jobs/{job['id']}", headers=admin_headers).json()
    assert seen["node_id"] is not None
    listed = client.get(f"{API}/jobs?all=true", headers=admin_headers).json()
    assert [j["id"] for j in listed] == [job["id"]]


def test_per_user_active_job_limit(client, student_headers, app):
    app.state.settings = app.state.settings.model_copy(update={"max_active_jobs_per_user": 2})
    body = {"kind": "cpu", "total_units": 1}
    for _ in range(2):
        assert client.post(f"{API}/jobs", headers=student_headers, json=body).status_code == 201
    assert client.post(f"{API}/jobs", headers=student_headers, json=body).status_code == 429


# -- central checkpoints ----------------------------------------------------------------------


def _checkpoint_body(attempt, units, version=1, checksum=None, corrupt=None):
    payload = json.dumps(
        {
            "units_done": units,
            "checksum": expected_checksum(units) if checksum is None else checksum,
        }
    ).encode()
    digest = hashlib.sha256(payload).hexdigest()
    if corrupt == "truncate":
        payload = payload[:-3]  # interrupted upload: fewer bytes than were hashed
    return {
        "attempt": attempt,
        "version": version,
        "units_done": units,
        "sha256": digest,
        "payload_b64": base64.b64encode(payload).decode(),
    }


def _put_ckpt(client, headers, job_id, body):
    return client.put(f"{API}/agent/jobs/{job_id}/checkpoint", headers=headers, json=body)


def test_checkpoint_migrates_to_another_node_after_permanent_loss(
    client, student_headers, node, submit, clock, enroll, inventory_factory
):
    job = submit(student_headers, units=100)
    [first] = _sync(client, node)["assignments"]
    assert first["checkpoint"] is None
    _sync(client, node, [_report(first, "running", 40)], accept=False)
    assert _put_ckpt(client, node, job["id"], _checkpoint_body(1, 40)).status_code == 204

    # The original node disappears for good; its lease expires and the job is requeued.
    clock.advance(seconds=2 * LEASE + 1)
    other = enroll(inventory_factory(hostname="survivor"))[1]
    _sync(client, other, accept=False)
    requeued = _job(client, student_headers, job["id"])
    assert requeued["state"] == "queued" and requeued["units_done"] == 40  # progress kept

    [second] = _sync(client, other)["assignments"]
    assert second["attempt"] == 2
    ref = second["checkpoint"]
    assert ref["units_done"] == 40 and ref["version"] == 1
    download = client.get(
        f"{API}/agent/jobs/{job['id']}/checkpoint?attempt=2", headers=other
    ).json()
    payload = base64.b64decode(download["payload_b64"])
    assert hashlib.sha256(payload).hexdigest() == ref["sha256"] == download["sha256"]
    assert json.loads(payload)["units_done"] == 40
    # The lost node can neither download nor overwrite it any more (fencing).
    assert (
        client.get(f"{API}/agent/jobs/{job['id']}/checkpoint?attempt=1", headers=node).status_code
        == 409
    )
    assert _put_ckpt(client, node, job["id"], _checkpoint_body(1, 60, 2)).status_code == 409
    logs = [
        line["message"]
        for line in client.get(f"{API}/jobs/{job['id']}/logs", headers=student_headers).json()
    ]
    assert any("resumes from checkpoint at 40 units" in m for m in logs)
    assert any(m.startswith("assigned (attempt 2, resume from 40 units)") for m in logs)

    # The new node continues: newer progress is accepted, then the job completes.
    assert _put_ckpt(client, other, job["id"], _checkpoint_body(2, 70)).status_code == 204
    done = _sync(
        client, other, [_report(second, "completed", 100, result=_result(100))], accept=False
    )
    assert done["acknowledged"] == [job["id"]]
    assert _job(client, student_headers, job["id"])["state"] == "succeeded"
    # A finished job's checkpoint is deleted.
    assert (
        client.get(f"{API}/agent/jobs/{job['id']}/checkpoint?attempt=2", headers=other).status_code
        == 409
    )


def test_corrupted_interrupted_or_inconsistent_uploads_never_replace_a_good_checkpoint(
    client, student_headers, node, submit
):
    job = submit(student_headers, units=100)
    _sync(client, node)
    assert _put_ckpt(client, node, job["id"], _checkpoint_body(1, 30)).status_code == 204
    bad_hash = {**_checkpoint_body(1, 50, 2), "sha256": "0" * 64}
    truncated = _checkpoint_body(1, 50, 2, corrupt="truncate")
    wrong_sum = _checkpoint_body(1, 50, 2, checksum=12345)
    lying_units = {**_checkpoint_body(1, 50, 2), "units_done": 60}
    too_far = _checkpoint_body(1, 101, 2)
    not_b64 = {**_checkpoint_body(1, 50, 2), "payload_b64": "!!!notbase64!!!"}
    for body in (bad_hash, truncated, wrong_sum, lying_units, too_far, not_b64):
        response = _put_ckpt(client, node, job["id"], body)
        assert response.status_code == 422, (body, response.text)
    stored = client.get(f"{API}/agent/jobs/{job['id']}/checkpoint?attempt=1", headers=node).json()
    assert stored["units_done"] == 30 and stored["version"] == 1


def test_stale_checkpoint_versions_are_rejected_and_retries_are_idempotent(
    client, student_headers, node, submit
):
    job = submit(student_headers, units=100)
    _sync(client, node)
    body = _checkpoint_body(1, 30, version=5)
    assert _put_ckpt(client, node, job["id"], body).status_code == 204
    assert _put_ckpt(client, node, job["id"], body).status_code == 204  # retried: same
    assert _put_ckpt(client, node, job["id"], _checkpoint_body(1, 35, 4)).status_code == 409
    assert _put_ckpt(client, node, job["id"], _checkpoint_body(1, 20, 6)).status_code == 409
    assert _put_ckpt(client, node, job["id"], _checkpoint_body(1, 40, 6)).status_code == 204
    stored = client.get(f"{API}/agent/jobs/{job['id']}/checkpoint?attempt=1", headers=node).json()
    assert stored["units_done"] == 40 and stored["version"] == 2


def test_a_failed_attempt_discards_its_checkpoint(client, student_headers, node, submit):
    job = submit(student_headers, units=10)
    [a] = _sync(client, node)["assignments"]
    assert _put_ckpt(client, node, job["id"], _checkpoint_body(1, 5)).status_code == 204
    bad = {"units": 10, "checksum": "1"}
    _sync(client, node, [_report(a, "completed", 10, result=bad)], accept=False)
    [retry] = _sync(client, node)["assignments"]
    assert retry["attempt"] == 2 and retry["checkpoint"] is None
    assert _job(client, student_headers, job["id"])["units_done"] == 0


def test_checkpoints_need_a_node_credential(client, student_headers, submit, node):
    job = submit(student_headers)
    _sync(client, node)
    body = _checkpoint_body(1, 1)
    assert _put_ckpt(client, student_headers, job["id"], body).status_code == 401
    assert _put_ckpt(client, {}, job["id"], body).status_code == 401
