"""Lab-scoped enrollment keys, pending approval, per-node identity and rotation."""

from sqlalchemy import select

from udcs_controller.audit.models import AuditEvent
from udcs_shared.agent_api import PROTOCOL_VERSION

API = "/api/v1"


def _enroll_raw(client, key, inventory):
    return client.post(
        f"{API}/agent/enroll",
        json={
            "enrollment_token": key,
            "protocol_version": PROTOCOL_VERSION,
            "inventory": inventory.model_dump(mode="json"),
        },
    )


def _bearer(credential):
    return {"Authorization": f"Bearer {credential}"}


def _audit(app, action):
    with app.state.sessionmaker() as db:
        return db.scalars(select(AuditEvent).where(AuditEvent.action == action)).all()


def test_lab_key_enrolls_many_nodes_with_unique_identities(
    client, admin_headers, new_enrollment_key, inventory_factory, heartbeat
):
    key = new_enrollment_key(max_uses=3, lab="CS Lab B")
    bodies = []
    for n in range(3):
        response = _enroll_raw(client, key, inventory_factory(hostname=f"lab-b-{n:02d}"))
        assert response.status_code == 201
        bodies.append(response.json())
    credentials = {b["node_credential"] for b in bodies}
    assert len(credentials) == 3, "each node must get its own credential"
    assert key not in credentials, "the lab key must never become a node identity"
    assert _enroll_raw(client, key, inventory_factory(hostname="lab-b-99")).status_code == 401

    nodes = client.get(f"{API}/admin/nodes", headers=admin_headers).json()
    assert {n["lab"] for n in nodes} == {"CS Lab B"}
    keys = client.get(f"{API}/admin/enrollment-keys", headers=admin_headers).json()
    assert keys[0]["use_count"] == 3 and "key" not in keys[0]


def test_lab_key_cannot_authenticate_as_a_node(
    client, new_enrollment_key, inventory_factory, heartbeat
):
    key = new_enrollment_key(max_uses=5)
    _enroll_raw(client, key, inventory_factory())
    assert heartbeat(_bearer(key), inventory_factory()).status_code == 401


def test_revoked_key_stops_enrollment_but_not_existing_nodes(
    client, admin_headers, new_enrollment_key, inventory_factory, heartbeat
):
    key = new_enrollment_key(max_uses=10)
    first = _enroll_raw(client, key, inventory_factory(hostname="pc-1")).json()
    [record] = client.get(f"{API}/admin/enrollment-keys", headers=admin_headers).json()
    revoked = client.post(
        f"{API}/admin/enrollment-keys/{record['id']}/revoke", headers=admin_headers
    )
    assert revoked.status_code == 200 and revoked.json()["revoked_at"] is not None
    assert _enroll_raw(client, key, inventory_factory(hostname="pc-2")).status_code == 401
    assert (
        heartbeat(_bearer(first["node_credential"]), inventory_factory(hostname="pc-1")).status_code
        == 200
    )


def test_key_limits_are_capped_by_configuration(client, admin_headers, settings):
    response = client.post(
        f"{API}/admin/enrollment-keys",
        headers=admin_headers,
        json={"lab": "CS Lab B", "max_uses": settings.enrollment_key_max_uses + 1},
    )
    assert response.status_code == 422
    bad_lab = client.post(
        f"{API}/admin/enrollment-keys", headers=admin_headers, json={"lab": "<script>"}
    )
    assert bad_lab.status_code == 422


def test_pending_node_must_be_approved_before_it_is_schedulable(
    app, client, admin_headers, student_headers, new_enrollment_key, inventory_factory, heartbeat
):
    key = new_enrollment_key(auto_approve=False)
    inventory = inventory_factory()
    body = _enroll_raw(client, key, inventory).json()
    assert body["admin_state"] == "pending"
    headers = _bearer(body["node_credential"])

    # A pending node may report (so IT can inspect its hardware) but is never schedulable.
    assert heartbeat(headers, inventory).json()["admin_state"] == "pending"
    node = client.get(f"{API}/admin/nodes/{body['node_id']}", headers=admin_headers).json()
    assert node["admin_state"] == "pending" and node["schedulable"] is False
    summary = client.get(f"{API}/resources/summary", headers=student_headers).json()
    assert summary["pending_nodes"] == 1 and summary["online_nodes"] == 0

    bypass = client.post(
        f"{API}/admin/nodes/{body['node_id']}/state",
        headers=admin_headers,
        json={"admin_state": "active"},
    )
    assert bypass.status_code == 409, "approval must go through the audited approve endpoint"
    approved = client.post(f"{API}/admin/nodes/{body['node_id']}/approve", headers=admin_headers)
    assert approved.status_code == 200
    assert approved.json()["schedulable"] is True and approved.json()["approved_at"]
    assert (
        client.post(
            f"{API}/admin/nodes/{body['node_id']}/approve", headers=admin_headers
        ).status_code
        == 409
    )
    assert len(_audit(app, "node.approved")) == 1


def test_students_cannot_manage_keys_or_approve(client, student_headers):
    assert client.get(f"{API}/admin/enrollment-keys", headers=student_headers).status_code == 403
    assert (
        client.post(
            f"{API}/admin/nodes/00000000-0000-0000-0000-000000000000/approve",
            headers=student_headers,
        ).status_code
        == 403
    )


def test_two_phase_credential_rotation(app, client, admin_headers, enroll, heartbeat):
    body, old_headers, inventory = enroll()
    rotated = client.post(f"{API}/agent/credential/rotate", headers=old_headers)
    assert rotated.status_code == 200
    new_headers = _bearer(rotated.json()["node_credential"])

    # Until the new credential is used, the old one keeps working (lost-response safety).
    assert heartbeat(old_headers, inventory).status_code == 200
    node = client.get(f"{API}/admin/nodes/{body['node_id']}", headers=admin_headers).json()
    assert node["credential_rotation_pending"] is True

    assert heartbeat(new_headers, inventory).status_code == 200  # promotes the new credential
    assert heartbeat(old_headers, inventory).status_code == 401
    assert heartbeat(new_headers, inventory).status_code == 200
    node = client.get(f"{API}/admin/nodes/{body['node_id']}", headers=admin_headers).json()
    assert node["credential_rotation_pending"] is False
    assert len(_audit(app, "node.credential_rotated")) == 1


def test_lost_rotation_response_can_be_retried(client, enroll, heartbeat):
    _, old_headers, inventory = enroll()
    client.post(f"{API}/agent/credential/rotate", headers=old_headers)  # response "lost"
    retry = client.post(f"{API}/agent/credential/rotate", headers=old_headers)
    assert retry.status_code == 200
    assert heartbeat(_bearer(retry.json()["node_credential"]), inventory).status_code == 200


def test_controller_requests_rotation_when_credential_is_old(enroll, heartbeat, clock, settings):
    _, headers, inventory = enroll()
    assert heartbeat(headers, inventory).json()["rotate_credential"] is False
    clock.advance(days=settings.node_credential_max_age_days)
    assert heartbeat(headers, inventory).json()["rotate_credential"] is True


def test_revocation_also_kills_a_pending_rotated_credential(
    client, admin_headers, enroll, heartbeat
):
    body, old_headers, inventory = enroll()
    new = client.post(f"{API}/agent/credential/rotate", headers=old_headers).json()
    client.post(f"{API}/admin/nodes/{body['node_id']}/revoke", headers=admin_headers)
    assert heartbeat(_bearer(new["node_credential"]), inventory).status_code == 401
    assert heartbeat(old_headers, inventory).status_code == 403


def test_policy_is_delivered_with_heartbeats(enroll, heartbeat):
    _, headers, inventory = enroll()
    policy = heartbeat(headers, inventory).json()["protection_policy"]
    assert policy["envelopes"]["shared"]["allow_memory_class"] is False
    assert 0.5 <= policy["assessment_interval_seconds"] <= 2.0
