from sqlalchemy import select

from udcs_controller.audit.models import AuditEvent
from udcs_shared.agent_api import PROTOCOL_VERSION

API = "/api/v1"


def _audit(app, action):
    with app.state.sessionmaker() as db:
        return db.scalars(select(AuditEvent).where(AuditEvent.action == action)).all()


def _nodes(client, admin_headers):
    response = client.get(f"{API}/admin/nodes", headers=admin_headers)
    assert response.status_code == 200
    return response.json()


def test_enroll_heartbeat_and_status(
    app, client, admin_headers, enroll, heartbeat, clock, settings
):
    body, node_headers, inventory = enroll()
    assert body["node_credential"].startswith("udcs_n_")
    assert body["heartbeat_interval_seconds"] == settings.heartbeat_interval_seconds

    response = heartbeat(node_headers, inventory)
    assert response.status_code == 200
    hb = response.json()
    assert {
        k: hb[k]
        for k in (
            "heartbeat_interval_seconds",
            "inventory_required",
            "admin_state",
            "rotate_credential",
        )
    } == {
        "heartbeat_interval_seconds": settings.heartbeat_interval_seconds,
        "inventory_required": False,
        "admin_state": "active",
        "rotate_credential": False,
    }
    assert hb["protection_policy"]["version"] == settings.protection_policy_version

    [node] = _nodes(client, admin_headers)
    assert node["id"] == body["node_id"]
    assert node["connectivity"] == "online" and node["schedulable"] is True
    assert node["inventory"]["gpus"][0]["name"] == "NVIDIA GeForce RTX 3060"
    assert node["latest_telemetry"]["cpu_percent"] == 12.5
    assert len(_audit(app, "node.enrolled")) == 1

    clock.advance(seconds=settings.offline_after.total_seconds() + 1)
    [node] = _nodes(client, admin_headers)
    assert node["connectivity"] == "offline" and node["schedulable"] is False

    assert heartbeat(node_headers, inventory).status_code == 200
    assert _nodes(client, admin_headers)[0]["connectivity"] == "online"


def test_liveness_uses_controller_clock_not_agent_clock(
    client, admin_headers, enroll, heartbeat, telemetry_factory, clock
):
    from datetime import UTC, datetime

    _, node_headers, inventory = enroll()
    stale = telemetry_factory(collected_at=datetime(2001, 1, 1, tzinfo=UTC))
    assert heartbeat(node_headers, inventory, stale).status_code == 200
    [node] = _nodes(client, admin_headers)
    assert node["last_heartbeat_at"].startswith(clock.now.isoformat()[:19])
    assert node["connectivity"] == "online"


def test_enrollment_token_is_single_use(
    app, client, enroll, new_enrollment_token, inventory_factory
):
    token = new_enrollment_token()
    enroll(token=token)
    second = client.post(
        f"{API}/agent/enroll",
        json={
            "enrollment_token": token,
            "protocol_version": PROTOCOL_VERSION,
            "inventory": inventory_factory(hostname="lab-b-08").model_dump(mode="json"),
        },
    )
    assert second.status_code == 401
    assert len(_audit(app, "node.enroll_rejected")) == 1


def test_expired_and_unknown_tokens_are_rejected(
    client, new_enrollment_token, inventory_factory, clock
):
    token = new_enrollment_token(ttl_minutes=5)
    clock.advance(minutes=6)
    inventory = inventory_factory().model_dump(mode="json")
    for candidate in (token, "udcs_e_" + "B" * 43, "not-even-a-udcs-token-xx"):
        response = client.post(
            f"{API}/agent/enroll",
            json={
                "enrollment_token": candidate,
                "protocol_version": PROTOCOL_VERSION,
                "inventory": inventory,
            },
        )
        assert response.status_code == 401


def test_unsupported_protocol_does_not_consume_token(
    client, new_enrollment_token, inventory_factory, enroll
):
    token = new_enrollment_token()
    response = client.post(
        f"{API}/agent/enroll",
        json={
            "enrollment_token": token,
            "protocol_version": 99,
            "inventory": inventory_factory().model_dump(mode="json"),
        },
    )
    assert response.status_code == 400
    enroll(token=token)  # still valid


def test_enrollment_token_ttl_is_capped(client, admin_headers, settings):
    too_long = settings.enrollment_key_max_ttl_minutes + 1
    response = client.post(
        f"{API}/admin/enrollment-keys",
        headers=admin_headers,
        json={"lab": "CS Lab B", "ttl_minutes": too_long},
    )
    assert response.status_code == 422


def test_inventory_resync_on_hardware_change(
    app, client, admin_headers, enroll, heartbeat, inventory_factory
):
    _, node_headers, _original = enroll()
    upgraded = inventory_factory(gpus=(("NVIDIA GeForce RTX 4060 Ti", 16 * 2**30, "8.9"),))
    assert heartbeat(node_headers, upgraded).json()["inventory_required"] is True

    response = client.put(
        f"{API}/agent/inventory",
        headers=node_headers,
        json={"inventory": upgraded.model_dump(mode="json")},
    )
    assert response.status_code == 204
    assert heartbeat(node_headers, upgraded).json()["inventory_required"] is False
    [node] = _nodes(client, admin_headers)
    assert node["inventory"]["gpus"][0]["name"] == "NVIDIA GeForce RTX 4060 Ti"
    assert len(_audit(app, "node.inventory_changed")) == 1


def test_revoked_node_is_locked_out_permanently(app, client, admin_headers, enroll, heartbeat):
    body, node_headers, inventory = enroll()
    response = client.post(f"{API}/admin/nodes/{body['node_id']}/revoke", headers=admin_headers)
    assert response.status_code == 200 and response.json()["admin_state"] == "revoked"
    assert heartbeat(node_headers, inventory).status_code == 403
    reactivate = client.post(
        f"{API}/admin/nodes/{body['node_id']}/state",
        headers=admin_headers,
        json={"admin_state": "active"},
    )
    assert reactivate.status_code == 409
    assert len(_audit(app, "node.revoked")) == 1


def test_maintenance_mode(client, admin_headers, student_headers, enroll, heartbeat):
    body, node_headers, inventory = enroll()
    response = client.post(
        f"{API}/admin/nodes/{body['node_id']}/state",
        headers=admin_headers,
        json={"admin_state": "maintenance"},
    )
    assert response.status_code == 200 and response.json()["schedulable"] is False
    assert heartbeat(node_headers, inventory).json()["admin_state"] == "maintenance"
    summary = client.get(f"{API}/resources/summary", headers=student_headers).json()
    assert summary["maintenance_nodes"] == 1 and summary["online_nodes"] == 0
    bad = client.post(
        f"{API}/admin/nodes/{body['node_id']}/state",
        headers=admin_headers,
        json={"admin_state": "revoked"},
    )
    assert bad.status_code == 422  # revocation has its own audited endpoint


def test_invalid_telemetry_is_rejected(client, enroll, telemetry_factory, inventory_factory):
    _, node_headers, inventory = enroll()
    good = telemetry_factory().model_dump(mode="json")
    for telemetry in (
        {**good, "cpu_percent": 150},
        {**good, "memory_available_bytes": good["memory_total_bytes"] + 1},
        {**good, "run_as_admin": True},
    ):
        response = client.post(
            f"{API}/agent/heartbeat",
            headers=node_headers,
            json={
                "protocol_version": PROTOCOL_VERSION,
                "telemetry": telemetry,
                "inventory_fingerprint": inventory.fingerprint(),
            },
        )
        assert response.status_code == 422


def test_credential_types_are_not_interchangeable(client, admin_headers, enroll, heartbeat):
    _, node_headers, inventory = enroll()
    assert heartbeat(admin_headers, inventory).status_code == 401
    assert client.get(f"{API}/auth/me", headers=node_headers).status_code == 401
    assert client.get(f"{API}/admin/nodes", headers=node_headers).status_code == 401


def test_resource_summary_aggregates_without_identities(
    client, student_headers, enroll, heartbeat, inventory_factory
):
    for hostname, gpus in (
        ("lab-a-01", (("NVIDIA GeForce RTX 3060", 12 * 2**30, "8.6"),)),
        ("lab-a-02", (("NVIDIA GeForce RTX 3060", 12 * 2**30, "8.6"),)),
        ("lab-c-01", ()),  # CPU-only machine
    ):
        _, headers, inventory = enroll(inventory_factory(hostname=hostname, gpus=gpus))
        heartbeat(headers, inventory)

    response = client.get(f"{API}/resources/summary", headers=student_headers)
    summary = response.json()
    assert summary["online_nodes"] == 3
    assert summary["gpu_count"] == 2
    assert summary["total_logical_cores"] == 60
    assert summary["gpu_models"] == [
        {
            "name": "NVIDIA GeForce RTX 3060",
            "memory_total_bytes": 12 * 2**30,
            "compute_capability": "8.6",
            "count": 2,
        }
    ]
    assert "lab-a-01" not in response.text and "10.20.30.40" not in response.text


def test_audit_log_lists_events_newest_first(
    client, admin_headers, enroll, new_enrollment_token, clock
):
    # Distinct timestamps: with a frozen clock the order of tied events is undefined, and
    # SQLite and PostgreSQL legitimately return them in different orders.
    clock.advance(seconds=1)
    token = new_enrollment_token()
    clock.advance(seconds=1)
    enroll(token=token)
    events = client.get(f"{API}/admin/audit-events", headers=admin_headers).json()
    actions = [e["action"] for e in events]
    assert actions[0] == "node.enrolled"
    assert actions.index("enrollment_key.created") < actions.index("auth.login_succeeded")
    stamps = [e["created_at"] for e in events]
    assert stamps == sorted(stamps, reverse=True)
    assert "enrollment_key.created" in actions and "auth.login_succeeded" in actions
    assert all(
        "token" not in str(e["details"]).lower() or "token_id" in str(e["details"]) for e in events
    )
