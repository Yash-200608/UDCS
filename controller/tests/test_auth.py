from sqlalchemy import select

from udcs_controller.audit.models import AuditEvent
from udcs_controller.auth.permissions import Role

API = "/api/v1"


def _actions(app, action):
    with app.state.sessionmaker() as db:
        return db.scalars(select(AuditEvent).where(AuditEvent.action == action)).all()


def test_login_and_me(client, make_user, login):
    make_user("alice", Role.RESEARCHER)
    response = client.get(f"{API}/auth/me", headers=login("alice"))
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "alice" and body["role"] == "researcher"
    assert "password_hash" not in body


def test_username_is_case_insensitive(client, make_user, login):
    make_user("alice")
    assert client.get(f"{API}/auth/me", headers=login("ALICE")).status_code == 200


def test_bad_credentials_are_indistinguishable_and_audited(app, client, make_user):
    make_user("alice")
    wrong = client.post(
        f"{API}/auth/login", json={"username": "alice", "password": "nope-nope-nope"}
    )
    unknown = client.post(f"{API}/auth/login", json={"username": "mallory", "password": "x"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()
    assert len(_actions(app, "auth.login_failed")) == 2


def test_missing_or_malformed_credentials_are_rejected(client):
    for headers in (
        {},
        {"Authorization": "Bearer nope"},
        {"Authorization": "Basic YWxpY2U6cGFzcw=="},
        {"Authorization": "Bearer udcs_s_" + "A" * 43},
    ):
        assert client.get(f"{API}/auth/me", headers=headers).status_code == 401


def test_logout_revokes_session(client, make_user, login):
    make_user("alice")
    headers = login("alice")
    assert client.post(f"{API}/auth/logout", headers=headers).status_code == 204
    assert client.get(f"{API}/auth/me", headers=headers).status_code == 401


def test_session_expires(client, make_user, login, clock, settings):
    make_user("alice")
    headers = login("alice")
    clock.advance(minutes=settings.session_ttl_minutes + 1)
    assert client.get(f"{API}/auth/me", headers=headers).status_code == 401


def test_student_cannot_reach_admin_surface(client, student_headers):
    for method, path in (
        ("GET", "/admin/users"),
        ("POST", "/admin/users"),
        ("GET", "/admin/nodes"),
        ("POST", "/admin/enrollment-keys"),
        ("GET", "/admin/audit-events"),
        ("POST", "/admin/nodes/00000000-0000-0000-0000-000000000000/revoke"),
    ):
        response = client.request(method, f"{API}{path}", headers=student_headers, json={})
        assert response.status_code == 403, (method, path, response.status_code)


def test_student_can_view_resource_summary(client, student_headers):
    assert client.get(f"{API}/resources/summary", headers=student_headers).status_code == 200


def test_admin_creates_users_with_validation(client, admin_headers, login):
    new = {
        "username": "r.kumar",
        "display_name": "R Kumar",
        "password": "a-long-enough-pw",
        "role": "researcher",
    }
    assert client.post(f"{API}/admin/users", headers=admin_headers, json=new).status_code == 201
    assert client.post(f"{API}/admin/users", headers=admin_headers, json=new).status_code == 409
    for bad in (
        {**new, "username": "x2", "password": "short"},
        {**new, "username": "Has Spaces"},
        {**new, "username": "ok-name", "role": "superuser"},
        {**new, "username": "ok-name2", "is_admin": True},
    ):
        assert client.post(f"{API}/admin/users", headers=admin_headers, json=bad).status_code == 422
    assert (
        client.get(f"{API}/auth/me", headers=login("r.kumar", "a-long-enough-pw")).json()["role"]
        == "researcher"
    )


def test_admin_cannot_lock_themselves_out(client, admin_headers):
    me = client.get(f"{API}/auth/me", headers=admin_headers).json()
    for change in ({"role": "student"}, {"is_active": False}):
        response = client.patch(f"{API}/admin/users/{me['id']}", headers=admin_headers, json=change)
        assert response.status_code == 409


def test_deactivated_user_loses_access_immediately(client, admin_headers, make_user, login):
    bob = make_user("bob")
    bob_headers = login("bob")
    response = client.patch(
        f"{API}/admin/users/{bob.id}", headers=admin_headers, json={"is_active": False}
    )
    assert response.status_code == 200
    assert client.get(f"{API}/auth/me", headers=bob_headers).status_code == 401
    relogin = client.post(
        f"{API}/auth/login", json={"username": "bob", "password": "correct-horse-battery"}
    )
    assert relogin.status_code == 401


def test_login_is_rate_limited(client, make_user, settings, app):
    make_user("carol")
    for _ in range(settings.login_attempts_per_minute):
        response = client.post(f"{API}/auth/login", json={"username": "carol", "password": "wrong"})
        assert response.status_code == 401
    blocked = client.post(
        f"{API}/auth/login", json={"username": "carol", "password": "correct-horse-battery"}
    )
    assert blocked.status_code == 429
    assert _actions(app, "auth.login_rate_limited")


def test_request_id_is_echoed_or_generated(client):
    assert (
        client.get("/healthz", headers={"X-Request-ID": "abc-123"}).headers["X-Request-ID"]
        == "abc-123"
    )
    generated = client.get("/healthz", headers={"X-Request-ID": "bad id with spaces"})
    assert generated.headers["X-Request-ID"] != "bad id with spaces"


def test_readiness_checks_database(client):
    assert client.get("/readyz").json() == {"status": "ready"}
