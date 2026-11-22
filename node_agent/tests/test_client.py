from datetime import UTC, datetime

import httpx
import pytest

from udcs_agent.communication.client import (
    ControllerClient,
    ControllerUnavailable,
    CredentialRejected,
    EnrollmentRejected,
    ProtocolError,
)
from udcs_agent.config import AgentConfig
from udcs_shared.agent_api import HeartbeatRequest
from udcs_shared.telemetry import TelemetrySnapshot

CONFIG = AgentConfig(controller_url="https://udcs.campus.test")


def _heartbeat_request(make_inventory):
    return HeartbeatRequest(
        protocol_version=1,
        telemetry=TelemetrySnapshot(
            collected_at=datetime.now(UTC),
            cpu_percent=1,
            memory_total_bytes=10,
            memory_available_bytes=5,
            uptime_seconds=1,
        ),
        inventory_fingerprint=make_inventory().fingerprint(),
    )


def _client(handler, credential="udcs_n_test"):
    return ControllerClient(CONFIG, credential=credential, transport=httpx.MockTransport(handler))


def test_heartbeat_sends_credential_and_request_id(make_inventory):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers["Authorization"]
        seen["rid"] = request.headers["X-Request-ID"]
        seen["path"] = request.url.path
        return httpx.Response(
            200,
            json={
                "heartbeat_interval_seconds": 20,
                "inventory_required": True,
                "admin_state": "active",
            },
        )

    response = _client(handler).heartbeat(_heartbeat_request(make_inventory))
    assert response.heartbeat_interval_seconds == 20 and response.inventory_required
    assert seen == {
        "auth": "Bearer udcs_n_test",
        "rid": seen["rid"],
        "path": "/api/v1/agent/heartbeat",
    }
    assert seen["rid"].startswith("agent-")


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (401, CredentialRejected),
        (403, CredentialRejected),
        (429, ControllerUnavailable),
        (500, ControllerUnavailable),
        (503, ControllerUnavailable),
        (400, ProtocolError),
        (422, ProtocolError),
        (302, ProtocolError),  # redirects are never followed
    ],
)
def test_status_mapping(status, error, make_inventory):
    client = _client(lambda _r: httpx.Response(status, json={"detail": "nope"}))
    with pytest.raises(error):
        client.heartbeat(_heartbeat_request(make_inventory))


def test_network_errors_mean_unavailable(make_inventory):
    def handler(request):
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(ControllerUnavailable, match="cannot reach"):
        _client(handler).heartbeat(_heartbeat_request(make_inventory))


def test_malformed_response_is_protocol_error(make_inventory):
    client = _client(lambda _r: httpx.Response(200, json={"unexpected": True}))
    with pytest.raises(ProtocolError):
        client.heartbeat(_heartbeat_request(make_inventory))


def test_enroll_rejection_is_distinct(make_inventory):
    client = _client(lambda _r: httpx.Response(401, json={"detail": "expired"}), credential=None)
    with pytest.raises(EnrollmentRejected, match="expired"):
        client.enroll("udcs_e_" + "x" * 43, make_inventory(), None)


def test_no_credential_never_hits_network(make_inventory):
    def handler(_request):
        raise AssertionError("should not be called")

    with pytest.raises(CredentialRejected):
        _client(handler, credential=None).heartbeat(_heartbeat_request(make_inventory))
