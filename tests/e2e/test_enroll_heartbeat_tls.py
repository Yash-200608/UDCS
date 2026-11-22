"""Milestone 1 acceptance test, automated.

A real controller (uvicorn, HTTPS with a throwaway CA) and the real agent
running on this machine's real hardware: enroll -> inventory -> heartbeats ->
the controller shows the node online with the hardware it actually has.
"""

from __future__ import annotations

import ssl
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import httpx
import psutil
import pytest
import trustme

from udcs_agent.communication.client import ControllerClient, ControllerUnavailable
from udcs_agent.config import AgentConfig
from udcs_agent.credentials import CredentialStore, NodeCredential
from udcs_agent.discovery import collect_inventory
from udcs_agent.discovery.nvidia import Nvml
from udcs_agent.monitoring.telemetry import TelemetryCollector
from udcs_agent.runner import AgentRunner, ExitReason

pytestmark = [pytest.mark.e2e, pytest.mark.hardware]


@contextmanager
def _admin_http(controller) -> Iterator[httpx.Client]:
    with httpx.Client(
        base_url=f"{controller.url}/api/v1",
        verify=ssl.create_default_context(cafile=str(controller.ca_file)),
    ) as http:
        token = http.post(
            "/auth/login", json={"username": "itadmin", "password": controller.admin_password}
        )
        http.headers["Authorization"] = f"Bearer {token.json()['access_token']}"
        yield http


def test_real_agent_enrolls_and_reports_real_hardware_over_tls(controller, tmp_path):
    config = AgentConfig(controller_url=controller.url, ca_bundle=controller.ca_file)
    store = CredentialStore(tmp_path / "node-credential.bin")

    with Nvml() as nvml:
        inventory = collect_inventory(nvml)
        with ControllerClient(config) as client:
            enrolled = client.enroll(controller.tokens[0], inventory, "e2e-lab-pc")
        store.save(NodeCredential(node_id=enrolled.node_id, secret=enrolled.node_credential))
        credential = store.load()

        telemetry = TelemetryCollector(nvml, tmp_path)
        with ControllerClient(config, credential=credential.secret) as client:
            runner = AgentRunner(
                client,
                inventory_source=lambda: collect_inventory(nvml),
                telemetry_source=telemetry.collect,
                wait=lambda _d: False,
            )
            assert runner.run(max_iterations=3) is ExitReason.MAX_ITERATIONS
            assert runner.consecutive_failures == 0

    with _admin_http(controller) as http:
        [node] = http.get("/admin/nodes").json()
        summary = http.get("/resources/summary").json()

    assert node["id"] == str(enrolled.node_id)
    assert node["name"] == "e2e-lab-pc"
    assert node["connectivity"] == "online" and node["schedulable"] is True
    reported = node["inventory"]
    assert reported["cpu"]["logical_cores"] == psutil.cpu_count(logical=True)
    assert reported["memory"]["total_bytes"] == psutil.virtual_memory().total
    assert [g["name"] for g in reported["gpus"]] == [g.name for g in inventory.gpus]
    assert node["latest_telemetry"]["memory_total_bytes"] == psutil.virtual_memory().total
    assert summary["online_nodes"] == 1 and summary["gpu_count"] == len(inventory.gpus)


def test_agent_refuses_a_controller_it_does_not_trust(controller, tmp_path):
    impostor_ca = trustme.CA()
    impostor_file = tmp_path / "other-ca.pem"
    impostor_ca.cert_pem.write_to_path(str(impostor_file))
    config = AgentConfig(controller_url=controller.url, ca_bundle=impostor_file)
    with Nvml() as nvml, ControllerClient(config) as client:
        with pytest.raises(ControllerUnavailable, match="CERTIFICATE_VERIFY_FAILED"):
            client.enroll(controller.tokens[1], collect_inventory(nvml), None)

    # The token was never seen by the controller, so it is still usable.
    trusted = AgentConfig(controller_url=controller.url, ca_bundle=controller.ca_file)
    with Nvml() as nvml, ControllerClient(trusted) as client:
        assert isinstance(
            client.enroll(controller.tokens[1], collect_inventory(nvml), None).node_id, uuid.UUID
        )


def test_revoked_agent_stops(controller, tmp_path):
    config = AgentConfig(controller_url=controller.url, ca_bundle=controller.ca_file)
    with Nvml() as nvml:
        with ControllerClient(config) as client:
            enrolled = client.enroll(controller.tokens[0], collect_inventory(nvml), None)
        with _admin_http(controller) as http:
            assert http.post(f"/admin/nodes/{enrolled.node_id}/revoke").status_code == 200
        with ControllerClient(config, credential=enrolled.node_credential) as client:
            runner = AgentRunner(
                client,
                inventory_source=lambda: collect_inventory(nvml),
                telemetry_source=TelemetryCollector(nvml, tmp_path).collect,
                wait=lambda _d: False,
            )
            assert runner.run(max_iterations=5) is ExitReason.CREDENTIAL_REJECTED
