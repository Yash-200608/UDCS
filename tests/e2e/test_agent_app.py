"""The composed agent (AgentApp): offline protection, rotation, graceful shutdown."""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
import uuid
from datetime import UTC, datetime

import pytest

from udcs_agent.app import EXIT_OK, AgentApp
from udcs_agent.communication.client import ControllerClient, CredentialRejected
from udcs_agent.config import CREDENTIAL_FILENAME, AgentConfig, save_config
from udcs_agent.credentials import CredentialStore, NodeCredential
from udcs_agent.discovery import collect_inventory
from udcs_agent.discovery.nvidia import Nvml
from udcs_agent.workloads.manager import WorkloadManager, WorkloadSpec
from udcs_shared.agent_api import PROTOCOL_VERSION, HeartbeatRequest
from udcs_shared.telemetry import TelemetrySnapshot

pytestmark = [pytest.mark.e2e, pytest.mark.skipif(sys.platform != "win32", reason="Windows")]


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]  # nothing listens here once the socket closes


def _status(data_dir):
    try:
        return json.loads((data_dir / "status" / "governor.json").read_text("utf-8"))
    except (FileNotFoundError, ValueError):
        return None


def _wait(predicate, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.25)
    return False


def test_offline_node_last_confirmed_active_keeps_lending_under_protection(tmp_path):
    # The controller last said ACTIVE; now it is unreachable. Local protection carries on.
    (tmp_path / "controller-state.json").write_text(
        '{"no_work": false, "admin_state": "active"}', encoding="utf-8"
    )
    save_config(tmp_path, AgentConfig(controller_url=f"https://127.0.0.1:{_closed_port()}"))
    CredentialStore(tmp_path / CREDENTIAL_FILENAME).save(
        NodeCredential(node_id=uuid.uuid4(), secret="udcs_n_" + "x" * 43)
    )
    WorkloadManager(tmp_path).add(WorkloadSpec(id="cpu1", kind="cpu"))

    stop = threading.Event()
    app = AgentApp(tmp_path, stop=stop)
    result: dict[str, int] = {}
    thread = threading.Thread(target=lambda: result.update(code=app.run()))
    thread.start()
    try:
        assert _wait(lambda: (_status(tmp_path) or {}).get("ticks", 0) >= 5), "governor idle"
        first = _status(tmp_path)["ticks"]
        assert _wait(lambda: _status(tmp_path)["ticks"] >= first + 5)
        status = _status(tmp_path)
        # Protection is active although no heartbeat has ever succeeded.
        assert status["workloads"]["cpu1"] in ("running", "throttled", "paused")
        assert status["protection"]["level"] in {
            "open",
            "away",
            "shared",
            "constrained",
            "protected",
        }
    finally:
        started = time.monotonic()
        stop.set()
        thread.join(timeout=15)
        shutdown_seconds = time.monotonic() - started
    assert result["code"] == EXIT_OK
    assert shutdown_seconds < 5.0, f"shutdown took {shutdown_seconds:.1f} s"
    registry = json.loads((tmp_path / "workloads" / "registry.json").read_text("utf-8"))
    assert registry["workloads"][0]["state"] == "waiting"  # resumable after restart


def _heartbeat(config, secret, inventory):
    with ControllerClient(config, credential=secret) as client:
        return client.heartbeat(
            HeartbeatRequest(
                protocol_version=PROTOCOL_VERSION,
                telemetry=TelemetrySnapshot(
                    collected_at=datetime.now(UTC),
                    cpu_percent=1,
                    memory_total_bytes=10,
                    memory_available_bytes=5,
                    uptime_seconds=1,
                ),
                inventory_fingerprint=inventory.fingerprint(),
            )
        )


def test_credential_rotation_through_the_real_controller(controller, tmp_path):
    config = AgentConfig(controller_url=controller.url, ca_bundle=controller.ca_file)
    save_config(tmp_path, config)
    with Nvml() as nvml:
        inventory = collect_inventory(nvml)
    with ControllerClient(config) as client:
        enrolled = client.enroll(controller.tokens[0], inventory, "rotation-node")
    store = CredentialStore(tmp_path / CREDENTIAL_FILENAME)
    store.save(NodeCredential(node_id=enrolled.node_id, secret=enrolled.node_credential))

    app = AgentApp(tmp_path)
    app._credential = store.load()
    app._client = ControllerClient(config, credential=enrolled.node_credential)
    try:
        app._rotate_credential()
        rotated = store.load().secret
        assert rotated != enrolled.node_credential, "the new credential must be persisted"
        _heartbeat(config, rotated, inventory)  # first use promotes the new credential
        with pytest.raises(CredentialRejected):
            _heartbeat(config, enrolled.node_credential, inventory)
    finally:
        app._client.close()


def test_no_work_state_survives_restart_and_fails_closed(tmp_path):
    app = AgentApp(tmp_path)
    assert app._load_no_work() is False  # never told anything: local-only mode
    app._save_no_work(True, "maintenance")
    assert AgentApp(tmp_path)._load_no_work() is True
    (tmp_path / "controller-state.json").write_text("{corrupt", encoding="utf-8")
    assert AgentApp(tmp_path)._load_no_work() is True  # unreadable -> fail closed


def test_enrolled_node_never_confirmed_lends_nothing_while_offline(tmp_path):
    """Fail closed: no word from the controller yet -> protect locally, lend nothing."""
    save_config(tmp_path, AgentConfig(controller_url=f"https://127.0.0.1:{_closed_port()}"))
    CredentialStore(tmp_path / CREDENTIAL_FILENAME).save(
        NodeCredential(node_id=uuid.uuid4(), secret="udcs_n_" + "x" * 43)
    )
    WorkloadManager(tmp_path).add(WorkloadSpec(id="cpu1", kind="cpu"))
    stop = threading.Event()
    app = AgentApp(tmp_path, stop=stop)
    thread = threading.Thread(target=app.run)
    thread.start()
    try:
        assert _wait(lambda: (_status(tmp_path) or {}).get("ticks", 0) >= 5)
        status = _status(tmp_path)
        assert status["protection"]["level"] == "maintenance"
        assert status["workloads"]["cpu1"] == "waiting"
    finally:
        stop.set()
        thread.join(timeout=15)
