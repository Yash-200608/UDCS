"""I-2 fix 1, end to end: the enrolled agent against a local fake controller.

A real ControllerClient talks plain HTTP to a ThreadingHTTPServer on 127.0.0.1 that
accepts inventory, answers heartbeats and returns empty job syncs, so the runner's real
inventory -> heartbeat(telemetry) -> job-sync cycle runs. pynvml is a fake that counts
nvmlInit / nvmlShutdown, records which code path started NVML, and can be told to fail or
to lose the driver mid-run.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from udcs_agent.discovery.nvidia import Nvml

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="AgentApp's Windows service path")

HEARTBEAT = {
    "heartbeat_interval_seconds": 5,
    "inventory_required": False,
    "admin_state": "active",
    "protection_policy": None,
    "rotate_credential": False,
}
JOB_SYNC = {"assignments": [], "cancel": [], "acknowledged": [], "lease_seconds": 60}


class FakeController:
    """Minimal agent API: inventory, heartbeat, job sync. Records what it receives."""

    def __init__(self) -> None:
        self.inventories: list[int] = []  # GPU count of each inventory upload
        self.inventory_errors: list[str | None] = []
        self.heartbeats: list[int] = []  # GPU count in each heartbeat's telemetry
        self.syncs = 0
        self.unknown: list[str] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):  # keep test output clean
                pass

            def _body(self):
                length = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(length) or b"{}")

            def _reply(self, status: int, payload: dict | None = None) -> None:
                data = json.dumps(payload).encode() if payload is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_PUT(self):
                if self.path == "/api/v1/agent/inventory":
                    inventory = self._body()["inventory"]
                    fake.inventories.append(len(inventory["gpus"]))
                    fake.inventory_errors.append(inventory.get("gpu_discovery_error"))
                    return self._reply(204)
                fake.unknown.append(f"PUT {self.path}")
                return self._reply(404, {"detail": "not found"})

            def do_POST(self):
                if self.path == "/api/v1/agent/heartbeat":
                    fake.heartbeats.append(len(self._body()["telemetry"]["gpus"]))
                    return self._reply(200, HEARTBEAT)
                if self.path == "/api/v1/agent/jobs/sync":
                    self._body()
                    fake.syncs += 1
                    return self._reply(200, JOB_SYNC)
                fake.unknown.append(f"POST {self.path}")
                return self._reply(404, {"detail": "not found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> FakeController:
        self.thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.server.shutdown()
        self.server.server_close()


def _controllable(fake_pynvml):
    """A fake pynvml whose init / device count can fail on demand; counts and records
    which code path (collect_inventory or gpu_telemetry) called nvmlInit."""
    module = fake_pynvml()
    state = {"init_fails": False, "count_fails": False}
    calls = {"init": 0, "shutdown": 0, "initiators": []}
    count = module.nvmlDeviceGetCount

    def init():
        calls["init"] += 1
        names = [f.name for f in traceback.extract_stack()]
        calls["initiators"].append(
            next((n for n in reversed(names) if n in ("collect_inventory", "gpu_telemetry")), "?")
        )
        if state["init_fails"]:
            raise module.NVMLError("Driver Not Loaded")

    def device_count():
        if state["count_fails"]:
            raise module.NVMLError("GPU is lost")
        return count()

    def shutdown():
        calls["shutdown"] += 1

    module.nvmlInit, module.nvmlDeviceGetCount, module.nvmlShutdown = init, device_count, shutdown
    return module, state, calls


def _wait(predicate, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


class _Agent:
    """The real AgentApp, enrolled against `controller`, on a thread."""

    def __init__(self, data_dir: Path, controller: FakeController) -> None:
        from udcs_agent.app import AgentApp
        from udcs_agent.config import CREDENTIAL_FILENAME, AgentConfig, save_config
        from udcs_agent.credentials import CredentialStore, NodeCredential

        save_config(data_dir, AgentConfig(controller_url=controller.url, allow_insecure_http=True))
        CredentialStore(data_dir / CREDENTIAL_FILENAME).save(
            NodeCredential(node_id=uuid.uuid4(), secret="udcs_n_" + "x" * 43)
        )
        self.stop = threading.Event()
        self.app = AgentApp(
            data_dir, stop=self.stop, require_secure_data_dir=False, helper_channel=False
        )
        self.result: dict[str, int] = {}
        self.thread = threading.Thread(target=lambda: self.result.update(code=self.app.run()))

    def __enter__(self) -> _Agent:
        self.thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        self.stop.set()
        self.thread.join(timeout=20)
        assert not self.thread.is_alive(), "agent did not stop"


@pytest.fixture
def fast_link(monkeypatch):
    """Heartbeat every 0.2 s instead of the protocol minimum of 5 s (test only)."""
    from udcs_agent import runner

    monkeypatch.setattr(runner, "clamp_interval", lambda _seconds: 0.2)
    return runner


def test_heartbeats_carry_gpu_telemetry_from_one_nvml_start(
    tmp_path, monkeypatch, fake_pynvml, fast_link
):
    from udcs_agent.app import EXIT_OK

    module, _state, calls = _controllable(fake_pynvml)
    monkeypatch.setitem(sys.modules, "pynvml", module)
    with FakeController() as controller, _Agent(tmp_path, controller) as agent:
        assert _wait(lambda: len(controller.heartbeats) >= 6), "no heartbeat cycle"
        assert calls["init"] == 1  # 1 + 2: started once, not per heartbeat
        assert calls["initiators"] == ["collect_inventory"]  # the link's first NVML user
        assert controller.inventories[0] == 1
        assert all(n == 1 for n in controller.heartbeats)  # telemetry read the started NVML
        assert controller.syncs >= 1 and not controller.unknown
    assert agent.result["code"] == EXIT_OK
    assert calls["shutdown"] == 1  # 3: exactly once, on agent stop


def test_real_telemetry_collector_starts_nvml_on_first_use(tmp_path, fake_pynvml):
    # When telemetry is the first NVML user, the real collector path starts it.
    from udcs_agent.monitoring.telemetry import TelemetryCollector

    module, _state, calls = _controllable(fake_pynvml)
    nvml = Nvml(loader=lambda: module)
    collector = TelemetryCollector(nvml, tmp_path)
    assert calls["init"] == 0
    first = collector.collect()
    assert calls["init"] == 1 and calls["initiators"] == ["gpu_telemetry"]
    assert len(first.gpus) == 1
    for _ in range(5):
        assert len(collector.collect().gpus) == 1
    assert calls["init"] == 1
    nvml.shutdown()
    nvml.shutdown()
    assert calls["shutdown"] == 1


def test_nvml_start_failure_does_not_stop_heartbeats(tmp_path, monkeypatch, fake_pynvml, fast_link):
    from udcs_agent.app import EXIT_OK

    module, state, calls = _controllable(fake_pynvml)
    state["init_fails"] = True
    monkeypatch.setitem(sys.modules, "pynvml", module)
    with FakeController() as controller, _Agent(tmp_path, controller) as agent:
        assert _wait(lambda: len(controller.heartbeats) >= 3), "heartbeats stopped"
        attempts = calls["init"]  # link setup and the runner's first inventory each retry
        assert _wait(lambda: len(controller.heartbeats) >= 10), "heartbeats stopped"
        assert controller.inventories[0] == 0
        assert "Driver Not Loaded" in (controller.inventory_errors[0] or "")
        assert all(n == 0 for n in controller.heartbeats)
        # Telemetry never retries a failed start: 7 more heartbeats, no new attempt.
        assert calls["init"] == attempts
        assert set(calls["initiators"]) == {"collect_inventory"}
    assert agent.result["code"] == EXIT_OK  # 4: no crash
    assert calls["shutdown"] == 0  # nothing was started, nothing to shut down


def test_driver_loss_and_recovery_through_inventory_refresh(
    tmp_path, monkeypatch, fake_pynvml, fast_link
):
    from udcs_agent.app import EXIT_OK

    monkeypatch.setattr(fast_link.AgentRunner, "INVENTORY_REFRESH_SECONDS", 0.5)
    module, state, calls = _controllable(fake_pynvml)
    monkeypatch.setitem(sys.modules, "pynvml", module)
    with FakeController() as controller, _Agent(tmp_path, controller) as agent:
        assert _wait(lambda: len(controller.heartbeats) >= 3 and all(controller.heartbeats))
        state["count_fails"] = True  # the driver goes away (update / GPU reset)
        lost_at = len(controller.heartbeats)
        assert _wait(lambda: 0 in controller.heartbeats[lost_at:]), "loss not reported"
        assert _wait(lambda: 0 in controller.inventories), "refresh did not report the loss"
        state["count_fails"] = False  # the driver is back
        back_at = len(controller.heartbeats)
        assert _wait(lambda: controller.heartbeats[back_at:].count(1) >= 3), "no recovery"
        assert controller.inventories[-1] == 1  # refresh re-sent the recovered inventory
    assert agent.result["code"] == EXIT_OK
    # 5: every re-start after the loss came from inventory refresh, never from telemetry.
    assert calls["init"] >= 2
    assert set(calls["initiators"]) == {"collect_inventory"}
    assert calls["shutdown"] == 1


def test_shutdown_is_not_blocked_by_a_hung_nvml_start(fake_pynvml):
    module, _state, calls = _controllable(fake_pynvml)
    release = threading.Event()
    started = threading.Event()
    hung_init = module.nvmlInit

    def hanging():
        started.set()
        release.wait(10)  # a driver stuck inside nvmlInit
        hung_init()

    module.nvmlInit = hanging
    nvml = Nvml(loader=lambda: module)
    starter = threading.Thread(target=nvml.ensure_started)
    starter.start()
    assert started.wait(5)
    t0 = time.monotonic()
    nvml.shutdown(timeout=0.5)  # the agent's stop path
    assert time.monotonic() - t0 < 2.0, "shutdown waited for the hung nvmlInit"
    assert calls["shutdown"] == 0
    release.set()
    starter.join(5)
    assert nvml.available  # the late start completed; a later shutdown releases it
    nvml.shutdown()
    assert calls["shutdown"] == 1
