"""I-2 fix 1: NVML starts lazily, once, and only for the controller link's needs.

nvmlInit() costs ~21-23 MiB that is never released (docs/research/2026-11-28-i2-service-
memory.md). An unenrolled agent never uses NVML, so it must never call nvmlInit.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

from udcs_agent.discovery import collect_inventory
from udcs_agent.discovery.nvidia import Nvml

SRC = Path(__file__).resolve().parents[1] / "src" / "udcs_agent"


def _counting(module):
    """Wrap a fake pynvml so nvmlInit / nvmlShutdown calls are counted."""
    calls = {"init": 0, "shutdown": 0}
    init, shutdown = module.nvmlInit, module.nvmlShutdown

    def counted_init():
        calls["init"] += 1
        init()

    def counted_shutdown():
        calls["shutdown"] += 1
        shutdown()

    module.nvmlInit, module.nvmlShutdown = counted_init, counted_shutdown
    return module, calls


# -- Nvml itself -----------------------------------------------------------------------------


def test_constructing_nvml_does_not_start_it(fake_pynvml):
    module, calls = _counting(fake_pynvml())
    nvml = Nvml(loader=lambda: module)
    assert calls["init"] == 0 and not nvml.available
    nvml.shutdown()  # shutting down a never-started NVML is a no-op
    assert calls["shutdown"] == 0


def test_inventory_starts_nvml_on_demand(fake_pynvml):
    module, calls = _counting(fake_pynvml())
    nvml = Nvml(loader=lambda: module)
    inventory = collect_inventory(nvml)
    assert calls["init"] == 1
    assert [g.name for g in inventory.gpus] == ["GeForce GT 730"]
    collect_inventory(nvml)
    assert calls["init"] == 1  # once per process, not per call


def test_telemetry_starts_nvml_on_first_use(fake_pynvml):
    module, calls = _counting(fake_pynvml())
    nvml = Nvml(loader=lambda: module)
    [sample] = nvml.gpu_telemetry()
    assert calls["init"] == 1 and sample.temperature_c == 52.0
    nvml.gpu_telemetry()
    assert calls["init"] == 1


def test_failed_start_is_not_retried_on_every_telemetry_sample(fake_pynvml):
    module, calls = _counting(fake_pynvml(init_fails=True))
    nvml = Nvml(loader=lambda: module)
    assert nvml.gpu_telemetry() == [] and nvml.error.startswith("NVML unavailable")
    assert nvml.gpu_telemetry() == []
    assert calls["init"] == 1  # telemetry tries once; inventory refresh keeps retrying
    collect_inventory(nvml)
    assert calls["init"] == 2


def test_concurrent_callers_initialize_nvml_exactly_once(fake_pynvml):
    module, calls = _counting(fake_pynvml())
    slow_init = module.nvmlInit

    def slow():
        time.sleep(0.05)  # widen the race window
        slow_init()

    module.nvmlInit = slow
    nvml = Nvml(loader=lambda: module)
    barrier = threading.Barrier(16)
    errors: list[BaseException] = []

    def caller(i: int) -> None:
        try:
            barrier.wait()
            if i % 2:
                nvml.ensure_started()
            else:
                nvml.gpu_telemetry()
        except BaseException as exc:  # noqa: BLE001 -- surfaced by the assert below
            errors.append(exc)

    threads = [threading.Thread(target=caller, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert not errors
    assert calls["init"] == 1 and nvml.available


# -- the composed agent ----------------------------------------------------------------------

windows = pytest.mark.skipif(sys.platform != "win32", reason="AgentApp's Windows service path")


def _status_ticks(data_dir: Path) -> int:
    try:
        return json.loads((data_dir / "status" / "governor.json").read_text("utf-8"))["ticks"]
    except (FileNotFoundError, ValueError, KeyError):
        return 0


def _wait(predicate, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


def _run_agent(data_dir: Path, until):
    from udcs_agent.app import AgentApp

    stop = threading.Event()
    app = AgentApp(data_dir, stop=stop, require_secure_data_dir=False, helper_channel=False)
    result: dict[str, int] = {}
    thread = threading.Thread(target=lambda: result.update(code=app.run()))
    thread.start()
    try:
        assert _wait(until), "agent did not reach the expected state"
    finally:
        stop.set()
        thread.join(timeout=20)
    assert not thread.is_alive(), "agent did not stop"
    return result.get("code")


def _enroll(data_dir: Path) -> None:
    import socket

    from udcs_agent.config import CREDENTIAL_FILENAME, AgentConfig, save_config
    from udcs_agent.credentials import CredentialStore, NodeCredential

    with socket.socket() as sock:  # nothing listens here: heartbeats fail, the link retries
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    save_config(data_dir, AgentConfig(controller_url=f"https://127.0.0.1:{port}"))
    CredentialStore(data_dir / CREDENTIAL_FILENAME).save(
        NodeCredential(node_id=uuid.uuid4(), secret="udcs_n_" + "x" * 43)
    )


@windows
def test_unenrolled_agent_never_calls_nvml_init(tmp_path, monkeypatch, fake_pynvml):
    from udcs_agent.app import EXIT_OK

    module, calls = _counting(fake_pynvml())
    monkeypatch.setitem(sys.modules, "pynvml", module)
    code = _run_agent(tmp_path, until=lambda: _status_ticks(tmp_path) >= 3)
    assert code == EXIT_OK
    assert calls == {"init": 0, "shutdown": 0}


@windows
def test_enrolled_agent_starts_nvml_once_for_the_controller_link(
    tmp_path, monkeypatch, fake_pynvml
):
    # With the controller unreachable the link keeps retrying the inventory upload, so this
    # exercises inventory; telemetry's on-demand start is covered by the Nvml tests above.
    from udcs_agent import runner
    from udcs_agent.app import EXIT_OK

    module, calls = _counting(fake_pynvml())
    monkeypatch.setitem(sys.modules, "pynvml", module)
    monkeypatch.setattr(runner.AgentRunner, "backoff_delay", lambda self, failures: 0.2)
    uploads = {"n": 0}
    original = runner.AgentRunner.__init__

    def counting_init(self, controller, **kwargs):
        put = controller.put_inventory

        def counted_put(inventory):
            uploads["n"] += 1
            return put(inventory)

        controller.put_inventory = counted_put
        original(self, controller, **kwargs)

    monkeypatch.setattr(runner.AgentRunner, "__init__", counting_init)
    _enroll(tmp_path)
    code = _run_agent(
        tmp_path,
        until=lambda: calls["init"] >= 1 and uploads["n"] >= 3 and _status_ticks(tmp_path) >= 3,
    )
    assert code == EXIT_OK
    assert calls["init"] == 1  # started once for the link, not per inventory attempt
    assert calls["shutdown"] == 1  # released on agent stop, as before


@windows
def test_enrolled_agent_survives_an_nvml_start_failure(tmp_path, monkeypatch, fake_pynvml):
    from udcs_agent.app import EXIT_OK

    module, calls = _counting(fake_pynvml(init_fails=True))
    monkeypatch.setitem(sys.modules, "pynvml", module)
    _enroll(tmp_path)
    code = _run_agent(tmp_path, until=lambda: calls["init"] >= 1 and _status_ticks(tmp_path) >= 3)
    assert code == EXIT_OK  # no crash; GPU discovery reports the error instead
    assert calls["shutdown"] == 0


def test_governor_does_not_depend_on_nvml():
    # The governor's GPU signals come from PDH (governor/signals.py), never from NVML.
    for path in (SRC / "governor").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for needle in ("pynvml", "discovery.nvidia", "Nvml"):
            assert needle not in text, f"{path.name} references {needle}"
