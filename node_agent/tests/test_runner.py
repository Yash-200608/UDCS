from datetime import UTC, datetime

import pytest

from udcs_agent.communication.client import ControllerUnavailable, CredentialRejected
from udcs_agent.runner import AgentRunner, ExitReason, clamp_interval
from udcs_shared.agent_api import HeartbeatResponse, NodeAdminState
from udcs_shared.telemetry import TelemetrySnapshot


def ok(interval=15, inventory_required=False):
    return HeartbeatResponse(
        heartbeat_interval_seconds=interval,
        inventory_required=inventory_required,
        admin_state=NodeAdminState.ACTIVE,
    )


class FakeController:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def put_inventory(self, inventory):
        self.calls.append(("inventory", inventory.memory.total_bytes))

    def heartbeat(self, request):
        self.calls.append(("heartbeat", request.inventory_fingerprint))
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def telemetry():
    return TelemetrySnapshot(
        collected_at=datetime.now(UTC),
        cpu_percent=5,
        memory_total_bytes=10,
        memory_available_bytes=5,
        uptime_seconds=1,
    )


def make_runner(controller, inventory_source, **kwargs):
    waits = []
    runner = AgentRunner(
        controller,
        inventory_source=inventory_source,
        telemetry_source=telemetry,
        wait=lambda delay: waits.append(delay) or False,
        rng=lambda: 1.0,
        **kwargs,
    )
    return runner, waits


def test_sends_inventory_first_then_follows_server_interval(make_inventory):
    controller = FakeController([ok(interval=30), ok(interval=30)])
    runner, waits = make_runner(controller, make_inventory)
    assert runner.run(max_iterations=2) is ExitReason.MAX_ITERATIONS
    assert [c[0] for c in controller.calls] == ["inventory", "heartbeat", "heartbeat"]
    assert waits == [30.0]


def test_resends_inventory_when_controller_asks(make_inventory):
    controller = FakeController([ok(inventory_required=True), ok()])
    runner, waits = make_runner(controller, make_inventory)
    runner.run(max_iterations=2)
    assert [c[0] for c in controller.calls] == ["inventory", "heartbeat", "inventory", "heartbeat"]
    assert waits == [1.0]  # prompt, but not a hot loop


def test_stops_on_revocation(make_inventory):
    controller = FakeController([ok(), CredentialRejected("HTTP 403: node has been revoked")])
    runner, _ = make_runner(controller, make_inventory)
    assert runner.run() is ExitReason.CREDENTIAL_REJECTED


def test_exponential_backoff_then_recovery(make_inventory):
    outage = [ControllerUnavailable("down")] * 4
    controller = FakeController([*outage, ok()])
    runner, waits = make_runner(controller, make_inventory)
    runner.run(max_iterations=5)
    assert waits[:4] == [15.0, 30.0, 60.0, 120.0]
    assert runner.consecutive_failures == 0
    # inventory upload succeeded before the outage, so it is not repeated
    assert controller.calls.count(("inventory", 16 * 2**30)) == 1


def test_failed_inventory_upload_is_retried(make_inventory):
    class FlakyInventory(FakeController):
        def put_inventory(self, inventory):
            super().put_inventory(inventory)
            if len(self.calls) == 1:
                raise ControllerUnavailable("down")

    controller = FlakyInventory([ok()])
    runner, _ = make_runner(controller, make_inventory)
    runner.run(max_iterations=2)
    assert [c[0] for c in controller.calls] == ["inventory", "inventory", "heartbeat"]


def test_backoff_is_capped_and_jittered(make_inventory):
    runner, _ = make_runner(FakeController([]), make_inventory)
    assert runner.backoff_delay(50) == AgentRunner.MAX_BACKOFF_SECONDS
    low = AgentRunner(
        FakeController([]),
        inventory_source=make_inventory,
        telemetry_source=telemetry,
        rng=lambda: 0.0,
    )
    assert low.backoff_delay(50) == AgentRunner.MAX_BACKOFF_SECONDS / 2


def test_hardware_change_is_detected_on_refresh(make_inventory):
    now = [0.0]
    inventories = iter([make_inventory(16), make_inventory(32)])
    controller = FakeController([ok(), ok()])

    def wait(_delay):
        now[0] += AgentRunner.INVENTORY_REFRESH_SECONDS
        return False

    runner = AgentRunner(
        controller,
        inventory_source=lambda: next(inventories),
        telemetry_source=telemetry,
        wait=wait,
        monotonic=lambda: now[0],
    )
    runner.run(max_iterations=2)
    assert ("inventory", 32 * 2**30) in controller.calls


def test_unexpected_errors_do_not_kill_the_agent(make_inventory):
    calls = iter([RuntimeError("psutil exploded"), telemetry()])

    def flaky_telemetry():
        item = next(calls)
        if isinstance(item, Exception):
            raise item
        return item

    controller = FakeController([ok()])
    runner = AgentRunner(
        controller,
        inventory_source=make_inventory,
        telemetry_source=flaky_telemetry,
        wait=lambda _d: False,
        rng=lambda: 1.0,
    )
    assert runner.run(max_iterations=2) is ExitReason.MAX_ITERATIONS
    assert runner.consecutive_failures == 0


def test_stop_event_ends_loop(make_inventory):
    runner = AgentRunner(
        FakeController([ok()]),
        inventory_source=make_inventory,
        telemetry_source=telemetry,
        wait=lambda _d: True,
    )
    assert runner.run() is ExitReason.STOPPED


@pytest.mark.parametrize(("given", "expected"), [(1, 5.0), (15, 15.0), (10_000, 300.0)])
def test_interval_clamping(given, expected):
    assert clamp_interval(given) == expected
