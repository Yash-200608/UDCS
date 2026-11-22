"""The agent's main loop: inventory sync + heartbeats, with resilient back-off."""

from __future__ import annotations

import logging
import random
import threading
import time
from collections.abc import Callable
from enum import Enum
from typing import Protocol

from udcs_agent.communication.client import (
    ControllerUnavailable,
    CredentialRejected,
    ProtocolError,
)
from udcs_shared.agent_api import (
    MAX_HEARTBEAT_SECONDS,
    MIN_HEARTBEAT_SECONDS,
    PROTOCOL_VERSION,
    HeartbeatRequest,
    HeartbeatResponse,
)
from udcs_shared.hardware import HardwareInventory
from udcs_shared.telemetry import TelemetrySnapshot

logger = logging.getLogger(__name__)


class Controller(Protocol):
    def heartbeat(self, request: HeartbeatRequest) -> HeartbeatResponse: ...
    def put_inventory(self, inventory: HardwareInventory) -> None: ...


class ExitReason(Enum):
    STOPPED = "stopped"
    CREDENTIAL_REJECTED = "credential_rejected"
    MAX_ITERATIONS = "max_iterations"


def clamp_interval(seconds: float) -> float:
    return float(min(MAX_HEARTBEAT_SECONDS, max(MIN_HEARTBEAT_SECONDS, seconds)))


class AgentRunner:
    INVENTORY_REFRESH_SECONDS = 600.0
    MAX_BACKOFF_SECONDS = 300.0

    def __init__(
        self,
        controller: Controller,
        *,
        inventory_source: Callable[[], HardwareInventory],
        telemetry_source: Callable[[], TelemetrySnapshot],
        initial_interval_seconds: float = 15.0,
        stop_event: threading.Event | None = None,
        wait: Callable[[float], bool] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        rng: Callable[[], float] = random.random,
        on_response: Callable[[HeartbeatResponse], None] | None = None,
        after_heartbeat: Callable[[HeartbeatResponse], None] | None = None,
    ) -> None:
        self._controller = controller
        self._inventory_source = inventory_source
        self._telemetry_source = telemetry_source
        self._interval = clamp_interval(initial_interval_seconds)
        self.stop_event = stop_event or threading.Event()
        self._wait = wait or self.stop_event.wait  # returns True when stopped
        self._monotonic = monotonic
        self._rng = rng
        self._on_response = on_response
        # e.g. job sync. Runs in this loop, so a controller outage backs it off too.
        self._after_heartbeat = after_heartbeat
        self.consecutive_failures = 0

    def backoff_delay(self, failures: int) -> float:
        """Exponential back-off with jitter in [50%, 100%] of the capped delay."""
        ceiling = min(self.MAX_BACKOFF_SECONDS, self._interval * 2 ** min(failures - 1, 16))
        return ceiling * (0.5 + 0.5 * self._rng())

    def run(self, *, max_iterations: int | None = None) -> ExitReason:
        inventory = self._inventory_source()
        fingerprint = inventory.fingerprint()
        inventory_pending = True
        last_refresh = self._monotonic()
        iterations = 0

        while not self.stop_event.is_set():
            if self._monotonic() - last_refresh >= self.INVENTORY_REFRESH_SECONDS:
                last_refresh = self._monotonic()
                refreshed = self._inventory_source()
                if refreshed.fingerprint() != fingerprint:
                    logger.info("hardware inventory changed")
                    inventory, fingerprint, inventory_pending = (
                        refreshed,
                        refreshed.fingerprint(),
                        True,
                    )

            try:
                if inventory_pending:
                    self._controller.put_inventory(inventory)
                    inventory_pending = False
                    logger.info("inventory sent", extra={"gpus": len(inventory.gpus)})
                response = self._controller.heartbeat(
                    HeartbeatRequest(
                        protocol_version=PROTOCOL_VERSION,
                        telemetry=self._telemetry_source(),
                        inventory_fingerprint=fingerprint,
                    )
                )
                if self._on_response is not None:
                    self._on_response(response)
                if self._after_heartbeat is not None:
                    self._after_heartbeat(response)
                self._interval = clamp_interval(response.heartbeat_interval_seconds)
                inventory_pending = response.inventory_required
                if self.consecutive_failures:
                    logger.info(
                        "controller reachable again",
                        extra={"after_failures": self.consecutive_failures},
                    )
                self.consecutive_failures = 0
                # Resend inventory promptly if asked, but never hot-loop.
                delay = 1.0 if inventory_pending else self._interval
            except CredentialRejected as exc:
                logger.error("controller rejected node credential; stopping: %s", exc)
                return ExitReason.CREDENTIAL_REJECTED
            except (ControllerUnavailable, ProtocolError) as exc:
                self.consecutive_failures += 1
                delay = self.backoff_delay(self.consecutive_failures)
                logger.warning(
                    "heartbeat failed: %s",
                    exc,
                    extra={"failures": self.consecutive_failures, "retry_in_s": round(delay, 1)},
                )
            except Exception:
                self.consecutive_failures += 1
                delay = self.backoff_delay(self.consecutive_failures)
                logger.exception("unexpected error in agent loop")

            iterations += 1
            if max_iterations is not None and iterations >= max_iterations:
                return ExitReason.MAX_ITERATIONS
            if self._wait(delay):
                break
        return ExitReason.STOPPED
