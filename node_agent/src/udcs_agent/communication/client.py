"""HTTPS client for the controller's agent API.

Every failure is mapped to one of three outcomes the runner acts on:
- CredentialRejected  -> stop (revoked / bad credential), never retry blindly
- ControllerUnavailable -> back off and retry (network, TLS, 429, 5xx)
- ProtocolError       -> back off and retry, but it indicates a bug or version skew
"""

from __future__ import annotations

import ssl
import uuid
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from udcs_agent import __version__
from udcs_agent.config import AgentConfig
from udcs_shared.agent_api import (
    PROTOCOL_VERSION,
    EnrollRequest,
    EnrollResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    InventoryUpdate,
    RotateCredentialResponse,
)
from udcs_shared.hardware import HardwareInventory

ModelT = TypeVar("ModelT", bound=BaseModel)


class AgentError(Exception):
    pass


class ControllerUnavailable(AgentError):
    pass


class CredentialRejected(AgentError):
    pass


class EnrollmentRejected(AgentError):
    pass


class ProtocolError(AgentError):
    pass


def _ssl_context(config: AgentConfig) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(config.ca_bundle) if config.ca_bundle else None)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class ControllerClient:
    def __init__(
        self,
        config: AgentConfig,
        *,
        credential: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._credential = credential
        self._http = httpx.Client(
            base_url=f"{config.controller_url}/api/v1",
            verify=_ssl_context(config),
            timeout=config.request_timeout_seconds,
            transport=transport,
            follow_redirects=False,
            headers={"User-Agent": f"udcs-agent/{__version__}"},
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ControllerClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- public API -------------------------------------------------------

    def enroll(
        self, enrollment_token: str, inventory: HardwareInventory, requested_name: str | None
    ) -> EnrollResponse:
        body = EnrollRequest(
            enrollment_token=enrollment_token,
            protocol_version=PROTOCOL_VERSION,
            inventory=inventory,
            requested_name=requested_name,
        )
        response = self._send("POST", "/agent/enroll", body, authenticated=False)
        return self._parse(response, EnrollResponse)

    def heartbeat(self, request: HeartbeatRequest) -> HeartbeatResponse:
        return self._parse(self._send("POST", "/agent/heartbeat", request), HeartbeatResponse)

    def put_inventory(self, inventory: HardwareInventory) -> None:
        self._send("PUT", "/agent/inventory", InventoryUpdate(inventory=inventory))

    def rotate_credential(self) -> str:
        """Ask for a new credential. The old one stays valid until the new one is used."""
        response = (
            self._http.request(
                "POST",
                "/agent/credential/rotate",
                headers={
                    "Authorization": f"Bearer {self._credential}",
                    "X-Request-ID": f"agent-{uuid.uuid4().hex}",
                },
            )
            if self._credential
            else None
        )
        if response is None:
            raise CredentialRejected("agent has no node credential")
        self._raise_for_status(response, enrolling=False)
        return self._parse(response, RotateCredentialResponse).node_credential

    def set_credential(self, credential: str) -> None:
        self._credential = credential

    # -- internals --------------------------------------------------------

    def _send(
        self, method: str, path: str, body: BaseModel, *, authenticated: bool = True
    ) -> httpx.Response:
        headers = {"X-Request-ID": f"agent-{uuid.uuid4().hex}"}
        if authenticated:
            if not self._credential:
                raise CredentialRejected("agent has no node credential")
            headers["Authorization"] = f"Bearer {self._credential}"
        try:
            response = self._http.request(
                method, path, json=body.model_dump(mode="json"), headers=headers
            )
        except httpx.TimeoutException as exc:
            raise ControllerUnavailable(f"request to controller timed out ({exc})") from exc
        except httpx.TransportError as exc:  # DNS, refused, TLS verification failure, ...
            raise ControllerUnavailable(f"cannot reach controller ({exc})") from exc
        self._raise_for_status(response, enrolling=not authenticated)
        return response

    @staticmethod
    def _detail(response: httpx.Response) -> str:
        try:
            detail = response.json().get("detail")
        except ValueError:
            detail = None
        return str(detail) if detail else response.text[:200]

    def _raise_for_status(self, response: httpx.Response, *, enrolling: bool) -> None:
        status = response.status_code
        if 200 <= status < 300:
            return
        detail = self._detail(response)
        if status in (401, 403):
            raise (EnrollmentRejected if enrolling else CredentialRejected)(
                f"HTTP {status}: {detail}"
            )
        if status == 429 or status >= 500:
            raise ControllerUnavailable(f"HTTP {status}: {detail}")
        raise ProtocolError(f"HTTP {status}: {detail}")

    @staticmethod
    def _parse(response: httpx.Response, model: type[ModelT]) -> ModelT:
        try:
            return model.model_validate_json(response.content)
        except ValidationError as exc:
            raise ProtocolError(f"unexpected response from controller: {exc}") from exc
