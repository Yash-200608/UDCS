"""A thin, typed wrapper over the controller API. The httpx client is injected, so
tests drive the real controller in-process and production uses TLS (session.py)."""

from __future__ import annotations

from typing import Any

import httpx

from udcs_client.output import ClientError, Exit, clip, sanitize
from udcs_shared.packages import OutputManifest, PackageManifest, PackagePolicy

USER_CODE_DISABLED = "user code execution is disabled on this deployment"


class Api:
    def __init__(self, http: httpx.Client, *, token: str | None = None) -> None:
        self.http = http
        self.token = token

    # -- plumbing --------------------------------------------------------------------------

    def _detail(self, response: httpx.Response) -> str:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        return clip(sanitize(str(detail), secrets=(self.token or "",)), 200)

    def _call(self, method: str, path: str, *, auth: bool = True, **kwargs) -> httpx.Response:
        try:
            response = self.http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise ClientError(
                f"cannot reach the controller: {type(exc).__name__}", transient=True
            ) from None
        if 300 <= response.status_code < 400:
            # Redirects are never followed: a token must not travel to another origin.
            raise ClientError(f"unexpected redirect ({response.status_code}) from the controller")
        if response.status_code == 401 and auth:
            raise ClientError("not logged in, or the session expired: run `udcs login`")
        if response.status_code >= 500:
            raise ClientError(
                f"{method} {path}: the controller failed (HTTP {response.status_code}): "
                f"{self._detail(response)}",
                transient=True,
            )
        return response

    def _json(self, method: str, path: str, *, ok: tuple[int, ...] = (200,), **kwargs) -> Any:
        response = self._call(method, path, **kwargs)
        if response.status_code not in ok:
            raise ClientError(
                f"{method} {path}: HTTP {response.status_code}: {self._detail(response)}"
            )
        return response.json() if response.content else None

    # -- auth ------------------------------------------------------------------------------

    def login(self, username: str, password: str) -> dict:
        response = self._call(
            "POST", "/auth/login", auth=False, json={"username": username, "password": password}
        )
        if response.status_code != 200:
            raise ClientError(f"login failed: {self._detail(response)}")
        return response.json()

    def logout(self) -> bool:
        """True if the server confirmed the token is no longer valid (revoked now, or
        already expired: 204 or 401). False if that could not be confirmed."""
        try:
            response = self._call("POST", "/auth/logout", auth=False)
        except ClientError:
            return False
        return response.status_code in (200, 204, 401)

    def me(self) -> dict:
        return self._json("GET", "/auth/me")

    # -- deployment, policy, catalogue ------------------------------------------------------

    def deployment(self) -> dict:
        return self._json("GET", "/deployment")

    def policy(self) -> PackagePolicy:
        return PackagePolicy.model_validate(self._json("GET", "/packages/policy"))

    def list_packages(self, kind: str) -> list[dict]:
        items: list[dict] = []
        offset = 0
        while True:
            page = self._json(
                "GET", "/packages", params={"kind": kind, "limit": 200, "offset": offset}
            )
            items += page["items"]
            offset += len(page["items"])
            if not page["items"] or offset >= page["total"] or offset >= 10_000:
                return items

    def package(self, digest: str) -> dict | None:
        response = self._call("GET", f"/packages/{digest}")
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise ClientError(f"GET package: HTTP {response.status_code}: {self._detail(response)}")
        return response.json()

    def register(self, manifest: PackageManifest) -> dict:
        response = self._call("POST", "/packages", json=manifest.model_dump(mode="json"))
        if response.status_code == 422:
            raise ClientError(
                f"the controller refused the package: {self._detail(response)}", Exit.INVALID
            )
        if response.status_code != 201:
            raise ClientError(f"register: HTTP {response.status_code}: {self._detail(response)}")
        return response.json()

    # -- jobs ------------------------------------------------------------------------------

    def submit(self, body: dict) -> dict:
        response = self._call("POST", "/jobs", json=body)
        if response.status_code == 403 and USER_CODE_DISABLED in response.text:
            raise ClientError(USER_CODE_DISABLED, Exit.DISABLED)
        if response.status_code != 201:
            raise ClientError(f"submit: HTTP {response.status_code}: {self._detail(response)}")
        return response.json()

    def job(self, job_id: str) -> dict:
        response = self._call("GET", f"/jobs/{job_id}")
        if response.status_code == 404:
            raise ClientError(f"job {sanitize(job_id)} not found", Exit.USAGE)
        if response.status_code != 200:
            raise ClientError(f"job: HTTP {response.status_code}: {self._detail(response)}")
        return response.json()

    def jobs(self, *, state: str | None = None, limit: int = 50) -> list[dict]:
        params: dict[str, Any] = {"limit": limit}
        if state:
            params["state"] = state
        return self._json("GET", "/jobs", params=params)

    def logs(self, job_id: str, *, after: int | None = None, limit: int = 500) -> list[dict]:
        params: dict[str, Any] = {"limit": limit}
        if after is not None:
            params["after"] = after
        return self._json("GET", f"/jobs/{job_id}/logs", params=params)

    def cancel(self, job_id: str) -> dict:
        return self._json("POST", f"/jobs/{job_id}/cancel")

    def result(self, job_id: str) -> dict:
        return self._json("GET", f"/jobs/{job_id}/result")

    def outputs(self, job_id: str) -> OutputManifest | None:
        body = self._json("GET", f"/jobs/{job_id}/outputs")
        raw = body.get("outputs") if isinstance(body, dict) else None
        if raw is None:
            return None
        try:
            return OutputManifest.model_validate(raw)
        except ValueError as exc:
            raise ClientError(
                "the controller sent an unsafe or malformed output manifest: "
                f"{sanitize(exc)[:300]}",
                Exit.VERIFICATION,
            ) from None
