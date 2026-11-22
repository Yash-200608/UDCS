"""Correlation ids, access logging and common request helpers."""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Annotated

from fastapi import Depends, Request, Response

from udcs_shared.logs import request_id_var

logger = logging.getLogger("udcs.controller.access")

_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


async def request_context_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    incoming = request.headers.get("x-request-id")
    request_id = incoming if incoming and _VALID_REQUEST_ID.match(incoming) else uuid.uuid4().hex
    token = request_id_var.set(request_id)
    started = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        response.headers["X-Request-ID"] = request_id
        return response
    finally:
        logger.info(
            "request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": status,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "client_ip": client_ip(request),
            },
        )
        request_id_var.reset(token)


def client_ip(request: Request) -> str | None:
    """TCP peer address. Behind a reverse proxy this is the proxy (known limitation)."""
    return request.client.host if request.client else None


def get_now(request: Request) -> datetime:
    """The app's clock (injectable for tests); always timezone-aware UTC."""
    return request.app.state.clock()


Now = Annotated[datetime, Depends(get_now)]
