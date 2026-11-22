"""Application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from udcs_controller import __version__
from udcs_controller.audit.router import router as audit_router
from udcs_controller.auth.router import router as auth_router
from udcs_controller.config import Settings
from udcs_controller.core.ratelimit import RateLimiter
from udcs_controller.core.request_context import request_context_middleware
from udcs_controller.database.base import utcnow
from udcs_controller.database.session import create_db_engine, make_sessionmaker
from udcs_controller.jobs.agent_router import router as job_agent_router
from udcs_controller.jobs.router import router as jobs_router
from udcs_controller.nodes.agent_router import router as agent_router
from udcs_controller.nodes.router import router as nodes_router
from udcs_controller.packages.router import agent_router as package_agent_router
from udcs_controller.packages.router import router as packages_router
from udcs_controller.packages.service import BlobStore

API_PREFIX = "/api/v1"
_JSON_BODY_FLOOR = 4 * 2**20  # checkpoints (1 MiB as base64) and output manifests fit
_CHUNK_PATHS = (f"{API_PREFIX}/blobs/uploads/", f"{API_PREFIX}/agent/blobs/uploads/")


class _BodyTooLarge(Exception):
    pass


class BodyLimitMiddleware:
    """Refuse oversized request bodies before they are buffered. FastAPI reads a whole
    body into memory before any handler or dependency runs, so the bound has to sit
    here: the declared Content-Length is checked first, and bytes are counted as they
    arrive (which also covers chunked transfer encoding without a length)."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        policy = scope["app"].state.settings.package_policy
        if scope["method"] == "PUT" and scope["path"].startswith(_CHUNK_PATHS):
            limit = policy.chunk_bytes
        else:
            limit = max(_JSON_BODY_FLOOR, policy.max_manifest_bytes)
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and (not declared.isdigit() or int(declared) > limit):
            await self._refuse(send, limit)
            return
        seen = 0
        started = False

        async def counted():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    raise _BodyTooLarge
            return message

        async def tracked(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counted, tracked)
        except _BodyTooLarge:
            if not started:
                await self._refuse(send, limit)

    @staticmethod
    async def _refuse(send, limit: int) -> None:
        body = f'{{"detail":"request body larger than {limit} bytes"}}'.encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def create_app(
    settings: Settings | None = None, *, clock: Callable[[], datetime] | None = None
) -> FastAPI:
    settings = settings or Settings()  # type: ignore[call-arg]  # values come from env
    engine = create_db_engine(settings.database_url)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(title="UDCS Controller", version=__version__, lifespan=lifespan)
    app.state.settings = settings
    app.state.engine = engine
    app.state.sessionmaker = make_sessionmaker(engine)
    app.state.clock = clock or utcnow
    # Leases are not reaped during the first lease period after start (controller restart).
    app.state.started_at = app.state.clock()
    app.state.blob_store = BlobStore(Path(settings.blob_dir))
    app.state.login_limiter = RateLimiter(settings.login_attempts_per_minute, 60)
    app.state.enroll_limiter = RateLimiter(settings.enroll_attempts_per_minute, 60)

    app.middleware("http")(request_context_middleware)
    app.add_middleware(BodyLimitMiddleware)

    for router in (
        auth_router,
        nodes_router,
        agent_router,
        audit_router,
        jobs_router,
        job_agent_router,
        packages_router,
        package_agent_router,
    ):
        app.include_router(router, prefix=API_PREFIX)

    @app.get("/healthz", tags=["health"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", tags=["health"])
    def readyz() -> JSONResponse:
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError:
            return JSONResponse({"status": "database unavailable"}, status_code=503)
        return JSONResponse({"status": "ready"})

    return app
