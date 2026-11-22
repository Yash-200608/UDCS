"""Application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import datetime

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

API_PREFIX = "/api/v1"


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
    app.state.login_limiter = RateLimiter(settings.login_attempts_per_minute, 60)
    app.state.enroll_limiter = RateLimiter(settings.enroll_attempts_per_minute, 60)

    app.middleware("http")(request_context_middleware)

    for router in (
        auth_router,
        nodes_router,
        agent_router,
        audit_router,
        jobs_router,
        job_agent_router,
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
