"""Application factory.

Hardening that belongs to the transport rather than the domain lives here:
security headers, a request id on every response, no server banner, and a
refusal to serve interactive API docs in production.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from ehealth.api import (
    routes_access,
    routes_audit,
    routes_auth,
    routes_dossier,
    routes_medication,
    routes_persons,
)
from ehealth.config import Environment, Settings, get_settings
from ehealth.container import Container, build_container, get_container
from ehealth.db import create_all, init_engine
from ehealth.domain.uid import new_uid
from ehealth.services.access import AccessError
from ehealth.services.auth import AuthError

logger = logging.getLogger("ehealth")

#: Sent on every response. ``default-src 'none'`` because this service returns
#: JSON — it has no reason to be able to load anything at all.
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cache-Control": "no-store",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def create_app(
    settings: Settings | None = None, container: Container | None = None
) -> FastAPI:
    """Build the app.

    Passing a pre-built ``container`` keeps the caller and the app on the same
    keyring — which matters because a second container would derive different
    keys and silently fail to verify the first one's tokens.
    """
    settings = settings or get_settings()
    production = settings.environment is Environment.PRODUCTION

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_engine(settings)
        if not production:
            # Production schema changes go through migrations, not create_all.
            create_all()
        app.state.container = container or (
            get_container() if settings is get_settings() else build_container(settings)
        )
        logger.info(
            "started",
            extra={"environment": settings.environment.value, "region": settings.data_region.value},
        )
        yield

    app = FastAPI(
        title="Swiss e-health patient dossier",
        version="0.1.0",
        summary=(
            "AHVN13-derived pseudonymous UIDs, capability tokens, "
            "tamper-evident change tracking"
        ),
        lifespan=lifespan,
        docs_url=None if production else "/docs",
        redoc_url=None,
        openapi_url=None if production else "/openapi.json",
    )

    @app.middleware("http")
    async def harden(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get("x-request-id") or new_uid("req")
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        response.headers["X-Request-Id"] = request_id
        return response

    @app.exception_handler(AccessError)
    async def _access_denied(_: Request, exc: AccessError) -> JSONResponse:
        # The ledger holds the reason; the caller gets a bare refusal.
        return JSONResponse(status_code=403, content={"detail": "access denied"})

    @app.exception_handler(AuthError)
    async def _auth_failed(_: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(
            status_code=401,
            content={"detail": "authentication failed"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.get("/health", tags=["operations"])
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "environment": settings.environment.value,
            "data_region": settings.data_region.value,
        }

    if container is not None:
        # Keep dependency resolution on the injected container too.
        from ehealth.api.deps import container_dep

        app.dependency_overrides[container_dep] = lambda: container

    for router in (
        routes_auth.router,
        routes_persons.router,
        routes_access.router,
        routes_dossier.router,
        routes_medication.router,
        routes_audit.router,
    ):
        app.include_router(router)

    return app


app = create_app()
