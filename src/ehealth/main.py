# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
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
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ehealth.api import (
    routes_access,
    routes_audit,
    routes_auth,
    routes_dossier,
    routes_fhir,
    routes_medication,
    routes_mhd,
    routes_offline,
    routes_persons,
)
from ehealth.config import Environment, Settings, get_settings
from ehealth.container import Container, build_container, get_container
from ehealth.db import create_all, init_engine
from ehealth.domain.uid import new_uid
from ehealth.schema import require_matching_schema
from ehealth.services.access import AccessError
from ehealth.services.auth import AuthError
from ehealth.version import API_VERSION

logger = logging.getLogger("ehealth")

#: RFC 9457 problem types, resolved against the issuer so they are real URLs a
#: partner can look up rather than opaque strings.
_PROBLEM_TYPES = {
    400: "bad-request",
    401: "authentication-failed",
    403: "access-denied",
    404: "not-found",
    409: "conflict",
    413: "payload-too-large",
    422: "validation-failed",
    429: "rate-limited",
    500: "internal-error",
}
_PROBLEM_TITLES = {
    400: "Bad request",
    401: "Authentication failed",
    403: "Access denied",
    404: "Not found",
    409: "Conflict",
    413: "Payload too large",
    422: "Request validation failed",
    429: "Too many requests",
    500: "Internal error",
}


def problem(
    request: Request,
    status_code: int,
    problem_type: str,
    title: str,
    *,
    detail: object = None,
    headers: dict[str, str] | None = None,
    extra: dict[str, object] | None = None,
) -> JSONResponse:
    """Build an RFC 9457 ``application/problem+json`` response."""
    body: dict[str, object] = {
        "type": f"https://docs.dossier.example.ch/problems/{problem_type}",
        "title": title,
        "status": status_code,
        "instance": str(request.url.path),
    }
    if detail is not None:
        body["detail"] = detail
    if extra:
        body.update(extra)
    return JSONResponse(
        status_code=status_code,
        content=body,
        media_type="application/problem+json",
        headers=headers,
    )


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
        engine = init_engine(settings)
        if not production:
            # Production schema changes go through migrations, not create_all.
            create_all()
        # Refuse to serve a database this build does not expect — in either
        # direction. Running old code against a newer schema can silently drop
        # data, and running new code against an older one fails mid-write.
        require_matching_schema(engine)
        app.state.container = container or (
            get_container() if settings is get_settings() else build_container(settings)
        )
        logger.info(
            "started",
            extra={
                "environment": settings.environment.value,
                "region": settings.data_region.value,
            },
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
    async def _access_denied(request: Request, exc: AccessError) -> JSONResponse:
        # The ledger holds the reason; the caller gets a bare refusal.
        return problem(request, 403, "access-denied", "Access denied")

    @app.exception_handler(AuthError)
    async def _auth_failed(request: Request, exc: AuthError) -> JSONResponse:
        return problem(
            request,
            401,
            "authentication-failed",
            "Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_problem(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        """Every error leaves as RFC 9457 problem details.

        Partners integrating against this need one error shape, not two — and
        a machine-readable ``type`` they can branch on without parsing prose.
        """
        return problem(
            request,
            exc.status_code,
            _PROBLEM_TYPES.get(exc.status_code, "error"),
            _PROBLEM_TITLES.get(exc.status_code, "Error"),
            detail=exc.detail,
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_problem(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return problem(
            request,
            422,
            "validation-failed",
            "Request validation failed",
            detail="one or more fields are invalid",
            extra={"errors": jsonable_encoder(exc.errors())},
        )

    @app.get("/health", tags=["operations"])
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "environment": settings.environment.value,
            "data_region": settings.data_region.value,
            "api_version": API_VERSION,
        }

    if container is not None:
        # Keep dependency resolution on the injected container too.
        from ehealth.api.deps import container_dep

        app.dependency_overrides[container_dep] = lambda: container

    # Every resource route lives under /v1. A partner integrating against this
    # needs to know that a URL they hard-code keeps meaning the same thing,
    # and that a breaking change arrives as /v2 rather than as a surprise.
    for router in (
        routes_auth.router,
        routes_persons.router,
        routes_access.router,
        routes_dossier.router,
        routes_medication.router,
        routes_offline.router,
        routes_audit.router,
        routes_fhir.router,
        routes_mhd.router,
    ):
        app.include_router(router, prefix=f"/{API_VERSION}")

    return app


app = create_app()
