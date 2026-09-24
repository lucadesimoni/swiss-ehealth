# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""IUA Authorization Server endpoints (CH EPR FHIR v5.0.0).

* ``GET  /iua/authorize`` — ITI-71 authorisation request (code flow).
* ``POST /iua/token`` — ITI-71 token request; signed per RFC 9421.
* ``GET  /iua/jwks.json`` — the key IUA tokens are signed with.
* ``GET  /fhir/.well-known/smart-configuration`` — ITI-103 metadata, at the
  FHIR base the guide points clients to.

See :mod:`ehealth.services.iua` for what each check is and why.
"""

from __future__ import annotations

from typing import Annotated
from urllib.parse import parse_qsl

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, RedirectResponse

from ehealth.api.deps import ContainerDep, DbDep, RequestContextDep
from ehealth.services.auth import AuthError
from ehealth.services.iua import IuaError, TokenRequest
from ehealth.version import API_VERSION

router = APIRouter(tags=["iua"])

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _error(error: IuaError) -> JSONResponse:
    # Only the OAuth error code goes out; the reason is in the audit trail.
    headers = dict(_NO_STORE)
    if error.status == 401:
        headers["WWW-Authenticate"] = f'Bearer error="{error.error}"'
    return JSONResponse({"error": error.error}, error.status, headers=headers)


def _single_valued(pairs: list[tuple[str, str]]) -> dict[str, str]:
    """RFC 6749 §3.1: parameters must not be repeated. A repeated one is how
    a parameter-pollution attack gets two components to read two values."""
    out: dict[str, str] = {}
    for name, value in pairs:
        if name in out:
            raise IuaError(400, "invalid_request", f"parameter {name} is repeated")
        out[name] = value
    return out


def _api_base(request: Request) -> str:
    return f"{str(request.base_url).rstrip('/')}/{API_VERSION}"


@router.get("/iua/authorize")
def authorize(
    request: Request,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
    authorization: Annotated[str | None, Header()] = None,
):
    try:
        params = _single_valued(
            parse_qsl(request.url.query, keep_blank_values=True, strict_parsing=False)
        )
    except IuaError as error:
        return _error(error)
    # A user already signed in here (SwissID/HIN/AGOV plus a second factor)
    # is identified by that session. Otherwise the token request has to
    # bring the identity provider's ID token.
    person_uid = None
    if authorization and authorization[:7].lower() == "bearer ":
        try:
            claims, _ = container.auth.verify_session_token(
                db, authorization[7:].strip()
            )
        except AuthError:
            return _error(IuaError(401, "login_required", "session is not valid"))
        person_uid = claims.subject_uid
    try:
        location = container.iua.authorize(
            db, base, params, session_person_uid=person_uid
        )
    except IuaError as error:
        # Never redirect on an error here: the redirect_uri may be the thing
        # that failed validation.
        return _error(error)
    return RedirectResponse(location, status_code=302, headers=_NO_STORE)


@router.post("/iua/token")
async def token(
    request: Request,
    db: DbDep,
    container: ContainerDep,
    base: RequestContextDep,
):
    body = await request.body()
    content_type = request.headers.get("content-type", "").split(";")[0].strip()
    try:
        if content_type != "application/x-www-form-urlencoded":
            raise IuaError(400, "invalid_request", "body must be form-encoded")
        try:
            pairs = parse_qsl(
                body.decode("utf-8"), keep_blank_values=True, strict_parsing=True
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise IuaError(400, "invalid_request", "body is not a form") from exc
        form = _single_valued(pairs)
        result = container.iua.token(
            db,
            base,
            TokenRequest(
                method=request.method,
                target_uri=str(request.url),
                headers={k.lower(): v for k, v in request.headers.items()},
                body=body,
                form=form,
            ),
        )
    except IuaError as error:
        return _error(error)
    return JSONResponse(result, headers=_NO_STORE)


@router.get("/iua/jwks.json")
def jwks(container: ContainerDep):
    return JSONResponse(container.iua.jwks())


@router.get("/fhir/.well-known/smart-configuration")
def smart_configuration(request: Request, container: ContainerDep):
    return JSONResponse(container.iua.metadata(_api_base(request)))
