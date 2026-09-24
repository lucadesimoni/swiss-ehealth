# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Request body size limits, enforced before any application code runs.

Without this, the body of a request is read in full before authentication is
checked — FastAPI resolves body parameters alongside dependencies — so an
anonymous client could send gigabytes to ``/v1/auth/callback`` and exhaust
the server's memory. The limit is checked twice: against ``Content-Length``
before reading anything, and again while the body streams in, because a
chunked request carries no length to check.

Two limits: a small one for everything, and a large one only for the routes
that carry documents.
"""

from __future__ import annotations

import json

#: JSON bodies for login, consent, grants, searches: far below this.
DEFAULT_LIMIT = 1 * 1024 * 1024

#: A 32 MiB document, base64-encoded (4/3) inside a JSON or FHIR envelope.
DOCUMENT_LIMIT = 48 * 1024 * 1024

#: (method, path prefix, path suffix) that may carry a document.
DOCUMENT_ROUTES = (
    ("POST", "/v1/fhir", ""),
    ("POST", "/v1/dossiers/", "/documents"),
)


class _TooLarge(Exception):
    pass


def limit_for(method: str, path: str) -> int:
    for route_method, prefix, suffix in DOCUMENT_ROUTES:
        if method != route_method:
            continue
        if suffix == "" and path.rstrip("/") == prefix:
            return DOCUMENT_LIMIT
        if suffix and path.startswith(prefix) and path.endswith(suffix):
            return DOCUMENT_LIMIT
    return DEFAULT_LIMIT


class BodySizeLimit:
    """Pure ASGI middleware, so it works on the raw stream."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = limit_for(scope["method"], scope["path"])
        headers = dict(scope.get("headers") or [])
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                too_big = True  # a length that is not a number is not honest
            if too_big:
                await _reject(send, limit)
                return

        received = 0
        exceeded = False
        replaced = False

        async def counted_receive():
            nonlocal received, exceeded
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # Stop reading here, whatever the application does with
                    # the exception: memory stays bounded by the limit.
                    exceeded = True
                    raise _TooLarge
            return message

        async def guarded_send(message):
            nonlocal replaced
            if exceeded:
                # The framework may have caught the exception and built its
                # own error (FastAPI answers a failed body read with 400).
                # The honest answer is 413, so that is what goes out.
                if not replaced:
                    replaced = True
                    await _reject(send, limit)
                return
            await send(message)

        try:
            await self.app(scope, counted_receive, guarded_send)
        except _TooLarge:
            if not replaced:
                await _reject(send, limit)


async def _reject(send, limit: int) -> None:
    body = json.dumps(
        {
            "type": "https://dossier.example.ch/problems/payload-too-large",
            "title": "Payload too large",
            "status": 413,
            "detail": f"request bodies on this route are limited to {limit} bytes",
        }
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/problem+json"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
