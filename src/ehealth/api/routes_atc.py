# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""The patient's audit trail as FHIR ``AuditEvent`` resources (CH:ATC).

EPDV art. 17 gives every patient the right to see who accessed their record.
``GET /v1/audit/me`` already answers that in this system's own JSON; this
answers it in the shape the CH:ATC profile defines, so a patient portal built
for the EPD — or another community's portal showing this patient's trail —
can read it without a custom adapter:

    GET /v1/fhir/AuditEvent?patient.identifier=urn:oid:…|…[&date=ge…][&date=le…]

Only the patient may ask about their own trail; the query parameter must name
the caller. Every event comes from the signed ledger, and the ledger's own
sequence number and entry hash travel with it, so a portal can cross-check an
event against ``/v1/audit/verify``.

**Event type codes.** Document events use the CH:ATC event types
(``ATC_DOC_CREATE``, ``ATC_DOC_READ``, ``ATC_DOC_UPDATE``, ``ATC_DOC_DELETE``,
``ATC_DOC_SEARCH``). Events that have no CH:ATC code — medication, consent,
grants, logins — use this system's own action name under a local code
system, rather than being forced onto a code that means something else. The
value set is revised with the CH EPR guide; check it before the Projectathon.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time
from typing import Annotated, Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from ehealth.api.deps import AuditTrailReaderDep, ContainerDep, DbDep
from ehealth.api.routes_fhir import FHIR_JSON, operation_outcome
from ehealth.db import utcnow
from ehealth.models.audit import AuditAction, AuditEvent
from ehealth.services.patient_directory import OID_URN, DirectoryError

router = APIRouter(prefix="/fhir", tags=["fhir"])

#: CH:ATC event type code system (eHealth Suisse).
ATC_SYSTEM = f"{OID_URN}2.16.756.5.30.1.127.3.10.7"
#: This system's own action names, for events CH:ATC has no code for.
LOCAL_SYSTEM = "urn:ch:ehealth:swiss-ehealth:audit-action"
DICOM_EVENT_TYPE = "http://dicom.nema.org/resources/ontology/DCM"

ATC_CODES: dict[AuditAction, str] = {
    AuditAction.DOCUMENT_ADDED: "ATC_DOC_CREATE",
    AuditAction.DOCUMENT_READ: "ATC_DOC_READ",
    AuditAction.DOCUMENT_UPDATED: "ATC_DOC_UPDATE",
    AuditAction.DOCUMENT_RETRACTED: "ATC_DOC_DELETE",
    AuditAction.DOSSIER_READ: "ATC_DOC_SEARCH",
}

#: FHIR AuditEvent.action: Create, Read, Update, Delete, Execute.
_CRUD = {
    "added": "C",
    "opened": "C",
    "recorded": "C",
    "issued": "C",
    "registered": "C",
    "read": "R",
    "searched": "E",
    "cross_referenced": "E",
    "updated": "U",
    "stopped": "U",
    "retracted": "D",
    "closed": "U",
    "withdrawn": "U",
    "revoked": "U",
}

#: FHIR AuditEvent.outcome: 0 success, 4 minor failure (refused), 8 serious.
_OUTCOME = {"success": "0", "denied": "4", "error": "8"}


def _fhir(body: dict[str, Any], status: int = 200) -> JSONResponse:
    return JSONResponse(body, status_code=status, media_type=FHIR_JSON)


def _date_bounds(values: list[str]) -> tuple[datetime | None, datetime | None]:
    """``ge``/``gt``/``le``/``lt`` prefixed dates (FHIR date search)."""
    lower = upper = None
    for raw in values:
        prefix, value = raw[:2], raw[2:]
        if prefix not in {"ge", "gt", "le", "lt"}:
            prefix, value = "eq", raw
        try:
            day = date.fromisoformat(value[:10])
        except ValueError as exc:
            raise DirectoryError(400, "code-invalid", f"bad date {raw!r}") from exc
        start = datetime.combine(day, time.min, tzinfo=UTC)
        end = datetime.combine(day, time.max, tzinfo=UTC)
        if prefix in {"ge", "gt", "eq"}:
            lower = start if prefix != "gt" else end
        if prefix in {"le", "lt", "eq"}:
            upper = end if prefix != "lt" else start
    return lower, upper


def audit_event_resource(event: AuditEvent, *, patient_reference: str) -> dict:
    action = AuditAction(event.action)
    verb = event.action.rpartition(".")[2]
    atc = ATC_CODES.get(action)
    subtype = (
        {"system": ATC_SYSTEM, "code": atc}
        if atc
        else {"system": LOCAL_SYSTEM, "code": event.action}
    )
    agent: dict[str, Any] = {
        "requestor": True,
        "who": {
            "identifier": {"value": event.actor_uid or event.actor_kind},
        },
        "type": {"text": event.actor_kind},
    }
    if event.purpose:
        agent["purposeOfUse"] = [{"text": event.purpose}]
    agents = [agent]
    if event.on_behalf_of_uid:
        agents.append(
            {
                "requestor": False,
                "who": {"identifier": {"value": event.on_behalf_of_uid}},
                "type": {"text": "on-behalf-of"},
            }
        )
    entities: list[dict[str, Any]] = [
        {
            "what": {"reference": patient_reference},
            "type": {"code": "1", "display": "Person"},
        }
    ]
    if event.resource_uid and event.resource_type != "dossier":
        entities.append(
            {
                "what": {"identifier": {"value": event.resource_uid}},
                "name": event.resource_type,
            }
        )
    return {
        "resourceType": "AuditEvent",
        "id": event.uid,
        "type": {
            "system": DICOM_EVENT_TYPE,
            "code": "110110",
            "display": "Patient Record",
        },
        "subtype": [subtype],
        "action": _CRUD.get(verb, "E"),
        "recorded": event.occurred_at.isoformat(),
        "outcome": _OUTCOME.get(event.outcome, "8"),
        "agent": agents,
        "source": {"observer": {"display": "swiss-ehealth"}},
        "entity": entities,
        # The ledger position and hash, so a portal can cross-check this
        # event against the signed chain.
        "meta": {
            "tag": [
                {
                    "system": "urn:ch:ehealth:swiss-ehealth:ledger-seq",
                    "code": str(event.seq),
                },
                {
                    "system": "urn:ch:ehealth:swiss-ehealth:ledger-hash",
                    "code": event.entry_hash,
                },
            ]
        },
    }


@router.get("/AuditEvent")
def patient_audit_trail(
    request: Request,
    db: DbDep,
    container: ContainerDep,
    reader: AuditTrailReaderDep,
    patient_identifier: Annotated[
        str, Query(alias="patient.identifier", max_length=200)
    ],
    date_: Annotated[list[str] | None, Query(alias="date")] = None,
    count: Annotated[int, Query(alias="_count", ge=1, le=500)] = 100,
):
    if not reader.may_read_audit:
        return operation_outcome(
            DirectoryError(403, "forbidden", "audit:read is required")
        )
    try:
        patient = container.directory.resolve(db, patient_identifier)
        lower, upper = _date_bounds(date_ or [])
    except DirectoryError as error:
        return operation_outcome(error)
    if patient is None or patient.uid != reader.subject_uid:
        # Only your own trail. "Somebody else" and "nobody" answer alike.
        return operation_outcome(
            DirectoryError(403, "forbidden", "only the patient may read this trail")
        )
    dossier = container.dossiers.for_patient(db, patient.uid)
    events: list[AuditEvent] = []
    if dossier is not None:
        stmt = select(AuditEvent).where(AuditEvent.dossier_uid == dossier.uid)
        if lower is not None:
            stmt = stmt.where(AuditEvent.occurred_at >= lower)
        if upper is not None:
            stmt = stmt.where(AuditEvent.occurred_at <= upper)
        events = list(
            db.execute(stmt.order_by(AuditEvent.seq.desc()).limit(count)).scalars()
        )
    base = f"{str(request.base_url).rstrip('/')}/v1/fhir"
    reference = f"Patient/{patient.uid}"
    return _fhir(
        {
            "resourceType": "Bundle",
            "type": "searchset",
            "timestamp": utcnow().isoformat(),
            "total": len(events),
            "entry": [
                {
                    "fullUrl": f"{base}/AuditEvent/{event.uid}",
                    "resource": audit_event_resource(
                        event, patient_reference=reference
                    ),
                    "search": {"mode": "match"},
                }
                for event in events
            ],
        }
    )
