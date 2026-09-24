# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Patient identity lookups for other systems: IHE PIXm and PDQm.

Two questions another community's system asks before it can exchange a
document about a patient:

* **Cross-reference (PIXm, ITI-83):** "I know this patient as X in domain A;
  what are they in domain B?" — typically: given our local patient id, what
  is the EPR-SPID, or the reverse.
* **Demographic search (PDQm, ITI-78):** "Which patient has this identifier,
  or this family name and date of birth?"

This module answers both, framework-free; ``api/routes_fhir.py`` renders the
answers as FHIR. Error semantics follow the IHE PIXm/PDQm profiles as
constrained by the CH EPR FHIR implementation guide.

Deliberate restrictions, each a privacy decision rather than an omission:

* **Only professionals may ask**, and every question is recorded in the
  audit trail — who asked, which kind of query, how many matched. The search
  terms themselves are *not* recorded: the audit trail would otherwise become
  a searchable list of names and birthdays.
* **Only patients are found.** A person who is registered solely as a
  visitor or a professional is not in the patient directory.
* **A demographic search needs family name *and* date of birth.** It is a
  lookup of one person, not a way to list everyone called Müller. It runs on
  a blind index, so names stay encrypted at rest.
* **The AHVN13 is refused as an identifier domain.** EPDG art. 5 keeps the
  AHV number out of the patient record; accepting it here would turn this
  interface into exactly the join the law exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from sqlalchemy import select
from sqlalchemy.orm import Session

from ehealth.domain.identity import IdentityService, normalise_family_name
from ehealth.models.audit import AuditAction, AuditOutcome
from ehealth.models.core import Person, PersonRoleKind, PersonStatus
from ehealth.services.audit import ActorContext, AuditLedger
from ehealth.services.persons import PersonService

#: EPR-SPID assigning authority (eHealth Suisse). The national patient
#: identifier of the electronic patient record.
EPR_SPID_OID = "2.16.756.5.30.1.127.3.10.3"

#: AHVN13 assigning authority. Recognised only to be refused.
AHVN13_OID = "2.16.756.5.32"

OID_URN = "urn:oid:"

#: FHIR administrative gender codes.
FHIR_GENDERS = frozenset({"male", "female", "other", "unknown"})
_SEX_TO_GENDER = {
    "male": "male",
    "m": "male",
    "female": "female",
    "f": "female",
    "other": "other",
    "x": "other",
    "diverse": "other",
}


class DirectoryError(Exception):
    """A request the profile says must be answered with an OperationOutcome.

    ``status`` and ``code`` are the HTTP status and the FHIR issue type the
    IHE profile prescribes for the case, so the route layer does not have to
    re-derive them.
    """

    def __init__(self, status: int, code: str, diagnostics: str) -> None:
        super().__init__(diagnostics)
        self.status = status
        self.code = code
        self.diagnostics = diagnostics


@dataclass(frozen=True, slots=True)
class PatientRecord:
    """What the directory discloses about a patient. Nothing more."""

    uid: str
    spid: str | None
    family_name: str | None
    given_name: str | None
    birth_date: date | None
    gender: str
    active: bool


def strip_oid(system: str) -> str:
    """``urn:oid:1.2.3`` -> ``1.2.3``. Anything else is not an OID system."""
    if not system.startswith(OID_URN) or len(system) == len(OID_URN):
        raise DirectoryError(
            400, "code-invalid", f"identifier system must be urn:oid:…, got {system!r}"
        )
    return system[len(OID_URN) :]


def parse_token(token: str) -> tuple[str, str]:
    """A FHIR ``system|value`` identifier token -> (oid, value)."""
    system, separator, value = token.partition("|")
    if not separator or not value:
        raise DirectoryError(
            400, "code-invalid", "identifier must be given as urn:oid:<oid>|<value>"
        )
    return strip_oid(system), value


def fhir_gender(administrative_sex: str | None) -> str:
    if not administrative_sex:
        return "unknown"
    return _SEX_TO_GENDER.get(administrative_sex.strip().casefold(), "unknown")


class PatientDirectory:
    def __init__(
        self,
        persons: PersonService,
        identity: IdentityService,
        ledger: AuditLedger,
        *,
        community_oid: str,
        max_results: int = 10,
    ) -> None:
        self._persons = persons
        self._identity = identity
        self._ledger = ledger
        self._community_oid = community_oid
        self._max_results = max_results

    @property
    def community_oid(self) -> str:
        return self._community_oid

    @property
    def domains(self) -> tuple[str, ...]:
        """Identifier domains this directory can answer in."""
        return (EPR_SPID_OID, self._community_oid)

    # -- access ---------------------------------------------------------------

    def require_professional(self, session: Session, actor: ActorContext) -> None:
        """Patient lookups are for people treating patients."""
        if actor.actor_uid is None or not self._persons.has_role(
            session, actor.actor_uid, PersonRoleKind.HEALTHCARE_PROFESSIONAL
        ):
            self._ledger.append(
                session,
                actor=actor,
                action=AuditAction.ACCESS_DENIED,
                resource_type="patient_directory",
                outcome=AuditOutcome.DENIED,
                detail={"reason": "patient lookups require the professional role"},
            )
            raise DirectoryError(
                403,
                "forbidden",
                "patient lookups require the healthcare-professional role",
            )

    # -- resolution -----------------------------------------------------------

    def _check_domain(self, oid: str, *, role: str) -> None:
        if oid == AHVN13_OID:
            raise DirectoryError(
                400 if role == "source" else 403,
                "code-invalid",
                "the AHVN13 is not an identifier of the patient record "
                "(EPDG art. 5); use the EPR-SPID",
            )
        if oid not in self.domains:
            if role == "source":
                raise DirectoryError(
                    400,
                    "code-invalid",
                    "sourceIdentifier Assigning Authority not found",
                )
            raise DirectoryError(403, "code-invalid", "targetSystem not found")

    def _find(self, session: Session, oid: str, value: str) -> Person | None:
        if oid == EPR_SPID_OID:
            person = self._persons.find_by_spid(session, value)
        else:
            person = session.get(Person, value)
        if person is None or not self._is_patient(session, person):
            # A non-patient is indistinguishable from nobody: the directory
            # must not confirm that a professional or a visitor exists.
            return None
        return person

    def _is_patient(self, session: Session, person: Person) -> bool:
        return self._persons.has_role(session, person.uid, PersonRoleKind.PATIENT)

    def _identifiers(self, person: Person) -> dict[str, str]:
        identifiers = {self._community_oid: person.uid}
        if person.spid:
            identifiers[EPR_SPID_OID] = person.spid
        return identifiers

    def _record(self, session: Session, person: Person) -> PatientRecord:
        view = self._persons.view(session, person)
        return PatientRecord(
            uid=person.uid,
            spid=person.spid,
            family_name=view.family_name,
            given_name=view.given_name,
            birth_date=person.birth_date,
            gender=fhir_gender(person.administrative_sex),
            active=person.status == PersonStatus.ACTIVE.value,
        )

    def resolve(self, session: Session, identifier: str) -> Person | None:
        """Resolve a ``urn:oid:…|value`` token to a patient, without auditing
        or a role check. For callers that authorise by other means — a
        capability token for that patient's dossier — and audit themselves.
        """
        oid, value = parse_token(identifier)
        self._check_domain(oid, role="source")
        return self._find(session, oid, value)

    # -- ITI-83: cross-reference ----------------------------------------------

    def cross_reference(
        self,
        session: Session,
        actor: ActorContext,
        *,
        source_identifier: str,
        target_systems: tuple[str, ...] = (),
    ) -> tuple[str, list[tuple[str, str]]]:
        """Return (patient uid, [(oid, value), …]) in the requested domains.

        With no target system, every domain other than the source's. An empty
        list — the patient has no identifier in that domain yet, for example
        no EPR-SPID — is a successful answer, not an error.
        """
        self.require_professional(session, actor)
        source_oid, value = parse_token(source_identifier)
        self._check_domain(source_oid, role="source")
        targets = tuple(strip_oid(system) for system in target_systems)
        for target in targets:
            self._check_domain(target, role="target")

        person = self._find(session, source_oid, value)
        if person is None:
            self._audit(session, actor, AuditAction.PATIENT_CROSS_REFERENCED, 0, None)
            raise DirectoryError(
                404, "not-found", "sourceIdentifier Patient Identifier not found"
            )

        wanted = targets or tuple(oid for oid in self.domains if oid != source_oid)
        known = self._identifiers(person)
        found = [(oid, known[oid]) for oid in wanted if oid in known]
        self._audit(session, actor, AuditAction.PATIENT_CROSS_REFERENCED, 1, person.uid)
        return person.uid, found

    # -- ITI-78: demographic query --------------------------------------------

    def search(
        self,
        session: Session,
        actor: ActorContext,
        *,
        identifier: str | None = None,
        family: str | None = None,
        given: str | None = None,
        birthdate: date | None = None,
        gender: str | None = None,
    ) -> list[PatientRecord]:
        self.require_professional(session, actor)
        if gender is not None and gender not in FHIR_GENDERS:
            raise DirectoryError(400, "code-invalid", f"unknown gender {gender!r}")

        if identifier is not None:
            oid, value = parse_token(identifier)
            self._check_domain(oid, role="source")
            person = self._find(session, oid, value)
            candidates = [person] if person is not None else []
        else:
            if not family or birthdate is None:
                raise DirectoryError(
                    400,
                    "required",
                    "a demographic search needs family and birthdate, or an identifier",
                )
            index = self._identity.demographic_index(family, birthdate)
            candidates = [
                person
                for person in session.execute(
                    select(Person).where(Person.demographic_index == index)
                ).scalars()
                if self._is_patient(session, person)
            ]

        if gender is not None:
            candidates = [
                p for p in candidates if fhir_gender(p.administrative_sex) == gender
            ]
        records = [self._record(session, person) for person in candidates]
        if given:
            wanted = normalise_family_name(given)
            records = [r for r in records if _given_matches(r.given_name, wanted)]

        if len(records) > self._max_results:
            self._audit(
                session, actor, AuditAction.PATIENT_SEARCHED, len(records), None
            )
            raise DirectoryError(
                400,
                "too-costly",
                f"more than {self._max_results} patients match; narrow the search",
            )
        self._audit(
            session,
            actor,
            AuditAction.PATIENT_SEARCHED,
            len(records),
            records[0].uid if len(records) == 1 else None,
        )
        return records

    # -- ITI-119: demographic match -------------------------------------------

    def match(
        self,
        session: Session,
        actor: ActorContext,
        *,
        identifiers: list[str],
        family: str | None,
        given: str | None,
        birthdate: date | None,
        gender: str | None,
        only_certain: bool = False,
        count: int | None = None,
    ) -> list[tuple[PatientRecord, float, str]]:
        """Score candidates for a Patient the caller describes.

        Returns ``(record, score, grade)`` with grade ``certain``, ``probable``
        or ``possible`` (the FHIR match-grade codes), best first.

        Deliberately conservative, because a false match in a health record
        files one person's results under another:

        * **certain** only on an identifier this directory issued or knows —
          the EPR-SPID or our patient id. Demographics alone are never
          certain: two people can share a name and a birthday.
        * **probable** needs family name *and* birth date *and* given name to
          agree, with no contradicting gender.
        * **possible** is family name and birth date only.

        Candidates come only from an identifier or from the blind index over
        (family name, birth date), exactly as ITI-78 — so a $match is no
        wider a net than a search.
        """
        self.require_professional(session, actor)
        if gender is not None and gender not in FHIR_GENDERS:
            raise DirectoryError(400, "code-invalid", f"unknown gender {gender!r}")

        scored: dict[str, tuple[Person, float, str]] = {}
        for token in identifiers:
            oid, value = parse_token(token)
            if oid == AHVN13_OID:
                self._check_domain(oid, role="source")
            if oid not in self.domains:
                continue  # an identifier from another domain is not evidence
            person = self._find(session, oid, value)
            if person is not None:
                scored[person.uid] = (person, 1.0, "certain")

        if family and birthdate is not None:
            index = self._identity.demographic_index(family, birthdate)
            wanted_given = normalise_family_name(given) if given else None
            for person in session.execute(
                select(Person).where(Person.demographic_index == index)
            ).scalars():
                if person.uid in scored or not self._is_patient(session, person):
                    continue
                record_gender = fhir_gender(person.administrative_sex)
                if gender and record_gender not in (gender, "unknown"):
                    continue  # a contradiction rules the candidate out
                view_given = self._persons.view(session, person).given_name
                if wanted_given and _given_matches(view_given, wanted_given):
                    scored[person.uid] = (person, 0.9, "probable")
                else:
                    scored[person.uid] = (person, 0.6, "possible")
        elif not identifiers:
            raise DirectoryError(
                400,
                "required",
                "$match needs an identifier, or family name and birth date",
            )

        ranked = sorted(scored.values(), key=lambda item: -item[1])
        if only_certain:
            ranked = [item for item in ranked if item[2] == "certain"]
            if len(ranked) > 1:
                # Two "certain" answers mean the identifiers disagree about
                # who this is; that needs a person, not a guess.
                ranked = []
        if count is not None:
            ranked = ranked[:count]
        if len(ranked) > self._max_results:
            raise DirectoryError(
                400,
                "too-costly",
                f"more than {self._max_results} candidates; narrow the input",
            )
        self._audit(
            session,
            actor,
            AuditAction.PATIENT_SEARCHED,
            len(ranked),
            ranked[0][0].uid if len(ranked) == 1 else None,
        )
        return [
            (self._record(session, person), score, grade)
            for person, score, grade in ranked
        ]

    def read(self, session: Session, actor: ActorContext, uid: str) -> PatientRecord:
        """``GET Patient/{id}`` — the id being our local patient id."""
        self.require_professional(session, actor)
        person = self._find(session, self._community_oid, uid)
        if person is None:
            raise DirectoryError(404, "not-found", "no patient with this id")
        self._audit(session, actor, AuditAction.PATIENT_SEARCHED, 1, person.uid)
        return self._record(session, person)

    # -- audit ----------------------------------------------------------------

    def _audit(
        self,
        session: Session,
        actor: ActorContext,
        action: AuditAction,
        matches: int,
        patient_uid: str | None,
    ) -> None:
        # Counts and the resolved patient only — never the search terms.
        self._ledger.append(
            session,
            actor=actor,
            action=action,
            resource_type="patient",
            resource_uid=patient_uid,
            detail={"matches": matches},
        )


def _given_matches(given_name: str | None, wanted: str) -> bool:
    """Whether a normalised given-name query matches the full given name or
    any one of several (``Anna Maria`` is found by ``Maria``)."""
    if not given_name:
        return False
    parts = [given_name, *given_name.replace("-", " ").split()]
    return any(normalise_family_name(part) == wanted for part in parts)
