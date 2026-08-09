# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Build a demo dataset that walks the whole system.

Run with ``make seed``. It registers an institution, three people, opens a
dossier, records consent, issues a treatment grant, prescribes and dispenses a
medication, gives a visitor time-boxed read access, and then prints the audit
trail and verifies the ledger — so the output is a readable proof that the
pieces fit together.
"""

from __future__ import annotations

import datetime as dt
import sys

from ehealth.config import Settings
from ehealth.container import build_container
from ehealth.db import create_all, get_session_factory, init_engine
from ehealth.models.base import Confidentiality, Purpose
from ehealth.models.clinical import DispensingCategory, MedicationEventKind
from ehealth.models.core import (
    MedicalProfession,
    PersonRoleKind,
    ProfessionalRegister,
)
from ehealth.security.tokens import Scope
from ehealth.services.audit import ActorContext
from ehealth.services.dossier import DocumentInput
from ehealth.services.medication import ProductInput, StatementInput
from ehealth.services.persons import CredentialRegistration, PersonRegistration

ANNA = "756.1234.5678.97"
BEAT = "756.9217.0769.85"
CARLA = "756.3047.5009.62"


def rule(title: str) -> None:
    print(f"\n\033[1m{title}\033[0m")
    print("─" * max(len(title), 40))


def main() -> int:
    settings = Settings(database_url="sqlite+pysqlite:///./ehealth-demo.db")
    init_engine(settings)
    create_all()
    container = build_container(settings)
    actor = ActorContext.system(request_id="seed")

    with get_session_factory()() as db:
        rule("1. Registry")
        organization = container.organizations.register(
            db, actor, name="Kantonsspital Musterstadt", che_uid="CHE-109.322.551"
        )
        patient = container.persons.register(
            db,
            PersonRegistration(
                roles=[PersonRoleKind.PATIENT],
                given_name="Anna",
                family_name="Muster",
                ahvn13=ANNA,
                email="anna.muster@example.ch",
            ),
            actor,
        )
        doctor = container.persons.register(
            db,
            PersonRegistration(
                # Beat is a physician *and* a patient here: one person, one
                # UID, one pseudonym, two roles.
                roles=[PersonRoleKind.PATIENT],
                given_name="Beat",
                family_name="Arzt",
                ahvn13=BEAT,
            ),
            actor,
        )
        credential = container.persons.register_credential(
            db,
            doctor,
            actor,
            CredentialRegistration(
                gln="7601000000002",
                register=ProfessionalRegister.MEDREG,
                profession=MedicalProfession.PHYSICIAN,
                specialisation="Facharzt Allgemeine Innere Medizin",
                licence_canton="ZH",
                licence_number="ZH-2019-04412",
                licence_valid_from=dt.date(2019, 5, 1),
                zsr_number="A123456",
                organization_uid=organization.uid,
            ),
        )
        container.persons.verify_credential(
            db, credential, actor, source="MedReg", evidence={"checked": "demo"}
        )
        visitor = container.persons.register(
            db,
            PersonRegistration(
                roles=[PersonRoleKind.VISITOR],
                given_name="Carla",
                family_name="Besuch",
                ahvn13=CARLA,
            ),
            actor,
        )
        from ehealth.domain.uid import format_spid

        print(f"  institution  {organization.uid}  {organization.name}")
        print(f"  patient      {patient.uid}")
        print(f"    EPR-SPID   {format_spid(patient.spid)}  (18 digits)")
        print(f"  professional {doctor.uid}")
        print(f"    EPR-SPID   {format_spid(doctor.spid)}")
        print(f"    GLN        {credential.gln}  MedReg, {credential.specialisation}")
        print(
            f"    licence    {credential.licence_canton} "
            f"{credential.licence_number}, verified {credential.verified_at:%Y-%m-%d}"
        )
        print(
            f"    roles      {', '.join(sorted(r.role for r in container.persons.roles(db, doctor.uid)))}"
        )
        print(f"  visitor      {visitor.uid}")
        print(f"\n  the AHV number {ANNA} is now stored nowhere:")
        print(f"    ppid   {patient.ppid}")
        print(f"    index  {patient.lookup_index}")
        print(f"    sealed {patient.sealed_ahvn[:48]}…")

        rule("2. Dossier and consent")
        dossier = container.dossiers.open(
            db, actor, patient=patient, home_community="Gemeinschaft Musterstadt"
        )
        consent = container.consents.record(
            db,
            actor,
            patient=patient,
            default_access_level=Confidentiality.NORMAL,
            emergency_access_allowed=True,
            notify_on_access=True,
        )
        print(f"  dossier   {dossier.uid}")
        print(f"  retention until {dossier.retention_until:%Y-%m-%d}")
        print(f"  consent   {consent.uid}  participation={consent.participation}")

        rule("3. Treatment grant and capability token")
        grant = container.access.issue_grant(
            db,
            actor,
            dossier=dossier,
            grantee=doctor,
            granted_by=patient,
            purpose=Purpose.TREATMENT,
            scopes=[
                Scope.DOSSIER_READ,
                Scope.DOCUMENT_READ,
                Scope.DOCUMENT_WRITE,
                Scope.MEDICATION_READ,
                Scope.MEDICATION_WRITE,
            ],
            ttl_seconds=3600,
        )
        capability = container.access.mint(db, actor, grant=grant)
        db.commit()
        print(f"  grant     {grant.uid}  level={grant.access_level}")
        print(
            f"  token     expires {capability.expires_at:%H:%M:%S}, "
            f"scopes {', '.join(capability.scopes)}"
        )
        print(f"  {capability.token[:72]}…")

        access = container.access.authorize(
            db, capability.token, required_scope=Scope.MEDICATION_WRITE
        )

        rule("4. Medication")
        product = container.catalogue.register(
            db,
            actor,
            ProductInput(
                gtin="7601000000002",
                name="Lisinopril Mepha 10 mg",
                active_ingredient="Lisinopril",
                atc_code="C09AA03",
                dose_form="Tablette",
                strength="10 mg",
                package_size="30 Stk",
                swissmedic_authorisation="55123",
                pharmacode="1234567",
                dispensing_category=DispensingCategory.B,
                sl_listed=True,
                sl_number="55123.01",
            ),
        )
        prescription = container.medications.record(
            db,
            access,
            StatementInput(
                kind=MedicationEventKind.PRESCRIPTION,
                product_uid=product.uid,
                dosage={
                    "amount": 1,
                    "unit": "Tablette",
                    "frequency": "1-0-0-0",
                    "route": "oral",
                },
                reason="Arterielle Hypertonie",
            ),
            recorded_by_uid=doctor.uid,
            organization_uid=organization.uid,
        )
        container.medications.record(
            db,
            access,
            StatementInput(
                kind=MedicationEventKind.DISPENSE,
                product_uid=product.uid,
                quantity="30 Stk",
                based_on_uid=prescription.uid,
                dosage={"amount": 1, "unit": "Tablette", "frequency": "1-0-0-0"},
            ),
            recorded_by_uid=doctor.uid,
            organization_uid=organization.uid,
        )
        container.dossiers.add_document(
            db,
            access,
            author=doctor,
            document=DocumentInput(
                title="Konsultationsbericht",
                document_class="clinical-note",
                mime_type="text/plain",
                content=b"Blutdruck 150/95 mmHg. Therapie begonnen.",
            ),
        )
        db.commit()

        reconciled = container.medications.reconciled_list(db, access)
        print("  reconciled medication list:")
        for row in reconciled:
            product_name = (
                db.get(type(product), row.product_uid).name
                if row.product_uid
                else row.product_text
            )
            print(
                f"    {row.kind:<14} {product_name}  {row.dosage.get('frequency', '')}"
            )

        rule("5. Visitor access")
        visitor_grant = container.access.issue_grant(
            db,
            actor,
            dossier=dossier,
            grantee=visitor,
            granted_by=patient,
            purpose=Purpose.TREATMENT,
            # Write scopes are requested and silently clamped away.
            scopes=[Scope.DOSSIER_READ, Scope.MEDICATION_READ, Scope.DOCUMENT_WRITE],
            grantee_role=PersonRoleKind.VISITOR,
            ttl_seconds=7200,
            max_uses=10,
        )
        visitor_token = container.access.mint(db, actor, grant=visitor_grant)
        db.commit()
        print(
            f"  granted scopes {', '.join(visitor_grant.scopes)}"
            "  (document:write was asked for and dropped)"
        )
        print(
            f"  valid until {visitor_grant.valid_until:%H:%M:%S}, "
            f"max {visitor_grant.max_uses} uses"
        )

        visitor_access = container.access.authorize(
            db, visitor_token.token, required_scope=Scope.MEDICATION_READ
        )
        visible = container.medications.list_for_dossier(db, visitor_access)
        print(
            f"  visitor sees {len(visible)} medication entries at level "
            f"{visitor_access.max_level.value}"
        )

        rule("6. Revocation")
        container.access.revoke_grant(
            db, actor, grant, reason="Behandlung abgeschlossen"
        )
        db.commit()
        from ehealth.services.access import AccessError

        try:
            container.access.authorize(
                db, capability.token, required_scope=Scope.DOSSIER_READ
            )
            print("  ERROR: revoked token still worked")
            return 1
        except AccessError:
            print("  the doctor's token stopped working the moment it was revoked")

        rule("7. Audit trail")
        from sqlalchemy import select

        from ehealth.models.audit import AuditEvent

        events = db.execute(select(AuditEvent).order_by(AuditEvent.seq)).scalars().all()
        for event in events:
            actor_label = event.actor_uid or "system"
            print(
                f"  {event.seq:>3}  {event.occurred_at:%H:%M:%S}  "
                f"{event.action:<24} {event.outcome:<8} {actor_label}"
            )

        rule("8. Ledger integrity")
        # One chain per dossier, so a patient can verify their own record
        # without walking the whole country's trail.
        own = container.ledger.verify_chain(db, dossier.uid)
        print(f"  dossier chain {dossier.uid}: {own.ok} ({own.checked} entries)")
        whole = container.ledger.verify_all(db)
        print(
            f"  every chain verified: {whole.ok} "
            f"({whole.chains_checked} chains, {whole.events_checked} entries)"
        )

        anchor = container.ledger.anchor(db, "demo")
        db.commit()
        print(f"  anchor merkle root {anchor.merkle_root}")
        print(f"  anchor hash        {anchor.anchor_hash}   <- publish this")
        print(
            f"  covers             {anchor.chain_count} chains, "
            f"{anchor.event_count} entries"
        )
        print(f"  re-verified        {container.ledger.verify_anchor(db, anchor)}")

        rule("9. Offline")
        bundle = container.offline.emergency_dataset(
            db, patient=patient, dossier=dossier, actor=actor
        )
        db.commit()
        from ehealth.services.offline import verify_bundle

        verified = verify_bundle(bundle, container.offline.public_key())
        print(f"  emergency dataset  {len(bundle)} bytes (QR-sized)")
        print(f"  verifies offline   {verified.kind}, current={verified.is_current}")
        print(f"  public key         {container.offline.public_key()}")
        print(
            "  contains:",
            ", ".join(m["name"] for m in verified.payload["medications"])
            or "(no current medication)",
        )
        result = whole

        print("\nDemo database written to ./ehealth-demo.db\n")
        return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
