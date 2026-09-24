# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Load test: the real application, over HTTP, against a real database.

Starts the app with uvicorn in this process, registers a doctor and a set of
patients through the API (each patient logs in, consents and grants the
doctor access, exactly as in production), then runs concurrent workers that
exercise the hot paths for a fixed time:

* ``publish``  — ITI-65, a document into a patient's dossier (write path:
  encryption, storage, change tracking, two ledger appends);
* ``find``     — ITI-67, the patient's document list;
* ``retrieve`` — ITI-68, one document's bytes (decrypt, hash check, ledger);
* ``search``   — PDQm, a demographic patient search.

Reports throughput and p50/p95/p99 latency per operation, and ends by
verifying every ledger chain — a load test that corrupted the audit trail
under contention would otherwise report a pass.

The login uses the in-process mock identity provider, so this measures this
system, not SwissID. Numbers from a laptop are a floor for comparison
between versions, not a capacity figure for production; see docs/scale.md.

    make load-test DB=postgresql+psycopg://… [PATIENTS=50 WORKERS=16 SECONDS=30]
"""

from __future__ import annotations

import argparse
import base64
import random
import statistics
import threading
import time
from collections import defaultdict
from datetime import date

import httpx
import uvicorn
from sqlalchemy import select

from ehealth.config import Environment, Settings
from ehealth.container import build_container
from ehealth.db import get_session_factory, init_engine
from ehealth.main import create_app
from ehealth.models.auth import OidcFlow
from ehealth.schema import require_matching_schema
from ehealth.services.patient_directory import EPR_SPID_OID

ADMIN_KEY = "load-test-admin-key-0123456789abcdef"
SPID = f"urn:oid:{EPR_SPID_OID}"
SURNAMES = ["Müller", "Meier", "Schmid", "Keller", "Weber", "Huber", "Schneider"]


def valid_ahvn(rng: random.Random) -> str:
    """A random AHVN13 with a correct EAN-13 check digit."""
    body = "756" + "".join(str(rng.randrange(10)) for _ in range(9))
    total = sum(int(d) * (3 if i % 2 else 1) for i, d in enumerate(body))
    digits = body + str((10 - total % 10) % 10)
    return f"{digits[:3]}.{digits[3:7]}.{digits[7:11]}.{digits[11:]}"


class Harness:
    def __init__(self, database_url: str, port: int) -> None:
        self.settings = Settings(
            environment=Environment.LOCAL,
            database_url=database_url,
            admin_api_key=ADMIN_KEY,
            use_mock_idp=True,
            smtp_host="",
        )
        init_engine(self.settings)
        require_matching_schema_or_exit(self.settings)
        self.container = build_container(self.settings)
        self.app = create_app(self.settings, container=self.container)
        self.base = f"http://127.0.0.1:{port}"
        self.server = uvicorn.Server(
            uvicorn.Config(self.app, host="127.0.0.1", port=port, log_level="warning")
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> Harness:
        self.thread.start()
        while not self.server.started:
            time.sleep(0.05)
        return self

    def __exit__(self, *exc) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)

    def client(self, headers: dict | None = None) -> httpx.Client:
        return httpx.Client(base_url=f"{self.base}/v1", headers=headers, timeout=30)

    # -- setup, all through the API -------------------------------------------

    def login(self, admin: httpx.Client, person_uid: str, email: str) -> dict:
        subject = f"load-{person_uid}"
        idp = self.container.identity_provider
        idp.enrol(subject, email=email)
        linked = admin.post(
            "/auth/accounts/link",
            json={
                "person_uid": person_uid,
                "issuer": "https://mock-idp.local",
                "subject": subject,
                "email": email,
            },
        )
        linked.raise_for_status()
        with self.client() as anonymous:
            started = anonymous.post("/auth/login")
            started.raise_for_status()
            state = started.json()["state"]
            with get_session_factory()() as session:
                nonce = session.execute(
                    select(OidcFlow.nonce).where(OidcFlow.state == state)
                ).scalar_one()
            code = idp.authorize(subject, nonce)
            challenge = anonymous.post(
                "/auth/callback", json={"state": state, "code": code}
            )
            challenge.raise_for_status()
            otp = self.container.email.last_code_for(email)
            verified = anonymous.post(
                "/auth/mfa/verify",
                json={"session_uid": challenge.json()["session_uid"], "code": otp},
            )
            verified.raise_for_status()
        return {"Authorization": f"Bearer {verified.json()['access_token']}"}

    def setup(self, patients: int, seed: int) -> tuple[list[dict], dict]:
        rng = random.Random(seed)
        with self.client({"X-Admin-Key": ADMIN_KEY}) as admin:
            org = admin.post(
                "/organizations",
                json={"name": "Lastspital", "che_uid": "CHE-109.322.551"},
            )
            if org.status_code == 409:
                raise SystemExit("run against an empty, freshly migrated database")
            org.raise_for_status()
            doctor = admin.post(
                "/persons",
                json={
                    "roles": ["patient"],
                    "given_name": "Last",
                    "family_name": "Ärztin",
                    "ahvn13": valid_ahvn(rng),
                },
            ).json()
            credential = admin.post(
                f"/persons/{doctor['uid']}/credentials",
                json={
                    "gln": "7601000000002",
                    "professional_register": "medreg",
                    "profession": "physician",
                    "licence_canton": "BE",
                    "licence_number": "BE-LOAD-1",
                    "organization_uid": org.json()["uid"],
                },
            ).json()
            admin.post(
                f"/credentials/{credential['uid']}/verify",
                json={"source": "MedReg", "evidence": {"load": True}},
            ).raise_for_status()
            doctor_auth = self.login(admin, doctor["uid"], "aerztin@example.ch")

            cohort = []
            for index in range(patients):
                family = rng.choice(SURNAMES)
                born = date(
                    1940 + rng.randrange(70),
                    1 + rng.randrange(12),
                    1 + rng.randrange(28),
                )
                person = admin.post(
                    "/persons",
                    json={
                        "roles": ["patient"],
                        "given_name": f"Patient{index}",
                        "family_name": family,
                        "ahvn13": valid_ahvn(rng),
                        "birth_date": born.isoformat(),
                        "administrative_sex": rng.choice(["female", "male"]),
                    },
                )
                person.raise_for_status()
                person = person.json()
                dossier = admin.post(
                    "/dossiers", json={"patient_uid": person["uid"]}
                ).json()
                auth = self.login(admin, person["uid"], f"p{index}@example.ch")
                with self.client(auth) as own:
                    own.post(
                        "/consent",
                        json={
                            "default_access_level": "normal",
                            "emergency_access_allowed": True,
                        },
                    ).raise_for_status()
                    grant = own.post(
                        "/grants",
                        json={
                            "dossier_uid": dossier["uid"],
                            "grantee_uid": doctor["uid"],
                            "purpose": "treatment",
                            "scopes": [
                                "dossier:read",
                                "document:read",
                                "document:write",
                            ],
                            "ttl_seconds": 86_400,
                        },
                    ).json()
                with self.client(doctor_auth) as as_doctor:
                    token = as_doctor.post(
                        f"/grants/{grant['uid']}/token", json={}
                    ).json()
                cohort.append(
                    {
                        "spid": person["spid"],
                        "family": family,
                        "born": born.isoformat(),
                        "headers": {**doctor_auth, "X-Capability": token["token"]},
                        "documents": [],
                    }
                )
        return cohort, doctor_auth


def require_matching_schema_or_exit(settings: Settings) -> None:
    from ehealth.db import get_engine

    try:
        require_matching_schema(get_engine())
    except Exception as exc:
        raise SystemExit(f"database not ready: {exc}") from exc


def bundle(spid: str, rng: random.Random) -> dict:
    subject = {"identifier": {"system": SPID, "value": spid}}
    content = rng.randbytes(rng.choice([2_000, 20_000, 200_000]))
    return {
        "resourceType": "Bundle",
        "type": "transaction",
        "entry": [
            {
                "fullUrl": "urn:uuid:ss",
                "resource": {"resourceType": "List", "subject": subject},
            },
            {
                "fullUrl": "urn:uuid:dr",
                "resource": {
                    "resourceType": "DocumentReference",
                    "type": {
                        "coding": [{"system": "http://loinc.org", "code": "11488-4"}]
                    },
                    "subject": subject,
                    "description": "Konsiliarbericht",
                    "securityLabel": [
                        {
                            "coding": [
                                {"system": "http://snomed.info/sct", "code": "17621005"}
                            ]
                        }
                    ],
                    "content": [
                        {
                            "attachment": {
                                "contentType": "application/pdf",
                                "url": "urn:uuid:bin",
                            }
                        }
                    ],
                },
            },
            {
                "fullUrl": "urn:uuid:bin",
                "resource": {
                    "resourceType": "Binary",
                    "contentType": "application/pdf",
                    "data": base64.b64encode(content).decode(),
                },
            },
        ],
    }


def run(
    harness: Harness, cohort: list[dict], doctor: dict, *, workers: int, seconds: float
):
    timings: dict[str, list[float]] = defaultdict(list)
    errors: dict[str, int] = defaultdict(int)
    lock = threading.Lock()
    deadline = time.monotonic() + seconds

    def worker(seed: int) -> None:
        rng = random.Random(seed)
        with harness.client() as http:
            while time.monotonic() < deadline:
                patient = rng.choice(cohort)
                operation = rng.choices(
                    ["publish", "find", "retrieve", "search"], weights=[2, 3, 4, 1]
                )[0]
                if operation == "retrieve" and not patient["documents"]:
                    operation = "publish"
                started = time.perf_counter()
                if operation == "publish":
                    response = http.post(
                        "/fhir",
                        json=bundle(patient["spid"], rng),
                        headers=patient["headers"],
                    )
                    if response.status_code == 200:
                        location = response.json()["entry"][0]["response"]["location"]
                        with lock:
                            patient["documents"].append(location.rpartition("/")[2])
                elif operation == "find":
                    response = http.get(
                        "/fhir/DocumentReference",
                        params={"patient.identifier": f"{SPID}|{patient['spid']}"},
                        headers=patient["headers"],
                    )
                elif operation == "retrieve":
                    uid = rng.choice(patient["documents"])
                    response = http.get(
                        f"/fhir/Binary/{uid}", headers=patient["headers"]
                    )
                else:
                    response = http.get(
                        "/fhir/Patient",
                        params={
                            "family": patient["family"],
                            "birthdate": patient["born"],
                        },
                        headers=doctor,
                    )
                elapsed = time.perf_counter() - started
                with lock:
                    if response.status_code == 200:
                        timings[operation].append(elapsed)
                    else:
                        errors[operation] += 1

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return timings, errors


def report(timings, errors, seconds: float) -> None:
    print(
        f"\n{'operation':10} {'count':>7} {'req/s':>7} {'p50 ms':>8} {'p95 ms':>8} {'p99 ms':>8} {'errors':>7}"
    )
    total = 0
    for operation in ("publish", "find", "retrieve", "search"):
        samples = sorted(timings.get(operation, []))
        total += len(samples)
        if not samples:
            print(
                f"{operation:10} {0:>7} {'-':>7} {'-':>8} {'-':>8} {'-':>8} {errors[operation]:>7}"
            )
            continue
        q = statistics.quantiles(samples, n=100) if len(samples) > 1 else samples * 99
        print(
            f"{operation:10} {len(samples):>7} {len(samples) / seconds:>7.1f} "
            f"{q[49] * 1000:>8.1f} {q[94] * 1000:>8.1f} {q[98] * 1000:>8.1f} {errors[operation]:>7}"
        )
    print(f"{'total':10} {total:>7} {total / seconds:>7.1f}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--patients", type=int, default=50)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--seconds", type=float, default=30)
    parser.add_argument("--port", type=int, default=8765)
    arguments = parser.parse_args()

    with Harness(arguments.database_url, arguments.port) as harness:
        started = time.monotonic()
        cohort, doctor = harness.setup(arguments.patients, seed=7)
        print(
            f"setup: {arguments.patients} patients registered, logged in, consented "
            f"and granted in {time.monotonic() - started:.1f}s"
        )
        timings, errors = run(
            harness,
            cohort,
            doctor,
            workers=arguments.workers,
            seconds=arguments.seconds,
        )
        report(timings, errors, arguments.seconds)
        with get_session_factory()() as session:
            verification = harness.container.ledger.verify_all(session)
        print(
            f"\nledger after the run: {verification.chains_checked} chains, "
            f"{verification.events_checked} events, "
            f"{'all verify' if verification.ok else 'FAILURES: ' + str(verification.failures[:3])}"
        )
    failed = sum(errors.values()) > 0 or not verification.ok
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
