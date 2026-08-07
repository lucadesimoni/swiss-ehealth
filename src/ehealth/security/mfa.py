"""Email one-time codes — the second factor.

Properties that matter:

* The code is generated with :mod:`secrets`, never with ``random``.
* Only a keyed hash of the code is stored, and the key lives in the keyring
  rather than the database, so reading the database does not yield codes.
* Comparison is constant-time, attempts are capped, and consumption is
  one-shot.
* The hash binds the challenge id, so a code minted for one challenge cannot
  be replayed against another.

Email is a *second* factor, not a strong one — it inherits the security of
the user's mailbox. It is the pragmatic choice for population-scale rollout,
and the design leaves room for stronger factors: ``OtpChallenge.channel``
already distinguishes them, and the assurance level recorded on the session
is what authorisation actually reads.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from ehealth.db import utcnow
from ehealth.security.crypto import KeyPurpose, KeyRing, b64u, constant_time_equals


class MfaError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class OtpMaterial:
    """The generated code and the value safe to persist."""

    code: str
    code_hash: str
    expires_at: datetime


class EmailSender(Protocol):
    def send(self, *, to: str, subject: str, body: str) -> None: ...


class InMemoryEmailSender:
    """Collects messages instead of sending them. Development and tests."""

    def __init__(self) -> None:
        self.outbox: list[dict[str, str]] = []

    def send(self, *, to: str, subject: str, body: str) -> None:
        self.outbox.append({"to": to, "subject": subject, "body": body})

    def last_code_for(self, address: str) -> str | None:
        """First standalone 6-10 digit run in the newest message to ``address``."""
        import re

        for message in reversed(self.outbox):
            if message["to"] == address:
                match = re.search(r"\b\d{6,10}\b", message["body"])
                return match.group(0) if match else None
        return None


class SmtpEmailSender:
    """Minimal SMTP sender over STARTTLS.

    Deliberately no HTML, no tracking pixels, no external template service:
    the message says who is asking and what the code is, and nothing about the
    recipient's health data leaves the system.
    """

    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        *,
        username: str | None = None,
        password: str | None = None,
        timeout: int = 10,
    ) -> None:
        if not host:
            raise MfaError("SMTP host is not configured")
        self._host = host
        self._port = port
        self._sender = sender
        self._username = username
        self._password = password
        self._timeout = timeout

    def send(self, *, to: str, subject: str, body: str) -> None:  # pragma: no cover
        import smtplib
        from email.message import EmailMessage

        message = EmailMessage()
        message["From"] = self._sender
        message["To"] = to
        message["Subject"] = subject
        message.set_content(body)
        with smtplib.SMTP(self._host, self._port, timeout=self._timeout) as smtp:
            smtp.starttls()
            if self._username:
                smtp.login(self._username, self._password or "")
            smtp.send_message(message)


class OtpService:
    def __init__(
        self,
        keyring: KeyRing,
        sender: EmailSender,
        *,
        code_length: int = 6,
        ttl_seconds: int = 300,
        service_name: str = "Swiss e-health dossier",
    ) -> None:
        if not 6 <= code_length <= 10:
            raise MfaError("OTP length must be between 6 and 10 digits")
        self._keyring = keyring
        self._sender = sender
        self._length = code_length
        self._ttl = ttl_seconds
        self._service_name = service_name

    def generate(self, challenge_uid: str) -> OtpMaterial:
        # secrets.randbelow gives a uniform value; zero-padding keeps every
        # code the same length so "0" is not a weaker leading digit.
        code = f"{secrets.randbelow(10 ** self._length):0{self._length}d}"
        return OtpMaterial(
            code=code,
            code_hash=self.hash_code(challenge_uid, code),
            expires_at=utcnow() + timedelta(seconds=self._ttl),
        )

    def hash_code(self, challenge_uid: str, code: str) -> str:
        digest = self._keyring.mac(
            KeyPurpose.OTP_BINDING, f"{challenge_uid}|{code}".encode("utf-8")
        )
        return b64u(digest)

    def verify_code(self, challenge_uid: str, code: str, stored_hash: str) -> bool:
        return constant_time_equals(self.hash_code(challenge_uid, code), stored_hash)

    def deliver(self, *, to: str, code: str, expires_in_seconds: int) -> None:
        minutes = max(1, expires_in_seconds // 60)
        self._sender.send(
            to=to,
            subject=f"{self._service_name}: Bestätigungscode",
            body=(
                f"Ihr Bestätigungscode lautet: {code}\n\n"
                f"Der Code ist {minutes} Minuten gültig und kann nur einmal "
                f"verwendet werden.\n\n"
                "Wenn Sie sich nicht angemeldet haben, ignorieren Sie diese "
                "Nachricht und melden Sie den Vorfall.\n\n"
                "---\n"
                f"Votre code de confirmation : {code}\n"
                f"Valable {minutes} minutes, à usage unique.\n\n"
                f"Your confirmation code: {code}\n"
                f"Valid for {minutes} minutes, single use."
            ),
        )
