# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 swiss-ehealth contributors
"""Shared column types and mixins."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import DateTime, Integer, String, TypeDecorator
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from ehealth.db import utcnow

#: JSONB on PostgreSQL, plain JSON elsewhere (tests run on SQLite).
JsonType = JSON().with_variant(JSONB(), "postgresql")


class UtcDateTime(TypeDecorator):
    """Timezone-aware datetime that survives SQLite's naive storage.

    SQLite drops tzinfo, which turns every comparison against an aware "now"
    into a TypeError at the worst possible moment. Normalising on the way in
    and re-attaching UTC on the way out keeps the rest of the codebase free of
    naive datetimes.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(
        self, value: datetime | None, dialect: Any
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("refusing to store a naive datetime")
        if dialect.name == "sqlite":
            # Store UTC wall-clock, not local time, or ordering breaks across
            # deployments in different timezones.
            return value.astimezone(UTC).replace(tzinfo=None)
        return value

    def process_result_value(
        self, value: datetime | None, dialect: Any
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value


class Confidentiality(StrEnum):
    """EPDG access levels, ordered from least to most restrictive.

    ``NORMAL`` is visible to any professional the patient allows,
    ``RESTRICTED`` only to those the patient explicitly designates, and
    ``SECRET`` is visible to the patient alone (EPDV annex 2).
    """

    NORMAL = "normal"
    RESTRICTED = "restricted"
    SECRET = "secret"  # noqa: S105 (a confidentiality level, not a secret)

    @property
    def rank(self) -> int:
        return {"normal": 0, "restricted": 1, "secret": 2}[self.value]

    def is_reachable_from(self, granted: Confidentiality) -> bool:
        """A grant at ``granted`` may read documents up to that level."""
        return self.rank <= granted.rank


class Purpose(StrEnum):
    """Why an access is happening. Recorded on every token and audit event."""

    TREATMENT = "treatment"
    EMERGENCY = "emergency"
    PATIENT_ACCESS = "patient_access"
    REPRESENTATIVE = "representative"
    ADMINISTRATION = "administration"
    QUALITY_ASSURANCE = "quality_assurance"


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        UtcDateTime, default=utcnow, onupdate=utcnow, nullable=False
    )


class VersionMixin:
    """Optimistic locking plus a human-meaningful revision counter.

    ``version`` is incremented by the repository layer on every mutation and
    is the version referenced by :class:`~ehealth.models.audit.RecordRevision`,
    so a row and its change history can never drift apart silently.
    """

    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)


class UidPk:
    uid: Mapped[str] = mapped_column(String(32), primary_key=True)
