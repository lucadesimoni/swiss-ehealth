# SPDX-License-Identifier: AGPL-3.0-or-later
"""login identity per provider; demographic search index

A person may now hold one login identity per identity provider — HIN at the
practice and SwissID as a patient — instead of exactly one in total. Each
login flow also records which provider it was started with, so the callback
is completed by that provider and no other.

``person.demographic_index`` is a blind index over (normalised family name,
date of birth) for the IHE PDQm patient search. It starts empty for existing
people: computing it needs the root key, which a migration must never hold.
``make reindex-demographics`` fills it afterwards.

Revision ID: 27541241220c
Revises: dbc126357ff5
Created: 2026-09-23 11:13:38.433539

"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = '27541241220c'
down_revision: str | None = 'dbc126357ff5'
branch_labels: str | None = None
depends_on: str | None = None

SCHEMA_VERSION = 5


def upgrade() -> None:
    # The server default fills existing rows: every flow started before this
    # migration was a SwissID flow, because SwissID was the only provider.
    with op.batch_alter_table('oidc_flow', schema=None) as batch_op:
        batch_op.add_column(sa.Column('provider', sa.String(length=32), server_default='swissid', nullable=False))

    # Relaxing a uniqueness rule cannot fail on existing data: every row that
    # satisfied "one account per person" also satisfies "one per provider".
    with op.batch_alter_table('identity_account', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('uq_account_person_uid'), type_='unique')
        batch_op.create_unique_constraint('uq_account_person_issuer', ['person_uid', 'issuer'])

    with op.batch_alter_table('person', schema=None) as batch_op:
        batch_op.add_column(sa.Column('demographic_index', sa.String(length=80), nullable=True))
        batch_op.create_index('ix_person_demographic_index', ['demographic_index'], unique=False)

    from ehealth.schema import stamp_schema_version
    from ehealth.version import version_label

    stamp_schema_version(op.get_bind(), SCHEMA_VERSION, applied_by=version_label())


def downgrade() -> None:
    # Tightening the rule back *can* fail: once a person has linked a second
    # provider, "one account per person" no longer holds. Refuse with the
    # reason rather than letting the constraint fail halfway through a batch
    # rebuild — and never pick an account to delete, because which login a
    # person keeps is not a migration's decision.
    bind = op.get_bind()
    shared = bind.execute(
        sa.text(
            "select count(*) from ("
            " select person_uid from identity_account"
            " group by person_uid having count(*) > 1"
            ") as multi"
        )
    ).scalar()
    if shared:
        raise RuntimeError(
            f"{shared} person(s) hold login identities at more than one provider; "
            "schema 4 allows only one. Unlink the extra identities first."
        )

    with op.batch_alter_table('identity_account', schema=None) as batch_op:
        batch_op.drop_constraint('uq_account_person_issuer', type_='unique')
        batch_op.create_unique_constraint(batch_op.f('uq_account_person_uid'), ['person_uid'])

    with op.batch_alter_table('oidc_flow', schema=None) as batch_op:
        batch_op.drop_column('provider')

    with op.batch_alter_table('person', schema=None) as batch_op:
        batch_op.drop_index('ix_person_demographic_index')
        batch_op.drop_column('demographic_index')

    from ehealth.schema import stamp_schema_version

    stamp_schema_version(bind, 4)
