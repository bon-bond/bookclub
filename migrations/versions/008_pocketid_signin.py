# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Domatron22
"""Pocket ID sign-in identity column

Revision ID: 008
Revises: 007
Create Date: 2026-11-16

Adds a second OpenID Connect identity to `users`: Pocket ID, which is
self-hosted and therefore the provider a deployment that does not want a Google
Cloud project can use instead.

`pocketid_sub` is Pocket ID's stable subject identifier and carries the unique
constraint. As with `google_sub`, email is stored for display only and is
deliberately *not* the join key — addresses change and get recycled, and a new
owner of an old address must never inherit someone else's clubs.

`account_secret` is already nullable as of 005 (Google accounts never get one),
and Pocket ID accounts follow the same rule, so this revision only adds a column.
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('pocketid_sub', sa.String(64), nullable=True))
        # Unique so one Pocket ID identity can never be attached to two accounts.
        # NULLs are exempt in SQLite and PostgreSQL, so accounts that sign in
        # with a secret coexist freely.
        batch_op.create_index('ix_users_pocketid_sub', ['pocketid_sub'], unique=True)


def downgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_index('ix_users_pocketid_sub')
        batch_op.drop_column('pocketid_sub')
