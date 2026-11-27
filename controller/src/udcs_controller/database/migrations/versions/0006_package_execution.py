"""package execution: per-node user-code eligibility, package run limits, exit codes

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-27
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    with op.batch_alter_table("nodes", recreate="auto") as batch:
        # Administrator-set; every existing and new node starts NOT eligible for user code.
        batch.add_column(
            sa.Column("user_code_allowed", sa.Boolean(), nullable=False, server_default=sa.false())
        )
    with op.batch_alter_table("jobs", recreate="auto") as batch:
        batch.add_column(sa.Column("run_limits", JSON, nullable=True))
        batch.add_column(sa.Column("exit_code", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("jobs", recreate="auto") as batch:
        batch.drop_column("exit_code")
        batch.drop_column("run_limits")
    with op.batch_alter_table("nodes", recreate="auto") as batch:
        batch.drop_column("user_code_allowed")
