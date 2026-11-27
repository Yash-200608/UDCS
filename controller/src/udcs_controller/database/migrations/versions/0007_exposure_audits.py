"""exposure audits per node; user-code eligibility bound to an audited image

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-27
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from udcs_controller.database.base import UTCDateTime

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "node_exposure_audits",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("node_id", sa.Uuid(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("image", sa.String(length=330), nullable=False),
        sa.Column("runner", sa.String(length=64), nullable=False),
        sa.Column("passed", sa.Boolean(), nullable=False),
        sa.Column("summary", JSON, nullable=False),
        sa.Column("report", JSON, nullable=False),
        sa.Column("generated_at", UTCDateTime(), nullable=False),
        sa.Column("uploaded_at", UTCDateTime(), nullable=False),
        sa.Column("uploaded_by_user_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_node_exposure_audits_node_id_nodes"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["uploaded_by_user_id"],
            ["users.id"],
            name=op.f("fk_node_exposure_audits_uploaded_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_node_exposure_audits")),
    )
    op.create_index(op.f("ix_node_exposure_audits_node_id"), "node_exposure_audits", ["node_id"])
    with op.batch_alter_table("nodes", recreate="auto") as batch:
        batch.add_column(sa.Column("user_code_image", sa.String(length=330), nullable=True))
        batch.add_column(sa.Column("user_code_audit_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("user_code_granted_at", UTCDateTime(), nullable=True))
        batch.add_column(sa.Column("user_code_granted_by_user_id", sa.Uuid(), nullable=True))
        batch.create_foreign_key(
            op.f("fk_nodes_user_code_granted_by_user_id_users"),
            "users",
            ["user_code_granted_by_user_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    with op.batch_alter_table("nodes", recreate="auto") as batch:
        batch.drop_constraint(
            op.f("fk_nodes_user_code_granted_by_user_id_users"), type_="foreignkey"
        )
        batch.drop_column("user_code_granted_by_user_id")
        batch.drop_column("user_code_granted_at")
        batch.drop_column("user_code_audit_id")
        batch.drop_column("user_code_image")
    op.drop_index(op.f("ix_node_exposure_audits_node_id"), table_name="node_exposure_audits")
    op.drop_table("node_exposure_audits")
