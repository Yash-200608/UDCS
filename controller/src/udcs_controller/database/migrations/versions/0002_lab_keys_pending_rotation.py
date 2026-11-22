"""lab-scoped enrollment keys, pending node approval, two-phase credential rotation

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-21

Data migration: Milestone 1 single-use enrollment tokens become single-use keys in
the 'legacy' lab (auto-approved, because the nodes they created are already active).
Existing nodes keep their credentials; `credential_issued_at` starts at enrolment.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from udcs_controller.database.base import UTCDateTime

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _admin_state(*values: str) -> sa.Enum:
    return sa.Enum(
        *values, name="node_admin_state", native_enum=False, create_constraint=True, length=32
    )


OLD_STATES = ("active", "maintenance", "revoked")
NEW_STATES = ("pending", "active", "maintenance", "revoked")


def upgrade() -> None:
    op.create_table(
        "enrollment_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("lab", sa.String(length=128), nullable=False),
        sa.Column("note", sa.String(length=256), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("expires_at", UTCDateTime(), nullable=False),
        sa.Column("max_uses", sa.Integer(), nullable=False),
        sa.Column("use_count", sa.Integer(), nullable=False),
        sa.Column("auto_approve", sa.Boolean(), nullable=False),
        sa.Column("revoked_at", UTCDateTime(), nullable=True),
        sa.Column("last_used_at", UTCDateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name=op.f("fk_enrollment_keys_created_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_enrollment_keys")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_enrollment_keys_token_hash")),
    )
    op.execute(
        """
        INSERT INTO enrollment_keys (id, token_hash, lab, note, created_by_user_id, created_at,
                                     expires_at, max_uses, use_count, auto_approve, revoked_at,
                                     last_used_at)
        SELECT id, token_hash, 'legacy', note, created_by_user_id, created_at, expires_at, 1,
               CASE WHEN used_at IS NULL THEN 0 ELSE 1 END, TRUE, NULL, used_at
        FROM enrollment_tokens
        """
    )

    with op.batch_alter_table("nodes", recreate="auto") as batch:
        batch.add_column(sa.Column("lab", sa.String(length=128), nullable=False, server_default=""))
        batch.add_column(sa.Column("pending_credential_hash", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("credential_issued_at", UTCDateTime(), nullable=True))
        batch.add_column(sa.Column("enrollment_key_id", sa.Uuid(), nullable=True))
        batch.add_column(sa.Column("approved_at", UTCDateTime(), nullable=True))
        batch.add_column(sa.Column("approved_by_user_id", sa.Uuid(), nullable=True))

    op.execute("UPDATE nodes SET credential_issued_at = enrolled_at, approved_at = enrolled_at")
    op.execute(
        """
        UPDATE nodes SET enrollment_key_id =
            (SELECT t.id FROM enrollment_tokens t WHERE t.node_id = nodes.id)
        """
    )

    with op.batch_alter_table("nodes", recreate="auto") as batch:
        batch.alter_column("lab", server_default=None)
        batch.alter_column("credential_issued_at", existing_type=UTCDateTime(), nullable=False)
        batch.drop_constraint(op.f("ck_nodes_node_admin_state"), type_="check")
        batch.create_check_constraint(
            op.f("ck_nodes_node_admin_state"),
            sa.column("admin_state").in_(NEW_STATES),
        )
        batch.create_unique_constraint(
            op.f("uq_nodes_pending_credential_hash"), ["pending_credential_hash"]
        )
        batch.create_foreign_key(
            op.f("fk_nodes_enrollment_key_id_enrollment_keys"),
            "enrollment_keys",
            ["enrollment_key_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_foreign_key(
            op.f("fk_nodes_approved_by_user_id_users"),
            "users",
            ["approved_by_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch.create_index(op.f("ix_nodes_lab"), ["lab"])

    op.drop_table("enrollment_tokens")


def downgrade() -> None:
    op.create_table(
        "enrollment_tokens",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("note", sa.String(length=256), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("expires_at", UTCDateTime(), nullable=False),
        sa.Column("used_at", UTCDateTime(), nullable=True),
        sa.Column("node_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name=op.f("fk_enrollment_tokens_created_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_enrollment_tokens_node_id_nodes"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_enrollment_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_enrollment_tokens_token_hash")),
    )
    # Multi-use keys have no single-use equivalent; they are dropped, not converted.
    op.execute(
        """
        INSERT INTO enrollment_tokens (id, token_hash, created_by_user_id, note, created_at,
                                       expires_at, used_at, node_id)
        SELECT k.id, k.token_hash, k.created_by_user_id, k.note, k.created_at, k.expires_at,
               k.last_used_at, (SELECT n.id FROM nodes n WHERE n.enrollment_key_id = k.id)
        FROM enrollment_keys k WHERE k.max_uses = 1
        """
    )
    op.execute("UPDATE nodes SET admin_state = 'maintenance' WHERE admin_state = 'pending'")
    with op.batch_alter_table("nodes", recreate="auto") as batch:
        batch.drop_index(op.f("ix_nodes_lab"))
        batch.drop_constraint(op.f("fk_nodes_approved_by_user_id_users"), type_="foreignkey")
        batch.drop_constraint(
            op.f("fk_nodes_enrollment_key_id_enrollment_keys"), type_="foreignkey"
        )
        batch.drop_constraint(op.f("uq_nodes_pending_credential_hash"), type_="unique")
        batch.drop_constraint(op.f("ck_nodes_node_admin_state"), type_="check")
        batch.create_check_constraint(
            op.f("ck_nodes_node_admin_state"),
            sa.column("admin_state").in_(OLD_STATES),
        )
        for column in (
            "approved_by_user_id",
            "approved_at",
            "enrollment_key_id",
            "credential_issued_at",
            "pending_credential_hash",
            "lab",
        ):
            batch.drop_column(column)
    op.drop_table("enrollment_keys")
