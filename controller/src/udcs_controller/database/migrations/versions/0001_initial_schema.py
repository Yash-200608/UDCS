"""initial schema: users, sessions, nodes, inventory, enrollment, audit

Revision ID: 0001
Revises:
Create Date: 2026-11-21
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from udcs_controller.database.base import UTCDateTime

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def _enum(name: str, *values: str) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, create_constraint=True, length=32)


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column(
            "actor_type",
            _enum("audit_actor_type", "user", "node", "anonymous", "system"),
            nullable=False,
        ),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=32), nullable=True),
        sa.Column("target_id", sa.String(length=64), nullable=True),
        sa.Column("details", JSON, nullable=False),
        sa.Column("client_ip", sa.String(length=45), nullable=True),
        sa.Column("request_id", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_index(op.f("ix_audit_events_action"), "audit_events", ["action"])
    op.create_index(op.f("ix_audit_events_created_at"), "audit_events", ["created_at"])

    op.create_table(
        "nodes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column(
            "admin_state",
            _enum("node_admin_state", "active", "maintenance", "revoked"),
            nullable=False,
        ),
        sa.Column("credential_hash", sa.String(length=64), nullable=False),
        sa.Column("enrolled_at", UTCDateTime(), nullable=False),
        sa.Column("revoked_at", UTCDateTime(), nullable=True),
        sa.Column("last_heartbeat_at", UTCDateTime(), nullable=True),
        sa.Column("last_seen_ip", sa.String(length=45), nullable=True),
        sa.Column("agent_version", sa.String(length=32), nullable=False),
        sa.Column("protocol_version", sa.Integer(), nullable=False),
        sa.Column("inventory_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("latest_telemetry", JSON, nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_nodes")),
        sa.UniqueConstraint("credential_hash", name=op.f("uq_nodes_credential_hash")),
    )
    op.create_index(op.f("ix_nodes_admin_state"), "nodes", ["admin_state"])

    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", _enum("user_role", "student", "researcher", "admin"), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
    )

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("expires_at", UTCDateTime(), nullable=False),
        sa.Column("revoked_at", UTCDateTime(), nullable=True),
        sa.Column("client_ip", sa.String(length=45), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_auth_sessions_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_auth_sessions")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_auth_sessions_token_hash")),
    )
    op.create_index(op.f("ix_auth_sessions_user_id"), "auth_sessions", ["user_id"])

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

    op.create_table(
        "hardware_inventories",
        sa.Column("node_id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("inventory", JSON, nullable=False),
        sa.Column("logical_cores", sa.Integer(), nullable=False),
        sa.Column("memory_total_bytes", sa.BigInteger(), nullable=False),
        sa.Column("gpu_count", sa.Integer(), nullable=False),
        sa.Column("gpu_memory_total_bytes", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_hardware_inventories_node_id_nodes"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("node_id", name=op.f("pk_hardware_inventories")),
    )


def downgrade() -> None:
    op.drop_table("hardware_inventories")
    op.drop_table("enrollment_tokens")
    op.drop_index(op.f("ix_auth_sessions_user_id"), table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_table("users")
    op.drop_index(op.f("ix_nodes_admin_state"), table_name="nodes")
    op.drop_table("nodes")
    op.drop_index(op.f("ix_audit_events_created_at"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_action"), table_name="audit_events")
    op.drop_table("audit_events")
