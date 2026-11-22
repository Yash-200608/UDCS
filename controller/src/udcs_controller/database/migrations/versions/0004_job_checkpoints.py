"""central job checkpoints, so a requeued job resumes on another node

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-22
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from udcs_controller.database.base import UTCDateTime

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "job_checkpoints",
        sa.Column("job_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("node_id", sa.Uuid(), nullable=True),
        sa.Column("uploader_version", sa.Integer(), nullable=False),
        sa.Column("units_done", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size", sa.Integer(), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["job_id"], ["jobs.id"], name=op.f("fk_job_checkpoints_job_id_jobs"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_job_checkpoints_node_id_nodes"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("job_id", name=op.f("pk_job_checkpoints")),
    )


def downgrade() -> None:
    op.drop_table("job_checkpoints")
