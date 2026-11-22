"""content-addressed blobs, resumable uploads, packages; package and outputs on jobs

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-22
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from udcs_controller.database.base import UTCDateTime

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "blobs",
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.PrimaryKeyConstraint("sha256", name=op.f("pk_blobs")),
    )
    op.create_table(
        "blob_owners",
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["sha256"],
            ["blobs.sha256"],
            name=op.f("fk_blob_owners_sha256_blobs"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_blob_owners_user_id_users"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("sha256", "user_id", name=op.f("pk_blob_owners")),
    )
    op.create_table(
        "packages",
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column(
            "kind",
            sa.Enum(
                "package",
                "environment",
                "dataset",
                name="package_kind",
                native_enum=False,
                create_constraint=True,
                length=32,
            ),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("manifest", JSON, nullable=False),
        sa.Column("total_bytes", sa.BigInteger(), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("approved_at", UTCDateTime(), nullable=True),
        sa.Column("approved_by_user_id", sa.Uuid(), nullable=True),
        sa.ForeignKeyConstraint(
            ["owner_id"], ["users.id"], name=op.f("fk_packages_owner_id_users"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["approved_by_user_id"],
            ["users.id"],
            name=op.f("fk_packages_approved_by_user_id_users"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("digest", name=op.f("pk_packages")),
    )
    op.create_index(op.f("ix_packages_owner_id"), "packages", ["owner_id"])
    op.create_table(
        "package_owners",
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.ForeignKeyConstraint(
            ["digest"],
            ["packages.digest"],
            name=op.f("fk_package_owners_digest_packages"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_package_owners_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("digest", "user_id", name=op.f("pk_package_owners")),
    )
    op.create_table(
        "blob_uploads",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("received", sa.BigInteger(), nullable=False),
        sa.Column("transferred", sa.BigInteger(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("owner_user_id", sa.Uuid(), nullable=True),
        sa.Column("node_id", sa.Uuid(), nullable=True),
        sa.Column("job_id", sa.Uuid(), nullable=True),
        sa.Column("attempt", sa.Integer(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("expires_at", UTCDateTime(), nullable=False),
        sa.Column("error", sa.String(length=200), nullable=True),
        sa.ForeignKeyConstraint(
            ["owner_user_id"],
            ["users.id"],
            name=op.f("fk_blob_uploads_owner_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_blob_uploads_node_id_nodes"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["job_id"], ["jobs.id"], name=op.f("fk_blob_uploads_job_id_jobs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_blob_uploads")),
    )
    op.create_index(op.f("ix_blob_uploads_sha256"), "blob_uploads", ["sha256"])
    op.create_index(op.f("ix_blob_uploads_owner_user_id"), "blob_uploads", ["owner_user_id"])
    op.create_index(op.f("ix_blob_uploads_node_id"), "blob_uploads", ["node_id"])
    with op.batch_alter_table("jobs", recreate="auto") as batch:
        batch.add_column(sa.Column("package_digest", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("output_manifest", JSON, nullable=True))
    with op.batch_alter_table("jobs", recreate="auto") as batch:
        batch.create_foreign_key(
            op.f("fk_jobs_package_digest_packages"),
            "packages",
            ["package_digest"],
            ["digest"],
            ondelete="RESTRICT",
        )
        batch.create_index(op.f("ix_jobs_package_digest"), ["package_digest"])


def downgrade() -> None:
    with op.batch_alter_table("jobs", recreate="auto") as batch:
        batch.drop_index(op.f("ix_jobs_package_digest"))
        batch.drop_constraint(op.f("fk_jobs_package_digest_packages"), type_="foreignkey")
        batch.drop_column("output_manifest")
        batch.drop_column("package_digest")
    op.drop_index(op.f("ix_blob_uploads_node_id"), table_name="blob_uploads")
    op.drop_index(op.f("ix_blob_uploads_owner_user_id"), table_name="blob_uploads")
    op.drop_index(op.f("ix_blob_uploads_sha256"), table_name="blob_uploads")
    op.drop_table("blob_uploads")
    op.drop_table("package_owners")
    op.drop_index(op.f("ix_packages_owner_id"), table_name="packages")
    op.drop_table("packages")
    op.drop_table("blob_owners")
    op.drop_table("blobs")
