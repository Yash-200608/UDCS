"""Content-addressed storage and user-code packages (ADR 0002)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from udcs_controller.database.base import Base, JSONType, UTCDateTime, str_enum
from udcs_shared.packages import PackageKind


class Blob(Base):
    """Bytes that exist in the store, named by SHA-256. They are stored once, however
    many users, packages or jobs reference them (storage deduplication)."""

    __tablename__ = "blobs"

    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    size: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())


class BlobOwner(Base):
    """A user proved possession of the blob by uploading it in full. Only owners may
    download it or reference it from a package, and it counts against their quota. A
    hash alone never grants access, so knowing a digest is not enough."""

    __tablename__ = "blob_owners"

    sha256: Mapped[str] = mapped_column(
        ForeignKey("blobs.sha256", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())


class BlobUpload(Base):
    """A resumable, chunked upload session. Bytes go to a partial file; the blob exists
    only after the complete content hashes to `sha256`."""

    __tablename__ = "blob_uploads"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size: Mapped[int] = mapped_column(BigInteger)
    received: Mapped[int] = mapped_column(BigInteger, default=0)
    transferred: Mapped[int] = mapped_column(BigInteger, default=0)  # bytes on the wire
    state: Mapped[str] = mapped_column(String(16))  # open | complete | failed
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True
    )
    node_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("nodes.id", ondelete="CASCADE"), nullable=True, index=True
    )
    job_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"), nullable=True
    )
    attempt: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime())
    error: Mapped[str | None] = mapped_column(String(200), nullable=True)


class Package(Base):
    """A registered manifest (package, environment or dataset), named by its digest."""

    __tablename__ = "packages"

    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[PackageKind] = mapped_column(str_enum(PackageKind, "package_kind"))
    name: Mapped[str] = mapped_column(String(100))
    version: Mapped[str] = mapped_column(String(64))
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONType)
    total_bytes: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
    # Environments and datasets need administrator approval before any package uses them.
    approved_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )


class PackageOwner(Base):
    """A user registered this manifest, proving possession of every blob in it.
    Identical content registered by two users is one package with two owners, so
    nobody can block another user by registering their content first."""

    __tablename__ = "package_owners"

    digest: Mapped[str] = mapped_column(
        ForeignKey("packages.digest", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime())
