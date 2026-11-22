"""Content-addressed store, resumable uploads, package registration (ADR 0002). Callers commit.

Verification happens at every stage:
- each chunk is checked against its SHA-256 before it is written (with bounded
  decompression when compressed);
- the whole blob is hashed when the upload completes, before it is named;
- a manifest is validated and its blobs checked (existence, size, possession) at
  registration;
- nodes re-hash every file they stage, and the controller re-checks reported outputs.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
import zlib
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

from pydantic import ValidationError
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from udcs_controller.auth.models import User
from udcs_controller.jobs.models import Job
from udcs_controller.nodes.models import Node
from udcs_controller.packages.models import Blob, BlobOwner, BlobUpload, Package, PackageOwner
from udcs_shared.jobs import JobState
from udcs_shared.packages import (
    OutputManifest,
    PackageKind,
    PackageManifest,
    PackagePolicy,
    environment_problems,
    policy_problems,
)

logger = logging.getLogger(__name__)

_ACTIVE = (JobState.ASSIGNED, JobState.RUNNING)
_READ_BLOCK = 1 << 20
_SWEEP_BATCH = 200
_NOT_INTACT = "was not uploaded intact by this attempt"


class PackageError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


# -- the store --------------------------------------------------------------------------------


class BlobStore:
    """Files on disk named by SHA-256. A blob file exists only after verification."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        (self.root / "uploads").mkdir(parents=True, exist_ok=True)

    def path(self, sha256: str) -> Path:
        return self.root / sha256[:2] / sha256

    def partial(self, upload_id: uuid.UUID) -> Path:
        return self.root / "uploads" / f"{upload_id.hex}.part"

    def exists(self, sha256: str) -> bool:
        return self.path(sha256).is_file()

    def write_at(self, upload_id: uuid.UUID, offset: int, data: bytes) -> None:
        path = self.partial(upload_id)
        mode = "r+b" if path.exists() else "wb"
        with open(path, mode) as handle:
            handle.seek(offset)
            handle.write(data)
            handle.truncate()  # a retried chunk never leaves trailing garbage
            handle.flush()
            os.fsync(handle.fileno())

    def finalize(self, upload_id: uuid.UUID, sha256: str) -> bool:
        """Hash the partial file in full; name it only if it matches. Streams in 1 MiB
        blocks, so memory use does not depend on blob size. False means a mismatch
        (the partial file is deleted)."""
        partial = self.partial(upload_id)
        if not partial.exists():
            partial.touch()  # a zero-byte file has no chunks; its hash is still checked
        digest = hashlib.sha256()
        with open(partial, "rb") as handle:
            while block := handle.read(_READ_BLOCK):
                digest.update(block)
        if digest.hexdigest() != sha256:
            partial.unlink(missing_ok=True)
            return False
        target = self.path(sha256)
        if target.exists():  # someone else stored the same bytes: keep one copy
            partial.unlink(missing_ok=True)
            return True
        target.parent.mkdir(parents=True, exist_ok=True)
        os.replace(partial, target)
        return True

    def discard(self, upload_id: uuid.UUID) -> None:
        self.partial(upload_id).unlink(missing_ok=True)

    def read(self, sha256: str, start: int = 0) -> Iterator[bytes]:
        with open(self.path(sha256), "rb") as handle:
            handle.seek(start)
            while block := handle.read(_READ_BLOCK):
                yield block


# -- uploads ----------------------------------------------------------------------------------


def _owned_bytes(db: Session, user: User) -> int:
    return (
        db.scalar(
            select(func.coalesce(func.sum(Blob.size), 0))
            .join(BlobOwner, BlobOwner.sha256 == Blob.sha256)
            .where(BlobOwner.user_id == user.id)
        )
        or 0
    )


def owns(db: Session, user: User, sha256: str) -> bool:
    return owns_id(db, user.id, sha256)


def owns_id(db: Session, user_id: uuid.UUID, sha256: str) -> bool:
    return db.get(BlobOwner, (sha256, user_id)) is not None


def _open_bytes(db: Session, owner_filter, now: datetime) -> int:
    """Bytes reserved by unexpired open sessions: they count against quotas, or a user
    could hold unbounded partial files by never completing."""
    return (
        db.scalar(
            select(func.coalesce(func.sum(BlobUpload.size), 0)).where(
                owner_filter, BlobUpload.state == "open", BlobUpload.expires_at > now
            )
        )
        or 0
    )


def sweep_uploads(db: Session, store: BlobStore, *, now: datetime) -> int:
    """Close sessions that can never complete and delete their partial files: expired
    sessions, and node sessions whose job attempt is no longer current. Bounded per
    call; it runs whenever an upload starts."""
    current_attempt = (
        select(Job.id)
        .where(
            Job.id == BlobUpload.job_id,
            Job.attempt == BlobUpload.attempt,
            Job.state.in_(_ACTIVE),
        )
        .exists()
    )
    rows = db.scalars(
        select(BlobUpload)
        .where(
            BlobUpload.state == "open",
            or_(
                BlobUpload.expires_at <= now,
                BlobUpload.node_id.is_not(None) & ~current_attempt,
            ),
        )
        .limit(_SWEEP_BATCH)
    ).all()
    for upload in rows:
        upload.state = "expired"
        store.discard(upload.id)
    return len(rows)


def _output_budget(db: Session, job: Job, policy: PackagePolicy) -> tuple[int, int]:
    manifest = PackageManifest.model_validate(db.get(Package, job.package_digest).manifest)
    return (
        min(manifest.limits.max_output_bytes, policy.max_output_bytes),
        min(manifest.limits.max_output_files, policy.max_output_files),
    )


def begin_upload(
    db: Session,
    store: BlobStore,
    *,
    sha256: str,
    size: int,
    now: datetime,
    policy: PackagePolicy,
    user: User | None = None,
    node: Node | None = None,
    job: Job | None = None,
    attempt: int | None = None,
) -> BlobUpload | None:
    """Start (or resume) an upload. Returns None if the caller already holds this blob,
    so the transfer is skipped. A *user* is never told that someone else has the blob
    (no existence oracle across users); they upload it and prove possession.

    Node uploads are job outputs. They are bounded per job attempt by the package's and
    the policy's output limits, counted when a session starts (open and completed
    sessions both count), so a node cannot fill the store before it reports."""
    if size > policy.max_file_bytes:
        raise PackageError(413, f"file larger than {policy.max_file_bytes} bytes")
    sweep_uploads(db, store, now=now)
    if user is not None:
        owner_filter = BlobUpload.owner_user_id == user.id
        per_owner = owner_filter
        if owns(db, user, sha256):
            return None
    else:
        if node is None or job is None or attempt is None:
            raise PackageError(400, "node uploads need a job and attempt")
        owner_filter = (
            (BlobUpload.node_id == node.id)
            & (BlobUpload.job_id == job.id)
            & (BlobUpload.attempt == attempt)
        )
        per_owner = BlobUpload.node_id == node.id
    sessions = db.scalars(
        select(BlobUpload).where(
            owner_filter,
            BlobUpload.sha256 == sha256,
            BlobUpload.state.in_(("open", "complete")),
        )
    ).all()
    for existing in sessions:
        if existing.state == "complete" and user is None:
            return None  # this attempt already proved it holds these bytes
        if existing.state == "open" and existing.expires_at > now:
            return existing  # resume: the client asks for `received` and continues there
    if user is not None:
        reserved = _owned_bytes(db, user) + _open_bytes(db, owner_filter, now)
        if reserved + size > policy.user_storage_bytes:
            raise PackageError(413, "storage quota exceeded")
    else:
        max_bytes, max_files = _output_budget(db, job, policy)
        count, used = db.execute(
            select(func.count(), func.coalesce(func.sum(BlobUpload.size), 0)).where(
                owner_filter, BlobUpload.state.in_(("open", "complete"))
            )
        ).one()
        if count + 1 > max_files:
            raise PackageError(413, f"more than {max_files} output files for this attempt")
        if (used or 0) + size > max_bytes:
            raise PackageError(413, f"outputs for this attempt exceed {max_bytes} bytes")
    open_count = db.scalar(
        select(func.count())
        .select_from(BlobUpload)
        .where(per_owner, BlobUpload.state == "open", BlobUpload.expires_at > now)
    )
    if (open_count or 0) >= policy.max_open_uploads_per_owner:
        raise PackageError(429, "too many open uploads")
    upload = BlobUpload(
        sha256=sha256,
        size=size,
        received=0,
        transferred=0,
        state="open",
        owner_user_id=user.id if user is not None else None,
        node_id=node.id if node is not None else None,
        job_id=job.id if job is not None else None,
        attempt=attempt,
        created_at=now,
        expires_at=now + timedelta(hours=policy.upload_session_hours),
    )
    db.add(upload)
    db.flush()
    return upload


def append_chunk(
    db: Session,
    store: BlobStore,
    upload: BlobUpload,
    *,
    offset: int,
    body: bytes,
    chunk_sha256: str,
    encoding: str,
    raw_size: int,
    now: datetime,
    policy: PackagePolicy,
) -> None:
    """Write one chunk at `offset`. It must continue exactly where the session stands
    (or retry the last chunk), and its decoded bytes must hash to `chunk_sha256`.
    Compressed chunks are decoded with a hard output bound, so a decompression bomb
    is rejected after at most `raw_size + 1` bytes."""
    if upload.state != "open" or upload.expires_at <= now:
        raise PackageError(409, "upload session is not open")
    if offset > upload.received:
        raise PackageError(409, f"gap: the session has {upload.received} bytes")
    if raw_size <= 0 or raw_size > policy.chunk_bytes:
        raise PackageError(413, f"chunk must be 1..{policy.chunk_bytes} bytes")
    if offset + raw_size > upload.size:
        raise PackageError(413, "chunk goes past the declared size")
    if len(body) > policy.chunk_bytes:
        raise PackageError(413, "chunk body too large")
    if encoding == "identity":
        data = body
    elif encoding == "zlib":
        if raw_size > max(1, len(body)) * policy.max_compression_ratio:
            raise PackageError(413, "compression ratio above policy (decompression bomb)")
        decoder = zlib.decompressobj()
        try:
            data = decoder.decompress(body, raw_size + 1)
        except zlib.error:
            raise PackageError(422, "corrupt compressed chunk") from None
        if len(data) > raw_size or decoder.unconsumed_tail or not decoder.eof:
            raise PackageError(413, "chunk decompresses beyond its declared size")
    else:
        raise PackageError(415, f"unsupported chunk encoding {encoding!r}")
    if len(data) != raw_size:
        raise PackageError(422, "chunk size does not match its declared size")
    if hashlib.sha256(data).hexdigest() != chunk_sha256:
        raise PackageError(422, "chunk sha256 mismatch (corrupted in transit)")
    if upload.transferred + len(body) > policy.max_transfer_bytes:
        raise PackageError(413, "upload exceeds the transfer limit")
    store.write_at(upload.id, offset, data)
    upload.received = offset + len(data)
    upload.transferred += len(body)


def complete_upload(
    db: Session,
    store: BlobStore,
    upload: BlobUpload,
    *,
    now: datetime,
    user: User | None,
    policy: PackagePolicy,
) -> Blob:
    if upload.state != "open" or upload.expires_at <= now:
        state = "expired" if upload.state == "open" else upload.state
        raise PackageError(409, f"upload is {state}")
    if upload.received != upload.size:
        raise PackageError(409, f"incomplete: {upload.received} of {upload.size} bytes")
    if user is not None and not owns(db, user, upload.sha256):
        # Re-checked here: other sessions may have completed since this one started.
        if _owned_bytes(db, user) + upload.size > policy.user_storage_bytes:
            upload.state = "failed"
            upload.error = "storage quota exceeded"
            store.discard(upload.id)
            raise PackageError(413, "storage quota exceeded")
    if not store.finalize(upload.id, upload.sha256):
        upload.state = "failed"
        upload.error = "content does not match its sha256"
        raise PackageError(422, "content does not match its sha256; upload discarded")
    upload.state = "complete"
    blob = db.get(Blob, upload.sha256)
    if blob is None:
        blob = Blob(sha256=upload.sha256, size=upload.size, created_at=now)
        db.add(blob)
    if user is not None and not owns(db, user, upload.sha256):
        db.add(BlobOwner(sha256=upload.sha256, user_id=user.id, created_at=now))
    db.flush()
    return blob


# -- packages ---------------------------------------------------------------------------------


def parse_manifest(raw: dict) -> PackageManifest:
    try:
        return PackageManifest.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0]
        raise PackageError(422, f"invalid manifest: {first['msg']}") from None


def register(
    db: Session,
    store: BlobStore,
    manifest: PackageManifest,
    *,
    owner: User,
    policy: PackagePolicy,
    now: datetime,
) -> Package:
    """Accept a manifest only if it is valid under the policy and the owner possesses
    every file it names, at the declared size."""
    problems = policy_problems(manifest, policy)
    for item in manifest.files:
        blob = db.get(Blob, item.sha256)
        if blob is None or not store.exists(item.sha256) or not owns(db, owner, item.sha256):
            problems.append(f"{item.path}: blob not uploaded by you")
        elif blob.size != item.size:
            problems.append(f"{item.path}: size {item.size} does not match the blob")
        if len(problems) > 20:
            break
    if manifest.environment is not None:
        env = db.get(Package, manifest.environment)
        if env is None or env.approved_at is None:
            problems.append("environment is not an approved environment")
        else:
            problems += environment_problems(manifest, PackageManifest.model_validate(env.manifest))
    for dataset in manifest.inputs:
        row = db.get(Package, dataset.digest)
        if row is None or row.kind != PackageKind.DATASET or row.approved_at is None:
            problems.append(f"input {dataset.name}: not an approved dataset")
    if problems:
        raise PackageError(422, "; ".join(problems[:10]))
    digest = manifest.digest()
    package = db.get(Package, digest)
    if package is None:
        package = Package(
            digest=digest,
            kind=manifest.kind,
            name=manifest.name,
            version=manifest.version,
            owner_id=owner.id,  # the first registrant; access is decided by PackageOwner
            manifest=manifest.model_dump(mode="json"),
            total_bytes=manifest.total_bytes,
            created_at=now,
        )
        db.add(package)
        db.flush()
    # Identical content is the same package. Every user who proves possession of each
    # blob becomes an owner, so registering first never locks anyone else out.
    if not package_owned_by(db, package.digest, owner):
        db.add(PackageOwner(digest=package.digest, user_id=owner.id, created_at=now))
        db.flush()
    return package


def package_owned_by(db: Session, digest: str, user: User) -> bool:
    return db.get(PackageOwner, (digest, user.id)) is not None


def approve(package: Package, *, approver: User, now: datetime) -> None:
    if package.kind == PackageKind.PACKAGE:
        raise PackageError(409, "user packages are not approved artifacts")
    package.approved_at = now
    package.approved_by_user_id = approver.id


def usable_package(db: Session, digest: str, user: User) -> Package:
    package = db.get(Package, digest)
    if (
        package is None
        or package.kind != PackageKind.PACKAGE
        or not package_owned_by(db, digest, user)
    ):
        raise PackageError(404, "package not found")
    return package


def staging_closure(db: Session, package: Package) -> dict[str, dict]:
    """Every manifest a node needs for this package: the package, its environment and
    datasets."""
    manifest = PackageManifest.model_validate(package.manifest)
    closure = {package.digest: package.manifest}
    if manifest.environment:
        closure[manifest.environment] = db.get(Package, manifest.environment).manifest
    for dataset in manifest.inputs:
        closure[dataset.digest] = db.get(Package, dataset.digest).manifest
    return closure


def node_may_read(db: Session, node: Node, job: Job, attempt: int, sha256: str) -> bool:
    """A node may download a blob only while it holds the current attempt of a job
    whose package closure contains that blob (fencing, as for reports)."""
    if job.node_id != node.id or job.attempt != attempt or job.state not in _ACTIVE:
        return False
    if job.package_digest is None:
        return False
    package = db.get(Package, job.package_digest)
    for manifest in staging_closure(db, package).values():
        if any(f["sha256"] == sha256 for f in manifest["files"]):
            return True
    return False


def record_outputs(
    db: Session,
    store: BlobStore,
    node: Node,
    job: Job,
    outputs: OutputManifest,
    *,
    policy: PackagePolicy,
) -> None:
    """Accept a node's output manifest for the current attempt only, if every file is
    a verified blob and the totals are within the package's and the policy's limits."""
    if job.node_id != node.id or job.attempt != outputs.attempt or job.state not in _ACTIVE:
        raise PackageError(409, "not the current assignment of this job")
    if job.output_manifest is not None and job.output_manifest.get("attempt") == outputs.attempt:
        raise PackageError(409, "outputs for this attempt were already reported")
    max_bytes, max_files = _output_budget(db, job, policy)
    if len(outputs.files) > max_files:
        raise PackageError(413, f"more than {max_files} output files")
    if outputs.total_bytes > max_bytes:
        raise PackageError(413, f"outputs exceed {max_bytes} bytes")
    # Each output must have been uploaded in full by this node for this attempt, or be a
    # blob the job owner already holds. Naming a hash is never enough: otherwise a node
    # could hand the job owner any blob in the store. "Missing" and "not uploaded by
    # this attempt" get the same answer, so this is not an existence oracle either.
    uploaded = set(
        db.scalars(
            select(BlobUpload.sha256).where(
                BlobUpload.node_id == node.id,
                BlobUpload.job_id == job.id,
                BlobUpload.attempt == outputs.attempt,
                BlobUpload.state == "complete",
            )
        )
    )
    for item in outputs.files:
        blob = db.get(Blob, item.sha256)
        proven = item.sha256 in uploaded or owns_id(db, job.owner_id, item.sha256)
        if not proven or blob is None or blob.size != item.size or not store.exists(item.sha256):
            raise PackageError(422, f"output {item.path} {_NOT_INTACT}")
    job.output_manifest = outputs.model_dump(mode="json")
    for sha in sorted({f.sha256 for f in outputs.files}):  # the job owner may now download
        if db.get(BlobOwner, (sha, job.owner_id)) is None:
            db.add(BlobOwner(sha256=sha, user_id=job.owner_id, created_at=job.updated_at))
