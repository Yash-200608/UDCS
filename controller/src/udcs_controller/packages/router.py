"""HTTP endpoints for blobs, packages and job outputs (ADR 0002)."""

from __future__ import annotations

import re
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import StreamingResponse

from udcs_controller.audit.models import ActorType
from udcs_controller.audit.service import record_event
from udcs_controller.auth.deps import AuthContext, require
from udcs_controller.auth.permissions import Permission, has_permission
from udcs_controller.core.request_context import Now
from udcs_controller.database.session import DbSession
from udcs_controller.jobs.models import Job
from udcs_controller.nodes.deps import CurrentNode
from udcs_controller.packages import service
from udcs_controller.packages.models import Blob, BlobUpload, Package
from udcs_shared.packages import (
    CHUNK_ENCODING_HEADER,
    CHUNK_RAW_SIZE_HEADER,
    CHUNK_SHA256_HEADER,
    SHA256,
    OutputManifest,
    PackagePolicy,
    UploadStart,
    UploadStatus,
)

router = APIRouter(tags=["packages"])
agent_router = APIRouter(prefix="/agent", tags=["agent"])

SubmitJobs = Annotated[AuthContext, Depends(require(Permission.SUBMIT_JOBS))]
ManageJobs = Annotated[AuthContext, Depends(require(Permission.MANAGE_JOBS))]
_SHA = re.compile(SHA256)


def _policy(request: Request) -> PackagePolicy:
    return request.app.state.settings.package_policy


def _store(request: Request) -> service.BlobStore:
    return request.app.state.blob_store


def _user_code_enabled(request: Request) -> None:
    """Kill switch: with user code disabled, nodes get nothing package-related, even
    for jobs submitted while it was on."""
    if not request.app.state.settings.user_code_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="user code execution is disabled")


def _fail(exc: service.PackageError) -> HTTPException:
    return HTTPException(exc.status_code, detail=exc.detail)


def _status(upload: BlobUpload | None, size: int, policy: PackagePolicy) -> UploadStatus:
    if upload is None:
        return UploadStatus(
            upload_id=None, received=size, size=size, chunk_bytes=policy.chunk_bytes, state="owned"
        )
    return UploadStatus(
        upload_id=str(upload.id),
        received=upload.received,
        size=upload.size,
        chunk_bytes=policy.chunk_bytes,
        state=upload.state,
    )


def _range_start(range_header: str | None, size: int) -> int:
    if not range_header:
        return 0
    match = re.fullmatch(r"bytes=(\d+)-", range_header.strip())
    if not match or int(match.group(1)) > size:
        raise HTTPException(status.HTTP_416_RANGE_NOT_SATISFIABLE, detail="unsupported range")
    return int(match.group(1))


def _stream(store: service.BlobStore, sha256: str, size: int, range_header: str | None):
    start = _range_start(range_header, size)
    headers = {"Accept-Ranges": "bytes", "Content-Length": str(size - start), "ETag": sha256}
    code = status.HTTP_200_OK
    if start:
        headers["Content-Range"] = f"bytes {start}-{size - 1}/{size}"
        code = status.HTTP_206_PARTIAL_CONTENT
    return StreamingResponse(
        store.read(sha256, start),
        status_code=code,
        media_type="application/octet-stream",
        headers=headers,
    )


async def _chunk(
    request: Request,
    db,
    upload: BlobUpload,
    offset: int,
    sha: str | None,
    encoding: str,
    raw_size: int | None,
    now,
) -> dict:
    if sha is None or not _SHA.match(sha):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"{CHUNK_SHA256_HEADER} required")
    policy = _policy(request)
    # Bounded before buffering: the body-limit middleware refuses more than
    # policy.chunk_bytes on the wire, and the declared length is checked here first.
    declared = request.headers.get("content-length")
    if declared is None or not declared.isdigit() or int(declared) > policy.chunk_bytes:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"a chunk needs a Content-Length of at most {policy.chunk_bytes} bytes",
        )
    body = await request.body()
    try:
        service.append_chunk(
            db,
            _store(request),
            upload,
            offset=offset,
            body=body,
            chunk_sha256=sha,
            encoding=encoding,
            raw_size=raw_size if raw_size is not None else len(body),
            now=now,
            policy=policy,
        )
    except service.PackageError as exc:
        db.commit()  # keep the session's state; the bytes were not written
        raise _fail(exc) from None
    db.commit()
    return {"received": upload.received}


# -- users: uploads ---------------------------------------------------------------------------


def _user_upload(db, auth: AuthContext, upload_id: uuid.UUID) -> BlobUpload:
    upload = db.get(BlobUpload, upload_id)
    if upload is None or upload.owner_user_id != auth.user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="upload not found")
    return upload


@router.post("/blobs/uploads", response_model=UploadStatus)
def start_upload(body: UploadStart, auth: SubmitJobs, request: Request, db: DbSession, now: Now):
    try:
        upload = service.begin_upload(
            db,
            _store(request),
            sha256=body.sha256,
            size=body.size,
            now=now,
            policy=_policy(request),
            user=auth.user,
        )
    except service.PackageError as exc:
        raise _fail(exc) from None
    db.commit()
    return _status(upload, body.size, _policy(request))


@router.get("/blobs/uploads/{upload_id}", response_model=UploadStatus)
def upload_status(upload_id: uuid.UUID, auth: SubmitJobs, request: Request, db: DbSession):
    upload = _user_upload(db, auth, upload_id)
    return _status(upload, upload.size, _policy(request))


@router.put("/blobs/uploads/{upload_id}")
async def put_chunk(
    upload_id: uuid.UUID,
    auth: SubmitJobs,
    request: Request,
    db: DbSession,
    now: Now,
    offset: Annotated[int, Query(ge=0)],
    chunk_sha: Annotated[str | None, Header(alias=CHUNK_SHA256_HEADER)] = None,
    encoding: Annotated[str, Header(alias=CHUNK_ENCODING_HEADER)] = "identity",
    raw_size: Annotated[int | None, Header(alias=CHUNK_RAW_SIZE_HEADER)] = None,
):
    upload = _user_upload(db, auth, upload_id)
    return await _chunk(request, db, upload, offset, chunk_sha, encoding, raw_size, now)


@router.post("/blobs/uploads/{upload_id}/complete")
def complete(upload_id: uuid.UUID, auth: SubmitJobs, request: Request, db: DbSession, now: Now):
    upload = _user_upload(db, auth, upload_id)
    try:
        blob = service.complete_upload(
            db, _store(request), upload, now=now, user=auth.user, policy=_policy(request)
        )
    except service.PackageError as exc:
        db.commit()
        raise _fail(exc) from None
    db.commit()
    return {"sha256": blob.sha256, "size": blob.size}


@router.get("/blobs/{sha256}")
def download(
    sha256: str,
    auth: SubmitJobs,
    request: Request,
    db: DbSession,
    range_header: Annotated[str | None, Header(alias="Range")] = None,
):
    # Only owners may read a blob; others get the same 404 as for a blob that does not exist.
    if not _SHA.match(sha256) or not service.owns(db, auth.user, sha256):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="blob not found")
    blob = db.get(Blob, sha256)
    return _stream(_store(request), sha256, blob.size, range_header)


# -- users: packages --------------------------------------------------------------------------


@router.get("/packages/policy", response_model=PackagePolicy)
def get_policy(auth: SubmitJobs, request: Request) -> PackagePolicy:
    return _policy(request)


@router.post("/packages", status_code=status.HTTP_201_CREATED)
def register_package(body: dict, auth: SubmitJobs, request: Request, db: DbSession, now: Now):
    policy = _policy(request)
    try:
        manifest = service.parse_manifest(body)
        package = service.register(
            db, _store(request), manifest, owner=auth.user, policy=policy, now=now
        )
    except service.PackageError as exc:
        raise _fail(exc) from None
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="package.registered",
        target_type="package",
        target_id=package.digest,
        details={"kind": package.kind.value, "files": len(manifest.files)},
    )
    db.commit()
    return {
        "digest": package.digest,
        "kind": package.kind.value,
        "total_bytes": package.total_bytes,
    }


@router.get("/packages/{digest}")
def get_package(digest: str, auth: SubmitJobs, db: DbSession):
    package = db.get(Package, digest)
    visible = package is not None and (
        service.package_owned_by(db, digest, auth.user)
        or package.approved_at is not None
        or has_permission(auth.user.role, Permission.MANAGE_JOBS)
    )
    if not visible:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="package not found")
    return {
        "digest": package.digest,
        "kind": package.kind.value,
        "approved": package.approved_at is not None,
        "manifest": package.manifest,
    }


@router.post("/admin/packages/{digest}/approve")
def approve_package(digest: str, auth: ManageJobs, request: Request, db: DbSession, now: Now):
    package = db.get(Package, digest)
    if package is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="package not found")
    try:
        service.approve(package, approver=auth.user, now=now)
    except service.PackageError as exc:
        raise _fail(exc) from None
    record_event(
        db,
        request,
        now=now,
        actor_type=ActorType.USER,
        actor_id=auth.user.id,
        action="package.approved",
        target_type="package",
        target_id=digest,
        details={"kind": package.kind.value},
    )
    db.commit()
    return {"digest": digest, "approved": True}


@router.get("/jobs/{job_id}/outputs")
def job_outputs(job_id: uuid.UUID, auth: SubmitJobs, db: DbSession):
    job = db.get(Job, job_id)
    if job is None or (
        job.owner_id != auth.user.id and not has_permission(auth.user.role, Permission.MANAGE_JOBS)
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="job not found")
    return {"job_id": str(job.id), "outputs": job.output_manifest}


# -- nodes ------------------------------------------------------------------------------------


def _assigned_job(db, node, job_id: uuid.UUID, attempt: int) -> Job:
    job = db.get(Job, job_id)
    if (
        job is None
        or job.node_id != node.id
        or job.attempt != attempt
        or job.state.value not in ("assigned", "running")
        or job.package_digest is None
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="not the current assignment")
    return job


@agent_router.get("/jobs/{job_id}/package")
def package_for_job(
    job_id: uuid.UUID,
    node: CurrentNode,
    request: Request,
    db: DbSession,
    attempt: Annotated[int, Query(ge=1)],
):
    """The manifests the node must stage: the package, its environment, its datasets."""
    _user_code_enabled(request)
    job = _assigned_job(db, node, job_id, attempt)
    package = db.get(Package, job.package_digest)
    return {"package": package.digest, "manifests": service.staging_closure(db, package)}


@agent_router.get("/blobs/{sha256}")
def node_download(
    sha256: str,
    node: CurrentNode,
    request: Request,
    db: DbSession,
    job_id: Annotated[uuid.UUID, Query(alias="job")],
    attempt: Annotated[int, Query(ge=1)],
    range_header: Annotated[str | None, Header(alias="Range")] = None,
):
    _user_code_enabled(request)
    job = db.get(Job, job_id)
    if (
        job is None
        or not _SHA.match(sha256)
        or not service.node_may_read(db, node, job, attempt, sha256)
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="blob not found for this assignment")
    blob = db.get(Blob, sha256)
    return _stream(_store(request), sha256, blob.size, range_header)


def _node_upload(request: Request, db, node, upload_id: uuid.UUID) -> BlobUpload:
    _user_code_enabled(request)
    upload = db.get(BlobUpload, upload_id)
    if upload is None or upload.node_id != node.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="upload not found")
    job = db.get(Job, upload.job_id)
    if (
        job is None
        or job.node_id != node.id
        or job.attempt != upload.attempt
        or job.state.value not in ("assigned", "running")
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, detail="upload belongs to a stale attempt")
    return upload


@agent_router.post("/blobs/uploads", response_model=UploadStatus)
def node_start_upload(
    body: UploadStart, node: CurrentNode, request: Request, db: DbSession, now: Now
):
    if body.job_id is None or body.attempt is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="job_id and attempt required")
    _user_code_enabled(request)
    job = _assigned_job(db, node, uuid.UUID(body.job_id), body.attempt)
    try:
        upload = service.begin_upload(
            db,
            _store(request),
            sha256=body.sha256,
            size=body.size,
            now=now,
            policy=_policy(request),
            node=node,
            job=job,
            attempt=body.attempt,
        )
    except service.PackageError as exc:
        raise _fail(exc) from None
    db.commit()
    return _status(upload, body.size, _policy(request))


@agent_router.get("/blobs/uploads/{upload_id}", response_model=UploadStatus)
def node_upload_status(upload_id: uuid.UUID, node: CurrentNode, request: Request, db: DbSession):
    upload = _node_upload(request, db, node, upload_id)
    return _status(upload, upload.size, _policy(request))


@agent_router.put("/blobs/uploads/{upload_id}")
async def node_put_chunk(
    upload_id: uuid.UUID,
    node: CurrentNode,
    request: Request,
    db: DbSession,
    now: Now,
    offset: Annotated[int, Query(ge=0)],
    chunk_sha: Annotated[str | None, Header(alias=CHUNK_SHA256_HEADER)] = None,
    encoding: Annotated[str, Header(alias=CHUNK_ENCODING_HEADER)] = "identity",
    raw_size: Annotated[int | None, Header(alias=CHUNK_RAW_SIZE_HEADER)] = None,
):
    upload = _node_upload(request, db, node, upload_id)
    return await _chunk(request, db, upload, offset, chunk_sha, encoding, raw_size, now)


@agent_router.post("/blobs/uploads/{upload_id}/complete")
def node_complete(
    upload_id: uuid.UUID, node: CurrentNode, request: Request, db: DbSession, now: Now
):
    upload = _node_upload(request, db, node, upload_id)
    try:
        blob = service.complete_upload(
            db, _store(request), upload, now=now, user=None, policy=_policy(request)
        )
    except service.PackageError as exc:
        db.commit()
        raise _fail(exc) from None
    db.commit()
    return {"sha256": blob.sha256, "size": blob.size}


@agent_router.put("/jobs/{job_id}/outputs", status_code=status.HTTP_204_NO_CONTENT)
def put_outputs(
    job_id: uuid.UUID, body: OutputManifest, node: CurrentNode, request: Request, db: DbSession
):
    _user_code_enabled(request)
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="not the current assignment")
    try:
        service.record_outputs(db, _store(request), node, job, body, policy=_policy(request))
    except service.PackageError as exc:
        raise _fail(exc) from None
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
