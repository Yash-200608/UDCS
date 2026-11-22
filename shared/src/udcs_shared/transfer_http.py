"""Chunked, resumable, verified HTTP transfer (ADR 0002). Needs the `http` extra.

- ChunkedUploader: content-addressed uploads with a SHA-256 per chunk; compression is
  optional and bounded on the server.
- download_verified: Range-resumable download that hashes the whole file before it
  is put in place, and never accepts more bytes than declared.
"""

from __future__ import annotations

import hashlib
import os
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx

from udcs_shared.packages import CHUNK_ENCODING_HEADER, CHUNK_RAW_SIZE_HEADER, CHUNK_SHA256_HEADER
from udcs_shared.transfer import BLOCK, TransferError, VerificationError, sha256_file


@dataclass
class UploadStats:
    sha256: str
    size: int
    sent_bytes: int = 0
    skipped: bool = False
    resumed_from: int = 0


class ChunkedUploader:
    """`prefix` is "/blobs" (users) or "/agent/blobs" (nodes; `extra` names the job and
    attempt, so output uploads are fenced like every other node write)."""

    def __init__(
        self,
        http: httpx.Client,
        *,
        prefix: str = "/blobs",
        extra: dict | None = None,
        compress: bool = True,
        retries: int = 5,
    ) -> None:
        self.http = http
        self.prefix = prefix
        self.extra = extra or {}
        self.compress = compress
        self.retries = retries

    @staticmethod
    def _check(response: httpx.Response) -> httpx.Response:
        if response.status_code >= 400:
            raise TransferError(f"HTTP {response.status_code}: {response.text[:200]}")
        return response

    def upload(
        self,
        path: Path,
        *,
        sha256: str | None = None,
        size: int | None = None,
        on_chunk: Callable[[int], None] | None = None,
    ) -> UploadStats:
        """`sha256`/`size` are what the manifest recorded. If the file changed since,
        the server's whole-file hash at `complete` refuses it (VerificationError)."""
        size = path.stat().st_size if size is None else size
        sha256 = sha256 or sha256_file(path)
        stats = UploadStats(sha256=sha256, size=size)
        start = self._check(
            self.http.post(
                f"{self.prefix}/uploads", json={"sha256": sha256, "size": size, **self.extra}
            )
        ).json()
        if start["upload_id"] is None:
            stats.skipped = True  # already ours: no bytes need to move
            return stats
        upload_id, chunk = start["upload_id"], int(start["chunk_bytes"])
        offset = stats.resumed_from = int(start["received"])
        failures = 0
        with open(path, "rb") as handle:
            while offset < size:
                handle.seek(offset)
                raw = handle.read(min(chunk, size - offset))
                if not raw:
                    raise VerificationError(f"{path.name} changed during upload (shorter)")
                body, encoding = raw, "identity"
                if self.compress:
                    packed = zlib.compress(raw, 6)
                    if len(packed) < len(raw) * 0.9:
                        body, encoding = packed, "zlib"
                headers = {
                    CHUNK_SHA256_HEADER: hashlib.sha256(raw).hexdigest(),
                    CHUNK_ENCODING_HEADER: encoding,
                    CHUNK_RAW_SIZE_HEADER: str(len(raw)),
                }
                try:
                    response = self.http.put(
                        f"{self.prefix}/uploads/{upload_id}",
                        params={"offset": offset},
                        content=body,
                        headers=headers,
                    )
                except httpx.TransportError:
                    response = None
                if response is not None and response.status_code < 400:
                    offset = int(response.json()["received"])
                    stats.sent_bytes += len(body)
                    failures = 0
                    if on_chunk:
                        on_chunk(offset)
                    continue
                failures += 1
                if failures > self.retries or (
                    response is not None and response.status_code in (401, 403, 409, 413, 415, 422)
                ):
                    detail = response.text[:200] if response is not None else "network"
                    raise TransferError(f"chunk at {offset} failed: {detail}")
                # Interrupted: ask the server how far it really got, then continue there.
                status = self._check(self.http.get(f"{self.prefix}/uploads/{upload_id}")).json()
                offset = int(status["received"])
        done = self.http.post(f"{self.prefix}/uploads/{upload_id}/complete")
        if done.status_code == 422:
            raise VerificationError(
                f"{path.name} changed during upload, or was corrupted: {done.text[:200]}"
            )
        self._check(done)
        return stats


def download_verified(
    http: httpx.Client,
    url: str,
    sha256: str,
    size: int,
    partial: Path,
    *,
    params: dict | None = None,
    retries: int = 5,
) -> int:
    """Download into `partial` (resuming from its current length with Range) and verify
    the whole file. Returns bytes transferred now. On a mismatch the partial file is
    deleted and VerificationError raised; the caller puts a verified file in place."""
    partial.parent.mkdir(parents=True, exist_ok=True)
    moved = 0
    if size == 0:
        partial.write_bytes(b"")  # nothing to transfer; the hash below still checks it
    for _ in range(retries + 1):
        have = partial.stat().st_size if partial.exists() else 0
        if have > size:
            partial.unlink()
            have = 0
        if have < size:
            headers = {"Range": f"bytes={have}-"} if have else {}
            try:
                with http.stream("GET", url, params=params, headers=headers) as response:
                    if response.status_code not in (200, 206):
                        raise TransferError(f"HTTP {response.status_code} for blob {sha256[:12]}")
                    mode = "ab" if response.status_code == 206 else "wb"
                    with open(partial, mode) as handle:
                        for block in response.iter_bytes(BLOCK):
                            if handle.tell() + len(block) > size:
                                handle.close()
                                partial.unlink(missing_ok=True)
                                raise VerificationError("server sent more bytes than declared")
                            handle.write(block)
                            moved += len(block)
            except httpx.TransportError:
                continue  # resume from what arrived
        if partial.exists() and partial.stat().st_size == size:
            break
    else:
        raise TransferError(f"blob {sha256[:12]} incomplete after retries")
    if sha256_file(partial) != sha256:
        partial.unlink(missing_ok=True)
        raise VerificationError(f"blob {sha256[:12]} does not match its sha256")
    return moved


def place_new(source: Path, target: Path) -> None:
    """Move a verified file into place, never overwriting an existing file."""
    try:
        os.link(source, target)  # atomic, and fails if target exists
    except FileExistsError:
        raise
    except OSError:
        # No hard links here (e.g. FAT/exFAT). Windows rename never replaces an existing
        # file; elsewhere hard links are always available, so this branch is Windows-only
        # in practice. Either way no truncated target is ever left behind.
        if os.name != "nt":
            raise
        os.rename(source, target)
        return
    source.unlink()
