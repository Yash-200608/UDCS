"""User-code packages on the client and the node: transfer, staging, outputs (ADR 0002).

- ChunkedUploader: content-addressed, chunked, resumable uploads with a SHA-256 per
  chunk; compression is optional and bounded on the server.
- fetch_blob: resumable, verified download into the node's local CAS cache. A blob is
  fetched once per node, however many jobs use it.
- stage_package: builds a unique tree per job and attempt from verified blobs, re-hashing
  every byte while copying. Nothing in it runs before every file has verified.
- collect_outputs: copies a job's outputs into an agent-private snapshot, opening each
  file by handle without following reparse points or accepting hard links, and
  enforcing every limit while walking.

No step installs, builds or executes anything. Running user code is a separate,
disabled step (USER_CODE_ENABLED in udcs_agent.jobs).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import stat
import sys
import zlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

import httpx

from udcs_shared.packages import (
    CHUNK_ENCODING_HEADER,
    CHUNK_RAW_SIZE_HEADER,
    CHUNK_SHA256_HEADER,
    OutputFile,
    OutputManifest,
    PackageKind,
    PackageManifest,
    canonical_json,
    path_problem,
)

logger = logging.getLogger(__name__)

_BLOCK = 1 << 20
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class TransferError(OSError):
    pass


class VerificationError(TransferError):
    """Content does not match its SHA-256. Never retried into acceptance."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while block := handle.read(_BLOCK):
            digest.update(block)
    return digest.hexdigest()


def _is_reparse(path: Path) -> bool:
    try:
        attrs = os.lstat(path).st_file_attributes  # type: ignore[attr-defined]
    except AttributeError:  # not Windows
        return os.path.islink(path)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


# -- opening files without following links ---------------------------------------------------
#
# A path check followed by an open by path is a race: a workload that can still write its
# output directory can swap a checked file or directory for a junction in between. So the
# file is opened first, without following reparse points, and the *open handle* is
# checked: it must be a regular, singly-linked file whose final path is inside the
# expected root. The bytes hashed and copied are read from that same handle.

if sys.platform == "win32":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _GENERIC_READ = 0x80000000
    _DELETE = 0x00010000
    _SHARE_ALL = 0x1 | 0x2 | 0x4
    _OPEN_EXISTING = 3
    _FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FLAG_BACKUP_SEMANTICS = 0x02000000
    _FLAG_SEQUENTIAL_SCAN = 0x08000000
    _FILE_ATTRIBUTE_DIRECTORY = 0x10
    _INVALID_HANDLE = wintypes.HANDLE(-1).value
    _FILE_DISPOSITION_INFO_EX = 21
    # DELETE | POSIX_SEMANTICS | IGNORE_READONLY_ATTRIBUTE (Windows 10 1809 and later)
    _DISPOSE_FLAGS = 0x1 | 0x2 | 0x10

    class _ByHandleInfo(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    _k32.CreateFileW.restype = wintypes.HANDLE
    _k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _k32.GetFileInformationByHandle.restype = wintypes.BOOL
    _k32.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ByHandleInfo)]
    _k32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    _k32.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _k32.SetFileInformationByHandle.restype = wintypes.BOOL
    _k32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _k32.CloseHandle.restype = wintypes.BOOL
    _k32.CloseHandle.argtypes = [wintypes.HANDLE]

    def _win_open(path: Path, access: int) -> int:
        handle = _k32.CreateFileW(
            str(path),
            access,
            _SHARE_ALL,
            None,
            _OPEN_EXISTING,
            _FLAG_OPEN_REPARSE_POINT | _FLAG_BACKUP_SEMANTICS | _FLAG_SEQUENTIAL_SCAN,
            None,
        )
        if handle in (None, _INVALID_HANDLE):
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def _win_final_path(handle: int) -> str:
        buffer = ctypes.create_unicode_buffer(32768)
        length = _k32.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not length or length >= len(buffer):
            raise ctypes.WinError(ctypes.get_last_error())
        final = buffer.value
        if final.startswith("\\\\?\\UNC\\"):
            return "\\\\" + final[8:]
        return final[4:] if final.startswith("\\\\?\\") else final

    def _open_file_checked(path: Path, root: Path):
        handle = _win_open(path, _GENERIC_READ)
        try:
            info = _ByHandleInfo()
            if not _k32.GetFileInformationByHandle(handle, ctypes.byref(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | _FILE_ATTRIBUTE_DIRECTORY):
                raise VerificationError(f"{path.name}: not a regular file")
            if info.nNumberOfLinks != 1:
                raise VerificationError(f"{path.name}: hard-linked file refused")
            if not _inside(Path(_win_final_path(handle)), root):
                raise VerificationError(f"{path.name}: resolves outside the output directory")
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            _k32.CloseHandle(handle)
            raise
        return os.fdopen(fd, "rb")

    def _delete_ignoring_readonly(path: Path) -> None:
        """Delete one file without clearing its read-only attribute first. Clearing it
        (os.chmod) would change the attribute of every hard link to the same file,
        including links whose other name is outside the staging tree."""
        handle = _win_open(path, _DELETE)
        try:
            flags = wintypes.DWORD(_DISPOSE_FLAGS)
            if not _k32.SetFileInformationByHandle(
                handle, _FILE_DISPOSITION_INFO_EX, ctypes.byref(flags), ctypes.sizeof(flags)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            _k32.CloseHandle(handle)

else:

    def _open_file_checked(path: Path, root: Path):
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise VerificationError(f"{path.name}: not a regular file")
            if info.st_nlink != 1:
                raise VerificationError(f"{path.name}: hard-linked file refused")
            if not _inside(Path(os.path.realpath(path)), root):
                raise VerificationError(f"{path.name}: resolves outside the output directory")
        except BaseException:
            os.close(fd)
            raise
        return os.fdopen(fd, "rb")

    def _delete_ignoring_readonly(path: Path) -> None:
        os.unlink(path)  # POSIX: removal depends on the directory, not the file's mode


def _inside(path: Path, root: Path) -> bool:
    try:
        common = os.path.commonpath([os.path.normcase(path), os.path.normcase(root)])
    except ValueError:  # different drives
        return False
    return common == os.path.normcase(root)


# -- upload -----------------------------------------------------------------------------------


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
        on_chunk: Callable[[int], None] | None = None,
    ) -> UploadStats:
        size = path.stat().st_size
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
                    response is not None and response.status_code in (413, 415, 422)
                ):
                    detail = response.text[:200] if response is not None else "network"
                    raise TransferError(f"chunk at {offset} failed: {detail}")
                # Interrupted: ask the server how far it really got, then continue there.
                status = self._check(self.http.get(f"{self.prefix}/uploads/{upload_id}")).json()
                offset = int(status["received"])
        done = self.http.post(f"{self.prefix}/uploads/{upload_id}/complete")
        if done.status_code == 422:
            raise VerificationError(done.text[:200])
        self._check(done)
        return stats


# -- download into the node cache -------------------------------------------------------------


class NodeCache:
    """Verified blobs on this node. Lives inside the agent's protected data directory."""

    def __init__(self, data_dir: Path) -> None:
        self.root = data_dir / "cas"
        self.root.mkdir(parents=True, exist_ok=True)

    def path(self, sha256: str) -> Path:
        return self.root / sha256[:2] / sha256

    def has(self, sha256: str) -> bool:
        return self.path(sha256).is_file()


def fetch_blob(
    http: httpx.Client,
    url: str,
    sha256: str,
    size: int,
    cache: NodeCache,
    *,
    params: dict | None = None,
    retries: int = 5,
) -> tuple[Path, int]:
    """Download (resuming a partial file with Range) and verify; returns (path, bytes
    transferred now). A cached blob costs nothing (deduplication across jobs)."""
    target = cache.path(sha256)
    if target.is_file():
        return target, 0
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(".part")
    moved = 0
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
                        for block in response.iter_bytes(_BLOCK):
                            handle.write(block)
                            moved += len(block)
                            if handle.tell() > size:
                                raise VerificationError("server sent more bytes than declared")
            except httpx.TransportError:
                continue  # resume from what arrived
        if partial.exists() and partial.stat().st_size == size:
            break
    else:
        raise TransferError(f"blob {sha256[:12]} incomplete after retries")
    if sha256_file(partial) != sha256:
        partial.unlink(missing_ok=True)
        raise VerificationError(f"blob {sha256[:12]} does not match its sha256")
    os.replace(partial, target)
    return target, moved


# -- staging ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class StagedJob:
    root: Path
    source: Path
    environment: Path | None
    inputs: dict[str, Path]
    output: Path
    config: Path
    entry: Path

    @property
    def collected(self) -> Path:
        """Agent-private copy of the outputs; the sandbox has no grant on it."""
        return self.root / "collected"

    @property
    def read_only(self) -> tuple[Path, ...]:
        """What the sandbox gets read/execute on; `output` is its only writable grant."""
        return tuple(
            p for p in (self.source, self.environment, *self.inputs.values(), self.config) if p
        )


def staging_dir(data_dir: Path, job_id: str, attempt: int) -> Path:
    return data_dir / "staging" / f"{job_id.replace('-', '')}-{attempt}"


def _copy_verified(source: Path, destination: Path, sha256: str, size: int) -> None:
    """Copy while hashing. The bytes in the staging tree are the bytes that verified, so
    a cache file modified after download is caught here."""
    digest = hashlib.sha256()
    written = 0
    with open(source, "rb") as src, open(destination, "xb") as dst:  # x: never overwrite
        while block := src.read(_BLOCK):
            digest.update(block)
            dst.write(block)
            written += len(block)
    if written != size or digest.hexdigest() != sha256:
        destination.unlink(missing_ok=True)
        raise VerificationError(f"{destination.name}: staged bytes do not match the manifest")
    os.chmod(destination, stat.S_IREAD)  # read-only attribute (defence in depth)


def _place(root: Path, files: Iterable, cache: NodeCache) -> None:
    resolved_root = root.resolve()
    for item in files:
        problem = path_problem(item.path)
        if problem:  # the manifest was validated already; this guards the node anyway
            raise VerificationError(f"unsafe path {item.path!r}: {problem}")
        destination = root.joinpath(*item.path.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.resolve().is_relative_to(resolved_root):
            raise VerificationError(f"{item.path!r} escapes the staging directory")
        if _is_reparse(destination.parent):
            raise VerificationError(f"{item.path!r}: reparse point in the staging tree")
        _copy_verified(cache.path(item.sha256), destination, item.sha256, item.size)


def stage_package(
    data_dir: Path,
    job_id: str,
    attempt: int,
    package: PackageManifest,
    closure: dict[str, PackageManifest],
    cache: NodeCache,
) -> StagedJob:
    """Build `staging/<job>-<attempt>/` from cached, verified blobs. Each attempt gets a
    fresh directory, so a stale attempt can never share files with the current one."""
    root = staging_dir(data_dir, job_id, attempt)
    if root.exists():
        remove_staging(root)
    root.mkdir(parents=True)
    try:
        if _is_reparse(root) or _is_reparse(root.parent):
            raise VerificationError("staging directory is a reparse point")
        manifests = [package, *closure.values()]
        missing = [f.sha256 for m in manifests for f in m.files if not cache.has(f.sha256)]
        if missing:
            raise VerificationError(f"{len(missing)} blobs not in the node cache")
        source = root / "src"
        source.mkdir()
        _place(source, package.files, cache)
        environment = None
        if package.environment:
            env = closure[package.environment]
            if env.kind != PackageKind.ENVIRONMENT:
                raise VerificationError("environment reference is not an environment")
            environment = root / "env"
            environment.mkdir()
            _place(environment, env.files, cache)
        inputs: dict[str, Path] = {}
        for ref in package.inputs:
            dataset = closure[ref.digest]
            if dataset.kind != PackageKind.DATASET:
                raise VerificationError(f"input {ref.name} is not a dataset")
            target = root / "inputs" / ref.name
            target.mkdir(parents=True)
            _place(target, dataset.files, cache)
            inputs[ref.name] = target
        output = root / "out"
        output.mkdir()
        config = root / "config.json"
        config.write_bytes(canonical_json(package.config))
        os.chmod(config, stat.S_IREAD)
        entry = source.joinpath(*package.entry.script.split("/"))
        return StagedJob(root, source, environment, inputs, output, config, entry)
    except BaseException:
        remove_staging(root)
        raise


def remove_staging(root: Path) -> None:
    """Delete a staging tree, including read-only files, without following reparse
    points out of it and without ever changing a file's attributes (a hard link's
    attributes are shared with every other name of the same file)."""

    def _delete_read_only(function, path, exc):
        if function not in (os.unlink, os.remove):
            raise exc
        _delete_ignoring_readonly(Path(path))

    if root.exists() and not _is_reparse(root):
        shutil.rmtree(root, onexc=_delete_read_only)
    elif root.exists():
        root.unlink()  # a reparse point itself, never its target


# -- outputs ----------------------------------------------------------------------------------


def collect_outputs(
    output_dir: Path,
    *,
    attempt: int,
    snapshot_dir: Path,
    max_files: int,
    max_bytes: int,
    max_entries: int = 20_000,
    max_depth: int = 32,
) -> tuple[OutputManifest, dict[str, Path]]:
    """Copy a job's outputs into `snapshot_dir` (agent-private) and describe them.

    Call it only after the job's process tree has been terminated, so nothing can still
    change `out/`. It does not rely on that alone:
    - every file is opened first and the open handle is checked (regular file, one
      link, final path inside `output_dir`), so a junction or hard link swapped in at
      any moment is refused, never followed;
    - the bytes hashed are the bytes copied, from that same handle, and the upload
      reads the private copy, never `out/` again;
    - files, bytes, walked entries and depth are all bounded *while walking*, so a
      hostile tree cannot make collection unbounded in time or memory.
    """
    root = Path(os.path.realpath(output_dir))
    if _is_reparse(output_dir) or not root.is_dir():
        raise VerificationError("output directory is not a plain directory")
    if snapshot_dir.exists():
        remove_staging(snapshot_dir)
    snapshot_dir.mkdir(parents=True)
    found: list[OutputFile] = []
    paths: dict[str, Path] = {}
    total = entries = 0
    stack: list[tuple[Path, int]] = [(output_dir, 0)]
    try:
        while stack:
            directory, depth = stack.pop()
            with os.scandir(directory) as listing:
                for entry in listing:
                    entries += 1
                    if entries > max_entries:
                        raise VerificationError(f"more than {max_entries} entries in outputs")
                    path = Path(entry.path)
                    relative = path.relative_to(output_dir).as_posix()
                    if path_problem(relative):
                        raise VerificationError(f"unsafe output path {relative!r}")
                    if _is_reparse(path):
                        raise VerificationError(f"output contains a reparse point: {relative}")
                    if entry.is_dir(follow_symlinks=False):
                        if depth + 1 >= max_depth:
                            raise VerificationError(f"outputs nested deeper than {max_depth}")
                        stack.append((path, depth + 1))
                        continue
                    if len(found) + 1 > max_files:
                        raise VerificationError(f"more than {max_files} output files")
                    target = snapshot_dir / f"{len(found):06d}"
                    digest = hashlib.sha256()
                    size = 0
                    with _open_file_checked(path, root) as src, open(target, "xb") as dst:
                        while block := src.read(_BLOCK):
                            size += len(block)
                            if total + size > max_bytes:
                                raise VerificationError(f"outputs exceed {max_bytes} bytes")
                            digest.update(block)
                            dst.write(block)
                    total += size
                    found.append(OutputFile(path=relative, sha256=digest.hexdigest(), size=size))
                    paths[relative] = target
    except BaseException:
        remove_staging(snapshot_dir)
        raise
    found.sort(key=lambda f: f.path)
    return OutputManifest(attempt=attempt, files=found), paths


def manifest_from_dir(
    directory: Path,
    *,
    kind: PackageKind = PackageKind.PACKAGE,
    name: str,
    version: str,
    entry: str | None = None,
    **fields,
) -> tuple[PackageManifest, dict[str, Path]]:
    """Client side: build a deterministic manifest. Symlinks and reparse points are
    refused, never followed."""
    files = []
    paths: dict[str, Path] = {}
    for root, dirs, names in os.walk(directory):
        for d in list(dirs):
            if _is_reparse(Path(root) / d):
                raise VerificationError(f"refusing symlink/reparse point {d!r}")
        for n in names:
            path = Path(root) / n
            if _is_reparse(path) or not path.is_file():
                raise VerificationError(f"refusing symlink/reparse point or special file {n!r}")
            relative = path.relative_to(directory).as_posix()
            files.append(
                {"path": relative, "sha256": sha256_file(path), "size": path.stat().st_size}
            )
            paths[relative] = path
    files.sort(key=lambda f: f["path"])
    body = {
        "schema_version": 1,
        "kind": kind.value,
        "name": name,
        "version": version,
        "files": files,
    }
    if entry is not None:
        body["entry"] = {"script": entry}
    body.update(fields)
    return PackageManifest.model_validate(json.loads(json.dumps(body))), paths
