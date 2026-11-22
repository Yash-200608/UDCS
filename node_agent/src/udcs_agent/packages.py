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
import logging
import os
import shutil
import stat
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import httpx

from udcs_shared.packages import (
    OutputFile,
    OutputManifest,
    PackageKind,
    PackageManifest,
    canonical_json,
    path_problem,
)
from udcs_shared.transfer import (
    BLOCK as _BLOCK,
)
from udcs_shared.transfer import (
    FILE_ATTRIBUTE_REPARSE_POINT,
    TransferError,
    VerificationError,
    manifest_from_dir,
    sha256_file,
)

# A module global on purpose: collect_outputs and stage_package look it up here, so a
# test can replace it to simulate a path check that a race has already defeated.
from udcs_shared.transfer import is_reparse as _is_reparse
from udcs_shared.transfer_http import ChunkedUploader, UploadStats, download_verified

__all__ = [
    "ChunkedUploader",
    "NodeCache",
    "StagedJob",
    "TransferError",
    "UploadStats",
    "VerificationError",
    "collect_outputs",
    "fetch_blob",
    "manifest_from_dir",
    "remove_staging",
    "sha256_file",
    "stage_package",
    "staging_dir",
]

logger = logging.getLogger(__name__)


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
    partial = target.with_suffix(".part")
    moved = download_verified(http, url, sha256, size, partial, params=params, retries=retries)
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
