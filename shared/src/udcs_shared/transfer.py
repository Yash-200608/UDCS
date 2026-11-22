"""Content-addressed transfer primitives that need only the standard library (ADR 0002).

Shared by the node agent and the researcher client, so both hash, refuse links and
build manifests in exactly one way. HTTP transfer lives in `udcs_shared.transfer_http`
(the optional `http` extra), so the controller does not depend on an HTTP client.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from pathlib import Path

from udcs_shared.packages import PackageKind, PackageManifest

BLOCK = 1 << 20
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class TransferError(OSError):
    pass


class VerificationError(TransferError):
    """Content does not match its SHA-256, or a path is unsafe. Never retried into
    acceptance."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while block := handle.read(BLOCK):
            digest.update(block)
    return digest.hexdigest()


def is_reparse(path: Path) -> bool:
    """True for symlinks, junctions and any other reparse point (never followed).
    A path that does not exist is not a link."""
    try:
        attrs = os.lstat(path).st_file_attributes  # type: ignore[attr-defined]
    except FileNotFoundError:
        return False
    except AttributeError:  # not Windows
        return os.path.islink(path)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def manifest_from_files(
    entries: Iterable[tuple[str, Path]],
    *,
    kind: PackageKind = PackageKind.PACKAGE,
    name: str,
    version: str,
    entry: str | dict | None = None,
    **fields,
) -> tuple[PackageManifest, dict[str, Path]]:
    """Build a deterministic manifest from (relative POSIX path, local file) pairs.
    Every file is hashed here; a link or special file is refused, never followed.
    Validation (paths, NFC, case, clashes, entry membership) is the manifest model's."""
    files = []
    paths: dict[str, Path] = {}
    for relative, path in entries:
        if is_reparse(path) or not path.is_file():
            raise VerificationError(f"refusing symlink/reparse point or special file {relative!r}")
        files.append({"path": relative, "sha256": sha256_file(path), "size": path.stat().st_size})
        paths[relative] = path
    files.sort(key=lambda f: f["path"])
    body = {
        "schema_version": 1,
        "kind": kind.value,
        "name": name,
        "version": version,
        "files": files,
    }
    if entry is not None:  # a script path, or {"script": ..., "args": [...]}
        body["entry"] = {"script": entry} if isinstance(entry, str) else entry
    body.update(fields)
    return PackageManifest.model_validate(json.loads(json.dumps(body))), paths


def manifest_from_dir(
    directory: Path,
    *,
    kind: PackageKind = PackageKind.PACKAGE,
    name: str,
    version: str,
    entry: str | None = None,
    **fields,
) -> tuple[PackageManifest, dict[str, Path]]:
    """Every file under `directory`. Symlinks and reparse points are refused."""
    entries: list[tuple[str, Path]] = []
    for root, dirs, names in os.walk(directory):
        for d in list(dirs):
            if is_reparse(Path(root) / d):
                raise VerificationError(f"refusing symlink/reparse point {d!r}")
        for n in names:
            path = Path(root) / n
            entries.append((path.relative_to(directory).as_posix(), path))
    return manifest_from_files(
        entries, kind=kind, name=name, version=version, entry=entry, **fields
    )
