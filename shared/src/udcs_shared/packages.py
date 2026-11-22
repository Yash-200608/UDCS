"""User-code packages: manifest format, path rules, size policy (ADR 0002).

A package is a manifest plus content-addressed files, not an archive. Each file is
uploaded as a blob named by its SHA-256, and the manifest lists `{path, sha256, size}`.
The package's identity is the SHA-256 of its canonical manifest JSON. There are no
archives to unpack, so zip-slip, archive symlinks, duplicate entries and archive
decompression bombs cannot occur. The path rules below reject everything that could
escape the staging directory on Windows.

Three kinds share the format:
- `package`: user source plus entry point, optionally referencing an environment and
  datasets.
- `environment`: an administrator-approved, prebuilt, wheel-only dependency tree with
  a lock. It is never installed or built on a node.
- `dataset`: administrator-approved input files.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MANIFEST_SCHEMA_VERSION = 1
SHA256 = r"^[0-9a-f]{64}$"

_WINDOWS_RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
    "conin$",
    "conout$",
}
_FORBIDDEN_CHARS = set('<>:"|?*\\') | {chr(c) for c in range(32)} | {"\x7f"}
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_REQUIREMENT_NAME = re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$")
_VERSION = re.compile(r"^[0-9]+(\.[0-9]+)*([a-z]+[0-9]*)?(\.post[0-9]+)?(\.dev[0-9]+)?$")


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PackageKind(StrEnum):
    PACKAGE = "package"
    ENVIRONMENT = "environment"
    DATASET = "dataset"


def path_problem(path: str, *, max_length: int = 240) -> str | None:
    """None if `path` is a safe relative file path on every platform, else why not.

    Rules: POSIX '/' separators only; NFC-normalised; no absolute paths, drives, UNC,
    ':' (alternate data streams), '.'/'..' or empty segments, control or Windows-reserved
    characters, trailing dots or spaces, or reserved device names (CON, NUL, COM1, ...
    with or without an extension)."""
    if not isinstance(path, str) or not path:
        return "empty path"
    if len(path) > max_length:
        return f"path longer than {max_length} characters"
    if unicodedata.normalize("NFC", path) != path:
        return "path is not NFC-normalised"
    if path.startswith("/") or "\\" in path:
        return "absolute path or backslash"
    if set(path) & _FORBIDDEN_CHARS:
        return 'forbidden character (control, <>:"|?*\\)'
    for segment in path.split("/"):
        if segment in ("", ".", ".."):
            return "empty, '.' or '..' segment"
        if segment != segment.rstrip(" .") or segment != segment.lstrip(" "):
            return "segment with leading space or trailing dot/space"
        if len(segment) > 100:
            return "segment longer than 100 characters"
        if segment.split(".")[0].lower() in _WINDOWS_RESERVED:
            return "Windows reserved device name"
    return None


class PackageFile(_Contract):
    path: str = Field(min_length=1, max_length=240)
    sha256: str = Field(pattern=SHA256)
    size: int = Field(ge=0)

    @field_validator("path")
    @classmethod
    def _safe(cls, value: str) -> str:
        problem = path_problem(value)
        if problem:
            raise ValueError(f"unsafe path {value!r}: {problem}")
        return value


class Requirement(_Contract):
    """An exact pin. Ranges are not accepted: what runs must be what was approved."""

    name: str = Field(max_length=100)
    version: str = Field(max_length=64)

    @field_validator("name")
    @classmethod
    def _normalised(cls, value: str) -> str:
        normalised = re.sub(r"[-_.]+", "-", value).lower()  # PEP 503
        if not _REQUIREMENT_NAME.match(normalised):
            raise ValueError(f"invalid requirement name {value!r}")
        return normalised

    @field_validator("version")
    @classmethod
    def _pinned(cls, value: str) -> str:
        if not _VERSION.match(value):
            raise ValueError(f"version must be an exact release, got {value!r}")
        return value


class Entry(_Contract):
    script: str = Field(min_length=4, max_length=240, description="a .py file in `files`")
    args: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("script")
    @classmethod
    def _python_file(cls, value: str) -> str:
        if not value.endswith(".py") or path_problem(value):
            raise ValueError("entry script must be a safe relative path to a .py file")
        return value

    @field_validator("args")
    @classmethod
    def _bounded(cls, value: list[str]) -> list[str]:
        if any(len(a) > 256 or "\x00" in a for a in value):
            raise ValueError("arguments must be at most 256 characters, without NUL")
        return value


class DatasetRef(_Contract):
    name: str = Field(description="mounted at inputs/<name>/ (read-only)")
    digest: str = Field(pattern=SHA256)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _NAME.match(value) or path_problem(value):
            raise ValueError(f"invalid dataset name {value!r}")
        return value


class Limits(_Contract):
    """Requested by the package; each is capped by the controller's PackagePolicy."""

    max_runtime_seconds: int = Field(default=3600, ge=1)
    max_output_bytes: int = Field(default=256 * 2**20, ge=0)
    max_output_files: int = Field(default=1000, ge=0)


class PackageManifest(_Contract):
    schema_version: int = Field(description="currently 1")
    kind: PackageKind
    name: str
    version: str = Field(max_length=64)
    python: str = Field(default="3.12", pattern=r"^3\.[0-9]{1,2}$")
    files: list[PackageFile] = Field(max_length=1_000_000)
    entry: Entry | None = None
    environment: str | None = Field(default=None, pattern=SHA256)
    requirements: list[Requirement] = Field(default_factory=list, max_length=500)
    lock: list[Requirement] = Field(
        default_factory=list, max_length=5000, description="environments: what they contain"
    )
    platform: str | None = Field(default=None, pattern=r"^[a-z0-9_]{1,32}$")
    inputs: list[DatasetRef] = Field(default_factory=list, max_length=32)
    config: dict[str, Any] = Field(default_factory=dict)
    limits: Limits = Field(default_factory=Limits)

    @field_validator("schema_version")
    @classmethod
    def _version(cls, value: int) -> int:
        if value != MANIFEST_SCHEMA_VERSION:
            raise ValueError(f"unsupported manifest schema_version {value}")
        return value

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _NAME.match(value):
            raise ValueError(f"invalid package name {value!r}")
        return value

    @model_validator(mode="after")
    def _structure(self) -> PackageManifest:
        paths = [f.path for f in self.files]
        if paths != sorted(paths):
            raise ValueError("files must be sorted by path (deterministic structure)")
        folded = [unicodedata.normalize("NFC", p).casefold() for p in paths]
        if len(set(folded)) != len(folded):
            raise ValueError("duplicate paths (case-insensitively, as on Windows)")
        as_dirs = {"/".join(f.split("/")[:i]) for f in folded for i in range(1, f.count("/") + 1)}
        clash = as_dirs & set(folded)
        if clash:
            raise ValueError(f"a path is both a file and a directory: {sorted(clash)[0]!r}")
        if self.kind == PackageKind.PACKAGE:
            if self.entry is None or self.entry.script not in paths:
                raise ValueError("a package needs an entry script that is one of its files")
            if self.requirements and self.environment is None:
                raise ValueError("requirements need an approved environment (no installs)")
            if self.lock or self.platform:
                raise ValueError("lock/platform belong to environments")
        elif self.entry or self.environment or self.requirements or self.inputs:
            raise ValueError(f"a {self.kind.value} has no entry, environment or inputs")
        if self.kind == PackageKind.ENVIRONMENT:
            if not self.lock or not self.platform:
                raise ValueError("an environment needs its lock and platform tag")
            if any(p.endswith(".pth") for p in folded):
                raise ValueError(".pth files are startup code hooks and are not allowed")
        names = [d.name.casefold() for d in self.inputs]
        if len(set(names)) != len(names):
            raise ValueError("duplicate dataset names")
        return self

    # -- identity ------------------------------------------------------------------------

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.model_dump(mode="json"))

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class PackagePolicy(_Contract):
    """Every size and resource limit, in one place. The controller loads it from
    configuration (UDCS_PACKAGE_POLICY, JSON) and nodes receive it, so limits are
    policy-driven and can differ per deployment without code changes."""

    max_manifest_bytes: int = Field(default=2 * 2**20, ge=1024)
    max_files: int = Field(default=10_000, ge=1)
    max_file_bytes: int = Field(default=256 * 2**20, ge=1)
    max_package_bytes: int = Field(default=1 * 2**30, ge=1, description="expanded source")
    max_transfer_bytes: int = Field(
        default=1 * 2**30, ge=1, description="compressed bytes per upload session"
    )
    max_dataset_bytes: int = Field(default=20 * 2**30, ge=1)
    max_environment_bytes: int = Field(default=4 * 2**30, ge=1)
    max_output_bytes: int = Field(default=2 * 2**30, ge=0)
    max_output_files: int = Field(default=10_000, ge=0)
    max_output_entries: int = Field(
        default=20_000, ge=1, description="files and directories walked when collecting"
    )
    max_output_depth: int = Field(default=32, ge=1)
    max_runtime_seconds: int = Field(default=8 * 3600, ge=1)
    max_config_bytes: int = Field(default=64 * 1024, ge=2)
    chunk_bytes: int = Field(default=8 * 2**20, ge=64 * 1024, le=64 * 2**20)
    max_compression_ratio: int = Field(default=100, ge=1, description="per chunk, anti-bomb")
    upload_session_hours: int = Field(default=24, ge=1)
    max_open_uploads_per_owner: int = Field(default=32, ge=1)
    user_storage_bytes: int = Field(default=50 * 2**30, ge=1, description="per user quota")

    def size_limit(self, kind: PackageKind) -> int:
        return {
            PackageKind.PACKAGE: self.max_package_bytes,
            PackageKind.DATASET: self.max_dataset_bytes,
            PackageKind.ENVIRONMENT: self.max_environment_bytes,
        }[kind]


def policy_problems(manifest: PackageManifest, policy: PackagePolicy) -> list[str]:
    """Policy checks that need the policy (the schema checks already passed)."""
    problems: list[str] = []
    if len(manifest.canonical_bytes()) > policy.max_manifest_bytes:
        problems.append("manifest too large")
    if len(manifest.files) > policy.max_files:
        problems.append(f"more than {policy.max_files} files")
    big = [f.path for f in manifest.files if f.size > policy.max_file_bytes]
    if big:
        problems.append(f"file over {policy.max_file_bytes} bytes: {big[0]}")
    limit = policy.size_limit(manifest.kind)
    if manifest.total_bytes > limit:
        problems.append(f"{manifest.kind.value} expands to more than {limit} bytes")
    if len(canonical_json(manifest.config)) > policy.max_config_bytes:
        problems.append("config too large")
    if manifest.limits.max_runtime_seconds > policy.max_runtime_seconds:
        problems.append(f"runtime limit above policy ({policy.max_runtime_seconds} s)")
    if manifest.limits.max_output_bytes > policy.max_output_bytes:
        problems.append("output limit above policy")
    if manifest.limits.max_output_files > policy.max_output_files:
        problems.append("output file count above policy")
    return problems


def environment_problems(package: PackageManifest, environment: PackageManifest) -> list[str]:
    """Is every pinned requirement exactly provided by the approved environment, and
    does the Python version match? (Native code: wheels already built for `platform`.)"""
    if environment.kind != PackageKind.ENVIRONMENT:
        return ["referenced environment is not an environment"]
    problems = []
    if environment.python != package.python:
        problems.append(
            f"package needs Python {package.python}, environment is {environment.python}"
        )
    provided = {(r.name, r.version) for r in environment.lock}
    for req in package.requirements:
        if (req.name, req.version) not in provided:
            problems.append(f"{req.name}=={req.version} is not in the approved environment")
    return problems


class OutputFile(_Contract):
    path: str = Field(min_length=1, max_length=240)
    sha256: str = Field(pattern=SHA256)
    size: int = Field(ge=0)

    @field_validator("path")
    @classmethod
    def _safe(cls, value: str) -> str:
        problem = path_problem(value)
        if problem:
            raise ValueError(f"unsafe output path {value!r}: {problem}")
        return value


class OutputManifest(_Contract):
    """What a user job produced: reported by the node, files already uploaded as blobs."""

    attempt: int = Field(ge=1)
    files: list[OutputFile] = Field(default_factory=list, max_length=100_000)

    @model_validator(mode="after")
    def _structure(self) -> OutputManifest:
        paths = [f.path for f in self.files]
        folded = [p.casefold() for p in paths]
        if paths != sorted(paths) or len(set(folded)) != len(folded):
            raise ValueError("output files must be sorted and unique")
        return self

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)


# -- transfer contracts ------------------------------------------------------------------------


class UploadStart(_Contract):
    sha256: str = Field(pattern=SHA256)
    size: int = Field(ge=0)
    job_id: str | None = Field(default=None, description="nodes: output upload for this job")
    attempt: int | None = Field(default=None, ge=1)


class UploadStatus(_Contract):
    """`upload_id` None means the caller already owns this blob: nothing to send."""

    upload_id: str | None
    received: int = Field(ge=0)
    size: int = Field(ge=0)
    chunk_bytes: int = Field(ge=1)
    state: str


CHUNK_SHA256_HEADER = "X-UDCS-Chunk-SHA256"
CHUNK_ENCODING_HEADER = "X-UDCS-Chunk-Encoding"
CHUNK_RAW_SIZE_HEADER = "X-UDCS-Chunk-Raw-Size"
