"""`udcs fetch`: download a job's outputs and prove they are intact.

The output manifest comes from the controller, which got it from a node. Both are
treated as untrusted when writing to the researcher's disk:
- paths are validated by the shared model (no traversal, drives, devices, streams,
  non-NFC, case collisions, file/directory clashes) and again on the filesystem:
  every directory is created one segment at a time and must not be a link;
- every file is downloaded to a partial file, hashed in full, and only then put in
  place, never overwriting anything; more bytes than declared are refused;
- client-side limits bound the number of files and total bytes.

What "verified" means, honestly: the bytes on disk are the bytes the node reported.
It does not prove the node computed them correctly (threat T26).
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from udcs_client.api import Api
from udcs_client.output import ClientError, Exit
from udcs_shared.jobs import JobResult, expected_checksum
from udcs_shared.packages import OutputManifest, canonical_json
from udcs_shared.transfer import TransferError, VerificationError, is_reparse, sha256_file
from udcs_shared.transfer_http import download_verified, place_new

MAX_OUTPUT_FILES = 100_000
# The client's own bound, whatever the controller says: a compromised controller
# cannot make a fetch fill the disk beyond this (override with --max-bytes).
CLIENT_MAX_BYTES = 20 * 2**30
PARTIAL_DIR = ".udcs-partial"
RECEIPT = "udcs-receipt.json"
MARKER = "fetch.json"
RESERVED = {PARTIAL_DIR, RECEIPT}  # top-level names the client itself writes


@dataclass
class FetchReport:
    files: int = 0
    downloaded_bytes: int = 0
    skipped: int = 0
    target: Path | None = None


def _inside(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath([os.path.normcase(path), os.path.normcase(root)]) == (
            os.path.normcase(root)
        )
    except ValueError:
        return False


def _safe_parent(root: Path, relative: str) -> Path:
    """Create the directories for `relative` under `root`, one segment at a time,
    refusing any segment that is a link, a junction or not a directory."""
    current = root
    for segment in relative.split("/")[:-1]:
        current = current / segment
        if current.exists() or is_reparse(current):
            if is_reparse(current) or not current.is_dir():
                raise ClientError(
                    f"{current} exists and is not a plain directory; refusing to write there",
                    Exit.VERIFICATION,
                )
        else:
            current.mkdir()
    resolved = Path(os.path.realpath(current))
    if not _inside(resolved, root):
        raise ClientError(f"{relative!r} resolves outside {root}", Exit.VERIFICATION)
    return current


def _prepare_target(target: Path, *, resume: bool) -> Path:
    if is_reparse(target):
        raise ClientError(f"{target} is a link or junction; choose another directory", Exit.USAGE)
    if target.exists():
        if not target.is_dir():
            raise ClientError(f"{target} exists and is not a directory", Exit.USAGE)
        if any(target.iterdir()) and not resume:
            raise ClientError(
                f"{target} is not empty; use --resume to continue an earlier fetch, "
                "or choose another directory with -o",
                Exit.USAGE,
            )
    else:
        target.mkdir(parents=True)
    return Path(os.path.realpath(target))


def binding(job: dict, manifest: OutputManifest) -> dict:
    """What a fetch directory holds: --resume continues only the same job, attempt and
    output manifest, never another fetch's files."""
    return {
        "job_id": job["id"],
        "attempt": manifest.attempt,
        "outputs_sha256": hashlib.sha256(
            canonical_json(manifest.model_dump(mode="json"))
        ).hexdigest(),
    }


def _bound_to(root: Path, expected: dict) -> bool:
    for path in (root / PARTIAL_DIR / MARKER, root / RECEIPT):
        if path.is_file() and not is_reparse(path):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            stored = data.get("binding", data)
            if all(stored.get(k) == v for k, v in expected.items()):
                return True
    return False


def check_outputs(manifest: OutputManifest, job: dict, *, max_bytes: int) -> None:
    for item in manifest.files:
        if item.path.split("/")[0].casefold() in {r.casefold() for r in RESERVED}:
            raise ClientError(
                f"output {item.path!r} uses a name the client reserves for itself",
                Exit.VERIFICATION,
            )
    if manifest.attempt != job["attempt"]:
        raise ClientError(
            f"the outputs belong to attempt {manifest.attempt}, but the job is on attempt "
            f"{job['attempt']}; refusing a mixed result",
            Exit.VERIFICATION,
        )
    if len(manifest.files) > MAX_OUTPUT_FILES:
        raise ClientError(f"more than {MAX_OUTPUT_FILES} output files", Exit.VERIFICATION)
    if manifest.total_bytes > max_bytes:
        raise ClientError(
            f"the outputs declare {manifest.total_bytes} bytes, above the output limit of "
            f"{max_bytes} (the deployment's, or this client's --max-bytes)",
            Exit.VERIFICATION,
        )


def fetch_outputs(
    api: Api,
    http: httpx.Client,
    job: dict,
    manifest: OutputManifest,
    target: Path,
    *,
    resume: bool,
    max_bytes: int,
) -> FetchReport:
    check_outputs(manifest, job, max_bytes=max_bytes)
    fresh = not target.exists() or not any(target.iterdir())
    root = _prepare_target(target, resume=resume)
    expected = binding(job, manifest)
    if not fresh and not _bound_to(root, expected):
        raise ClientError(
            f"{root} holds a different fetch (another job, attempt or output set); "
            "--resume only continues the same one. Choose another directory with -o",
            Exit.USAGE,
        )
    free = shutil.disk_usage(root).free
    if manifest.total_bytes > free:
        raise ClientError(
            f"the outputs need {manifest.total_bytes} bytes; only {free} are free on {root}",
            Exit.USAGE,
        )
    partials = root / PARTIAL_DIR
    if is_reparse(partials) or (partials.exists() and not partials.is_dir()):
        raise ClientError(f"{partials} is not a plain directory; refusing", Exit.VERIFICATION)
    partials.mkdir(exist_ok=True)
    (partials / MARKER).write_text(json.dumps(expected), encoding="utf-8")
    report = FetchReport(target=root)
    for item in manifest.files:
        parent = _safe_parent(root, item.path)
        destination = parent / item.path.split("/")[-1]
        if destination.exists() or is_reparse(destination):
            if is_reparse(destination) or not destination.is_file():
                raise ClientError(f"{destination} is not a plain file", Exit.VERIFICATION)
            if sha256_file(destination) != item.sha256:
                raise ClientError(
                    f"{destination} already exists with different content; not overwritten",
                    Exit.VERIFICATION,
                )
            report.skipped += 1
            report.files += 1
            continue
        # Named by content: a resumed partial always continues the same bytes.
        partial = partials / f"{item.sha256}-{item.size}"
        try:
            report.downloaded_bytes += download_verified(
                http, f"/blobs/{item.sha256}", item.sha256, item.size, partial
            )
        except VerificationError as exc:
            raise ClientError(f"{item.path}: {exc}", Exit.VERIFICATION) from None
        except TransferError as exc:
            raise ClientError(f"{item.path}: {exc}") from None
        try:
            place_new(partial, destination)
        except FileExistsError:
            raise ClientError(f"{destination} appeared while fetching; not overwritten") from None
        report.files += 1
    shutil.rmtree(partials, ignore_errors=True)
    receipt = {
        "binding": expected,
        "job_id": job["id"],
        "attempt": manifest.attempt,
        "package": job.get("package"),
        "outputs": manifest.model_dump(mode="json"),
        "fetched_at": datetime.now(UTC).isoformat(),
        "meaning": "every file matches the SHA-256 the node reported; this proves the "
        "download is intact, not that the node computed it correctly",
    }
    receipt_path = root / RECEIPT
    receipt_path.write_text(json.dumps(receipt, indent=1), encoding="utf-8")
    return report


def verify_catalog_result(job: dict, result: dict) -> tuple[bool, str]:
    """Re-check a catalog job's checksum locally instead of trusting `verified`."""
    parsed = JobResult.model_validate(result["result"])
    if parsed.units != job["total_units"]:
        return False, f"{parsed.units} units reported, {job['total_units']} submitted"
    expected = expected_checksum(job["total_units"])
    if int(parsed.checksum) != expected:
        return False, f"checksum {parsed.checksum} != expected {expected}"
    return True, f"checksum {parsed.checksum} matches the closed form for {parsed.units} units"
