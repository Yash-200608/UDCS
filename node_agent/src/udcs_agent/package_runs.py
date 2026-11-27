"""Package runs on a node (ADR 0003): from an assignment to a staged, launchable run,
and from a finished run to uploaded outputs and a PackageResult.

Order of operations, and why:
1. The closure (package, environment, datasets) comes from the controller, fenced by
   job and attempt. Every manifest must hash to the digest it is filed under, so a
   compromised or buggy controller cannot substitute different content.
2. Every blob is downloaded into the node cache and verified; staging then re-hashes
   every byte while copying it into `staging/<job>-<attempt>/`. Nothing runs before
   all of it verified.
3. The run executes in AppContainer (workloads/manager.py). Outputs are collected only
   after the whole process tree has exited (the manager waits for an empty job).
4. Outputs are copied through checked handles into an agent-private snapshot, uploaded
   in chunks as this attempt, then reported. The result names the exact output
   manifest, so the controller can tie it to this attempt's uploads.
"""

from __future__ import annotations

import logging
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path

from udcs_agent.communication.client import ControllerUnavailable, ProtocolError
from udcs_agent.packages import (
    NodeCache,
    StagedJob,
    _open_file_checked,
    collect_outputs,
    fetch_blob,
    remove_staging,
    stage_package,
    staging_dir,
)
from udcs_shared.jobs import FailureKind, PackageResult, PackageRunLimits
from udcs_shared.packages import OutputFile, OutputManifest, PackageManifest
from udcs_shared.transfer import BLOCK, TransferError, VerificationError
from udcs_shared.transfer_http import ChunkedUploader

logger = logging.getLogger(__name__)

LOG_FILES = ("stdout.txt", "stderr.txt")
LOG_PREFIX = "udcs-logs"  # reserved top-level output name: the run's stdout/stderr
LOG_TAIL_BYTES = 4 * 2**20  # per stream; the start is dropped if a run logs more
STATE_BUDGET_BYTES = 64 * 2**20  # state/, logs/ and tmp/ on top of the output limit
CHECKPOINT_FILE = "checkpoint.bin"


class RunFailed(Exception):
    """The run cannot proceed. `kind` decides whether the controller retries it."""

    def __init__(self, message: str, kind: FailureKind = FailureKind.INFRASTRUCTURE) -> None:
        super().__init__(message)
        self.kind = kind


class RetryLater(Exception):
    """A transient problem (controller unreachable): try again on the next sync."""


@dataclass(frozen=True)
class PreparedRun:
    root: Path
    entry: str
    args: list[str]
    import_paths: list[str]
    read_only: list[str]


def _closure(
    controller, job_id: uuid.UUID, attempt: int, digest: str
) -> dict[str, PackageManifest]:
    try:
        body = controller.package_closure(job_id, attempt)
    except ControllerUnavailable as exc:
        raise RetryLater(str(exc)) from exc
    except ProtocolError as exc:
        raise RunFailed(f"package unavailable: {exc}") from exc
    if not isinstance(body, dict) or body.get("package") != digest:
        raise RunFailed("controller sent a different package than was assigned")
    manifests: dict[str, PackageManifest] = {}
    for key, raw in (body.get("manifests") or {}).items():
        try:
            manifest = PackageManifest.model_validate(raw)
        except ValueError as exc:
            raise RunFailed(f"malformed manifest in closure: {str(exc)[:120]}") from exc
        if manifest.digest() != key:  # substitution: content filed under the wrong digest
            raise RunFailed(f"manifest {key[:12]} does not match its digest")
        manifests[key] = manifest
    if digest not in manifests:
        raise RunFailed("closure does not contain the assigned package")
    return manifests


def prepare(
    controller,
    data_dir: Path,
    cache: NodeCache,
    job_id: uuid.UUID,
    attempt: int,
    digest: str,
    *,
    python: str | None = None,
    platform: str | None = None,
) -> PreparedRun:
    """Fetch, verify and stage. Raises RetryLater (transient) or RunFailed."""
    manifests = _closure(controller, job_id, attempt, digest)
    # Defence in depth: the controller matched these, but this node knows what it runs.
    package = manifests[digest]
    if python is not None and package.python != python:
        raise RunFailed(f"package needs Python {package.python}; this node runs {python}")
    if package.environment:
        env = manifests.get(package.environment)
        if env is None:
            raise RunFailed("closure is missing the package's environment")
        if platform is not None and env.platform != platform:
            raise RunFailed(f"environment is built for {env.platform}; this node is {platform}")
    http = controller.transfer_http()
    params = {"job": str(job_id), "attempt": attempt}
    for manifest in manifests.values():
        for item in manifest.files:
            try:
                fetch_blob(
                    http,
                    f"/agent/blobs/{item.sha256}",
                    item.sha256,
                    item.size,
                    cache,
                    params=params,
                )
            except VerificationError as exc:
                raise RunFailed(f"package content failed verification: {exc}") from exc
            except TransferError as exc:
                raise RetryLater(f"download incomplete: {exc}") from exc
    closure = {k: v for k, v in manifests.items() if k != digest}
    try:
        staged: StagedJob = stage_package(data_dir, str(job_id), attempt, package, closure, cache)
    except VerificationError as exc:
        raise RunFailed(f"staging failed verification: {exc}") from exc
    for name in ("state", "logs", "tmp"):
        (staged.root / name).mkdir(exist_ok=True)
    import_paths = [str(staged.source)]
    if staged.environment is not None:
        import_paths.append(str(staged.environment))
    return PreparedRun(
        root=staged.root,
        entry=package.entry.script,
        args=list(package.entry.args),
        import_paths=import_paths,
        read_only=[str(p) for p in staged.read_only],
    )


def storage_budget(limits: PackageRunLimits) -> int:
    return limits.max_output_bytes + STATE_BUDGET_BYTES


def _copy_log_tail(source: Path, root: Path, target: Path) -> OutputFile | None:
    """The end of a log stream, read through a checked handle (no links, one link)."""
    import hashlib

    if not source.exists():
        return None
    digest = hashlib.sha256()
    size = 0
    with _open_file_checked(source, root) as src, open(target, "xb") as dst:
        src.seek(0, os.SEEK_END)
        length = src.tell()
        src.seek(max(0, length - LOG_TAIL_BYTES))
        while block := src.read(BLOCK):
            digest.update(block)
            dst.write(block)
            size += len(block)
    return OutputFile(path=f"{LOG_PREFIX}/{source.name}", sha256=digest.hexdigest(), size=size)


def collect(
    root: Path, attempt: int, limits: PackageRunLimits
) -> tuple[OutputManifest, dict[str, Path]]:
    """Outputs (out/) plus the run's log tails, as one manifest. A limit breach or an
    unsafe output is the package's failure, not the node's."""
    snapshot = root / "collected"
    log_snapshot = root / "collected-logs"
    for path in (snapshot, log_snapshot):
        if path.exists():
            remove_staging(path)
    log_snapshot.mkdir(parents=True)
    log_files: list[OutputFile] = []
    paths: dict[str, Path] = {}
    try:
        for name in LOG_FILES:
            item = _copy_log_tail(
                root / "logs" / name, Path(os.path.realpath(root / "logs")), log_snapshot / name
            )
            if item is not None:
                log_files.append(item)
                paths[item.path] = log_snapshot / name
    except VerificationError as exc:
        raise RunFailed(f"log files refused: {exc}", FailureKind.WORKLOAD) from exc
    log_bytes = sum(f.size for f in log_files)
    try:
        outputs, out_paths = collect_outputs(
            root / "out",
            attempt=attempt,
            snapshot_dir=snapshot,
            max_files=max(0, limits.max_output_files - len(log_files)),
            max_bytes=max(0, limits.max_output_bytes - log_bytes),
            max_entries=limits.max_output_entries,
            max_depth=limits.max_output_depth,
        )
    except VerificationError as exc:
        raise RunFailed(f"outputs refused: {exc}", FailureKind.WORKLOAD) from exc
    if any(f.path.split("/")[0].casefold() == LOG_PREFIX for f in outputs.files):
        raise RunFailed(
            f"outputs refused: {LOG_PREFIX}/ is reserved for the run's logs", FailureKind.WORKLOAD
        )
    paths.update(out_paths)
    files = sorted([*outputs.files, *log_files], key=lambda f: f.path)
    return OutputManifest(attempt=attempt, files=files), paths


def upload(controller, job_id: uuid.UUID, manifest: OutputManifest, paths: dict[str, Path]) -> None:
    """Chunked, resumable uploads as this attempt, then the manifest. A retried report
    of the same manifest (lost response) is accepted as done."""
    uploader = ChunkedUploader(
        controller.transfer_http(),
        prefix="/agent/blobs",
        extra={"job_id": str(job_id), "attempt": manifest.attempt},
    )
    for item in manifest.files:
        try:
            uploader.upload(paths[item.path], sha256=item.sha256, size=item.size)
        except VerificationError as exc:
            raise RunFailed(f"output {item.path} changed or was corrupted: {exc}") from exc
        except TransferError as exc:
            text = str(exc)
            if "HTTP 413" in text:
                raise RunFailed(
                    f"outputs exceed the limit: {text[:150]}", FailureKind.WORKLOAD
                ) from exc
            if "HTTP 409" in text:
                raise RunFailed(f"no longer the current attempt: {text[:150]}") from exc
            raise RetryLater(f"output upload interrupted: {text[:150]}") from exc
    try:
        controller.put_outputs(job_id, manifest.model_dump(mode="json"))
    except ControllerUnavailable as exc:
        raise RetryLater(str(exc)) from exc
    except ProtocolError as exc:
        if "already reported" in str(exc):
            return  # our earlier report arrived; its response was lost
        if "HTTP 413" in str(exc):
            raise RunFailed(f"outputs exceed the limit: {exc}", FailureKind.WORKLOAD) from exc
        raise RunFailed(f"outputs refused: {exc}") from exc


def finish(
    controller,
    job_id: uuid.UUID,
    root: Path,
    attempt: int,
    limits: PackageRunLimits,
    exit_code: int | None,
) -> PackageResult:
    manifest, paths = collect(root, attempt, limits)
    upload(controller, job_id, manifest, paths)
    return PackageResult(
        exit_code=exit_code,
        outputs_sha256=manifest.digest() if manifest.files else None,
        files=len(manifest.files),
        bytes=manifest.total_bytes,
    )


def log_tail(root: Path, lines: int = 20) -> list[str]:
    """The last lines of stderr (then stdout), for the job log. Read only after the
    process tree is gone; bounded and decoded defensively."""
    out: list[str] = []
    for name in ("stderr.txt", "stdout.txt"):
        path = root / "logs" / name
        try:
            with open(path, "rb") as handle:
                handle.seek(0, os.SEEK_END)
                handle.seek(max(0, handle.tell() - 16_384))
                text = handle.read().decode("utf-8", "replace")
        except OSError:
            continue
        tail = [line for line in text.splitlines() if line.strip()][-lines:]
        out += [f"{name.split('.')[0]}: {line}"[:200] for line in tail]
    return out[-lines:]


def remove_runs(data_dir: Path, job_id: str) -> None:
    """Delete every attempt's staging tree of this job (cancelled, reassigned, done)."""
    base = staging_dir(data_dir, job_id, 1).parent
    prefix = job_id.replace("-", "") + "-"
    if not base.is_dir():
        return
    for child in base.iterdir():
        if child.name.startswith(prefix):
            try:
                remove_staging(child)
            except OSError:
                logger.warning("could not remove staging %s yet", child.name, exc_info=True)


def checkpoint_path(root: Path) -> Path:
    return root / "state" / CHECKPOINT_FILE


def install_checkpoint(root: Path, payload: bytes) -> None:
    state = root / "state"
    state.mkdir(exist_ok=True)
    tmp = state / (CHECKPOINT_FILE + ".tmp")
    tmp.write_bytes(payload)
    os.replace(tmp, state / CHECKPOINT_FILE)


__all__ = [
    "CHECKPOINT_FILE",
    "LOG_PREFIX",
    "PreparedRun",
    "RetryLater",
    "RunFailed",
    "checkpoint_path",
    "collect",
    "finish",
    "install_checkpoint",
    "log_tail",
    "prepare",
    "remove_runs",
    "shutil",
    "storage_budget",
    "upload",
]
