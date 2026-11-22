"""`udcs check`: everything that can be known before anything is uploaded.

Offline: the spec, the file selection, and the manifest (paths, NFC, case
collisions, file/directory clashes, entry membership: the same model the
controller uses). Online, read-only: the deployment's policy limits, the
environment (approved, same Python, every pin in its lock) and the datasets
(approved). The controller re-checks all of it at registration and stays
authoritative; this layer exists so researchers learn about problems before
waiting for an upload.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from pydantic import ValidationError

from udcs_client.api import Api
from udcs_client.output import human_bytes
from udcs_client.select import select_files
from udcs_client.spec import SPEC_FILENAME, ProjectSpec, SpecError, load_spec
from udcs_shared.packages import (
    PackageKind,
    PackageManifest,
    environment_problems,
    policy_problems,
)
from udcs_shared.transfer import TransferError, manifest_from_files

MANY_FILES = 1000  # measured: about 13.5 small files/s per upload (ADR 0002)


@dataclass
class Report:
    project: Path
    spec: ProjectSpec | None = None
    manifest: PackageManifest | None = None
    paths: dict[str, Path] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    excluded: dict[str, int] = field(default_factory=dict)
    user_code_enabled: bool | None = None

    @property
    def ok(self) -> bool:
        return not self.problems and self.manifest is not None

    def largest(self, count: int = 5) -> list[tuple[str, int]]:
        if self.manifest is None:
            return []
        files = sorted(self.manifest.files, key=lambda f: f.size, reverse=True)[:count]
        return [(f.path, f.size) for f in files]


def _manifest_error(exc: ValidationError) -> list[str]:
    out = []
    for error in exc.errors():
        where = ".".join(str(p) for p in error["loc"])
        out.append(f"manifest {where}: {error['msg']}" if where else f"manifest: {error['msg']}")
    return out


def check_offline(project: Path) -> Report:
    report = Report(project=project)
    try:
        report.spec = load_spec(project / SPEC_FILENAME)
    except SpecError as exc:
        report.problems += exc.problems
        return report
    spec = report.spec
    selection = select_files(project, spec.files.include, spec.files.allow_flagged)
    report.problems += selection.problems
    report.warnings += selection.warnings
    report.excluded = dict(selection.excluded)
    for flagged in selection.flagged:
        report.problems.append(
            f"{flagged} (heuristic, not a guarantee). Remove the secret, or list the path "
            "in files.allow_flagged if it is a false positive"
        )
    if report.problems:
        return report
    selected = {rel.casefold() for rel, _ in selection.files}
    if spec.entry.script.casefold() not in selected:
        report.problems.append(
            f"entry.script {spec.entry.script!r} is not among the selected files "
            "(check files.include)"
        )
        return report
    try:
        report.manifest, report.paths = manifest_from_files(
            selection.files,
            kind=PackageKind.PACKAGE,
            name=spec.project.name,
            version=spec.project.version,
            **spec.manifest_fields(),
        )
    except ValidationError as exc:
        report.problems += _manifest_error(exc)
    except TransferError as exc:
        report.problems.append(str(exc))
    if report.manifest is not None and len(report.manifest.files) > MANY_FILES:
        report.warnings.append(
            f"{len(report.manifest.files)} files: uploads run at roughly 13 small files per "
            "second; consider packaging large data as a dataset (`udcs dataset push`)"
        )
    return report


def check_online(report: Report, api: Api) -> Report:
    """Read-only checks against the deployment. Never writes to the server."""
    if report.manifest is None:
        return report
    manifest = report.manifest
    policy = api.policy()
    for problem in policy_problems(manifest, policy):
        if "expands to more than" not in problem:  # reported below, with the largest files
            report.problems.append(f"policy: {problem}")
    if manifest.total_bytes > policy.max_package_bytes:
        biggest = ", ".join(f"{p} ({human_bytes(s)})" for p, s in report.largest())
        report.problems.append(
            f"the package is {human_bytes(manifest.total_bytes)}, above this deployment's "
            f"{human_bytes(policy.max_package_bytes)}. Largest files: {biggest}. Large data "
            "belongs in a dataset (`udcs dataset push`)"
        )
    if manifest.environment:
        env = api.package(manifest.environment)
        if env is None or env.get("kind") != "environment" or not env.get("approved"):
            report.problems.append(
                "environment.digest is not an approved environment on this deployment "
                "(see `udcs env list`)"
            )
        else:
            env_manifest = PackageManifest.model_validate(env["manifest"])
            for problem in environment_problems(manifest, env_manifest):
                report.problems.append(f"environment: {problem}")
            locked = {r.name: r.version for r in env_manifest.lock}
            for req in manifest.requirements:
                if locked.get(req.name) not in (None, req.version):
                    report.problems.append(
                        f"environment: {req.name}=={req.version} is not in it; "
                        f"it provides {req.name}=={locked[req.name]}"
                    )
    for dataset in manifest.inputs:
        row = api.package(dataset.digest)
        if row is None or row.get("kind") != "dataset" or not row.get("approved"):
            report.problems.append(
                f"dataset {dataset.name!r} is not an approved dataset on this deployment "
                "(see `udcs dataset list`)"
            )
    report.user_code_enabled = bool(api.deployment().get("user_code_enabled"))
    if not report.user_code_enabled:
        report.notices.append(
            "running user code is turned off on this deployment; `udcs submit` will upload "
            "and register the package but create no job"
        )
    # De-duplicate while keeping order (policy and the explicit checks may overlap).
    report.problems = list(dict.fromkeys(report.problems))
    return report
