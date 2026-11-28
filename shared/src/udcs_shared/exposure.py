"""AppContainer exposure audit: what a UDCS package sandbox can still reach on a given
Windows image (ADR 0003, ADR 0001 gate 2).

The audit runs a probe *inside* a real UDCS AppContainer and records every resource it
could open: filesystem directories (list and add-file access), registry keys (read and
set-value access), other processes, named pipes, named kernel objects, network
endpoints, services, the interactive window station and the clipboard. The probe
modifies nothing: write access is tested by opening a handle with the right, never by
writing.

`violations()` is the single verdict, shared by the audit tool and the controller (which
re-judges every uploaded report rather than trusting its `passed` field). Findings that
are not violations are listed for human review: they are reachable, and an operator
must decide they are acceptable for the image.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

EXPOSURE_SCHEMA_VERSION = 1
ALLOWED_PRIVILEGES = frozenset({"SeChangeNotifyPrivilege"})


class _Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Category(StrEnum):
    FILESYSTEM = "filesystem"
    REGISTRY = "registry"
    PROCESS = "process"
    PIPE = "pipe"
    OBJECT = "object"
    NETWORK = "network"
    SERVICE = "service"
    WINDOW = "window"


class ExposureFinding(_Contract):
    """One resource the sandbox could open, and with which access."""

    category: Category
    target: str = Field(max_length=1024)
    access: str = Field(max_length=64, description="e.g. list, add_file, read, set_value, connect")
    sensitive: bool = Field(default=False, description="matches a sensitive-location rule")
    detail: str = Field(default="", max_length=300)


class ExposureReport(_Contract):
    schema_version: int = EXPOSURE_SCHEMA_VERSION
    generated_at: datetime
    hostname: str = Field(max_length=255)
    os_release: str = Field(max_length=64)
    os_version: str = Field(max_length=256)
    build: int = Field(ge=0)
    agent_version: str = Field(max_length=32)
    runner: str = Field(max_length=64, description="the identity that launched the sandbox")
    appcontainer: bool
    integrity_rid: int = Field(ge=0)
    privileges: list[str] = Field(default_factory=list, max_length=64)
    coverage: dict[str, int] = Field(default_factory=dict, description="items probed, by category")
    truncated: list[str] = Field(default_factory=list, description="categories not fully probed")
    errors: list[str] = Field(default_factory=list, max_length=200)
    findings: list[ExposureFinding] = Field(default_factory=list, max_length=200_000)

    def image(self) -> str:
        """What eligibility is bound to: the OS image the audit was taken on."""
        return image_key(self.os_release, self.os_version)


def image_key(release: str, version: str) -> str:
    return f"{release}|{version}"


# Access that is a violation wherever it is found (other than the sandbox's own grants,
# which the probe never reports).
_WRITE_ACCESS = {"add_file", "add_subdirectory", "set_value", "create_subkey"}
_PROCESS_ACCESS_VIOLATION = {"terminate", "vm_read", "vm_write", "dup_handle", "create_thread"}
# SERVICE_START on demand-start services is granted broadly by Windows itself so apps can
# trigger them (measured: dozens on a stock image). It is reported for review.
_SERVICE_ACCESS_VIOLATION = {"stop", "change_config", "write_dac"}


_SENSITIVE_REGISTRY = ("hklm\\sam\\sam", "hklm\\security")
# A real user's hive (and its _Classes hive) is HKU\S-1-5-21-<domain>-<rid>: a SID prefix,
# not a path component. Matching it as a component missed every student hive (measured
# 2026-11-28: HKU\<student>\Software, \Environment and _Classes were readable and passed).
_USER_HIVE_PREFIX = "hku\\s-1-5-21-"


def sensitive_registry(target: str) -> bool:
    """Judged here as well as in the probe, so a report whose probe mislabelled a finding
    (or was edited) is still failed by whoever re-judges it."""
    low = target.lower()
    return low.startswith(_USER_HIVE_PREFIX) or any(
        low == s or low.startswith(s + "\\") for s in _SENSITIVE_REGISTRY
    )


def finding_violation(f: ExposureFinding) -> str | None:
    """Why this one finding is a hard failure, or None if it is only for review."""
    where = f"{f.category.value} {f.target}"
    if f.category in (Category.FILESYSTEM, Category.REGISTRY) and f.access in _WRITE_ACCESS:
        return f"writable: {where} ({f.access})"
    if f.category == Category.REGISTRY and sensitive_registry(f.target):
        return f"student or account data readable: {where} ({f.access})"
    if f.category in (Category.FILESYSTEM, Category.REGISTRY) and f.sensitive:
        return f"sensitive data readable: {where} ({f.access})"
    if f.category == Category.PROCESS and f.access in _PROCESS_ACCESS_VIOLATION:
        return f"another process is controllable: {where} ({f.access})"
    if f.category == Category.NETWORK:
        return f"network reachable: {f.target}"
    if f.category == Category.SERVICE and f.access in _SERVICE_ACCESS_VIOLATION:
        return f"service controllable: {where} ({f.access})"
    if f.category == Category.WINDOW:
        return f"interactive session reachable: {where} ({f.access})"
    if f.category in (Category.PIPE, Category.OBJECT) and f.sensitive:
        return f"UDCS or credential IPC reachable: {where} ({f.access})"
    return None


def violations(report: ExposureReport) -> list[str]:
    """Hard failures. A report with any of these must never make a node eligible."""
    problems: list[str] = []
    if report.schema_version != EXPOSURE_SCHEMA_VERSION:
        problems.append(f"unsupported exposure report schema {report.schema_version}")
    if not report.appcontainer:
        problems.append("the probe did not run inside an AppContainer")
    if report.integrity_rid > 0x1000:  # above Low integrity
        problems.append(f"sandbox integrity level {report.integrity_rid:#x} is above Low")
    extra = sorted(set(report.privileges) - ALLOWED_PRIVILEGES)
    if extra:
        problems.append(f"sandbox token holds privileges: {', '.join(extra)}")
    if report.truncated:
        problems.append(f"audit incomplete for: {', '.join(sorted(report.truncated))}")
    problems += [v for f in report.findings if (v := finding_violation(f)) is not None]
    return problems


def review_items(report: ExposureReport) -> list[ExposureFinding]:
    """Reachable but not automatically a violation: for the operator to judge."""
    return [f for f in report.findings if finding_violation(f) is None]


def summary(report: ExposureReport) -> dict:
    counts: dict[str, dict[str, int]] = {}
    for f in report.findings:
        bucket = counts.setdefault(f.category.value, {})
        bucket[f.access] = bucket.get(f.access, 0) + 1
    found = violations(report)
    return {
        "passed": not found,
        "violations": found[:200],
        "violation_count": len(found),
        "reachable": counts,
        "coverage": report.coverage,
        "truncated": report.truncated,
        "image": report.image(),
        "runner": report.runner,
        "build": report.build,
    }
