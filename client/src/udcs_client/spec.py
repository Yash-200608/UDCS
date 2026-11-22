"""The researcher's project spec, `udcs.toml`, and how it maps to a package manifest.

The spec declares what the researcher means; the manifest (built by `check`) is what
is uploaded. Every table forbids unknown keys, so a typo is an error, not a silently
ignored setting.
"""

from __future__ import annotations

import json
import math
import re
import tomllib
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from udcs_shared.packages import SHA256, DatasetRef, Entry, Limits, Requirement
from udcs_shared.protection import WorkloadClass

SPEC_FILENAME = "udcs.toml"
MAX_SPEC_BYTES = 64 * 1024
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")  # as udcs_shared.packages
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^\s=<>!~;,]+)\s*$")


class SpecError(Exception):
    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProjectSection(_Strict):
    name: str

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _NAME.match(value):
            raise ValueError(
                f"{value!r}: use letters, digits, '.', '_' and '-' (up to 100), starting "
                "with a letter or digit"
            )
        return value

    version: str = Field(min_length=1, max_length=64)
    python: str = Field(default="3.12", pattern=r"^3\.[0-9]{1,2}$")
    resource_class: WorkloadClass = WorkloadClass.CPU


class EnvironmentSection(_Strict):
    digest: str | None = Field(default=None, pattern=SHA256)
    requirements: list[str] = Field(default_factory=list, max_length=500)

    @field_validator("requirements")
    @classmethod
    def _pins(cls, value: list[str]) -> list[str]:
        for item in value:
            if not _PIN.match(item):
                raise ValueError(
                    f"{item!r}: dependencies must be exact pins like 'numpy==2.1.3' "
                    "(no ranges: what runs must be what an administrator approved)"
                )
        return value


class FilesSection(_Strict):
    include: list[str] = Field(
        min_length=1,
        max_length=200,
        description="glob patterns (POSIX, ** for any depth) of the files to package",
    )
    allow_flagged: list[str] = Field(
        default_factory=list,
        max_length=200,
        description="exact paths exempt from the secret heuristic",
    )


class ProjectSpec(_Strict):
    project: ProjectSection
    entry: Entry
    environment: EnvironmentSection = Field(default_factory=EnvironmentSection)
    datasets: list[DatasetRef] = Field(default_factory=list, max_length=32)
    files: FilesSection
    limits: Limits = Field(default_factory=Limits)
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("config")
    @classmethod
    def _json_only(cls, value: dict[str, Any]) -> dict[str, Any]:
        """config becomes config.json: only JSON types (no TOML dates or times, no
        inf/nan), so what the code reads is exactly what was written."""

        def check(item: Any, where: str) -> None:
            if isinstance(item, bool | str | int):
                return
            if isinstance(item, float):
                if not math.isfinite(item):
                    raise ValueError(f"{where}: inf and nan are not JSON")
                return
            if isinstance(item, list):
                for i, element in enumerate(item):
                    check(element, f"{where}[{i}]")
                return
            if isinstance(item, dict):
                for key, element in item.items():
                    check(element, f"{where}.{key}")
                return
            raise ValueError(
                f"{where}: {type(item).__name__} values are not supported; use a string"
            )

        check(value, "config")
        return value

    def requirement_models(self) -> list[Requirement]:
        out = []
        for item in self.environment.requirements:
            name, version = _PIN.match(item).groups()
            out.append(Requirement(name=name, version=version))
        return out

    def manifest_fields(self) -> dict[str, Any]:
        """Everything in the manifest except `files` (which `check` builds)."""
        fields: dict[str, Any] = {
            "python": self.project.python,
            "entry": self.entry.model_dump(mode="json"),
            "requirements": [r.model_dump(mode="json") for r in self.requirement_models()],
            "inputs": [d.model_dump(mode="json") for d in self.datasets],
            "config": self.config,
            "limits": self.limits.model_dump(mode="json"),
        }
        if self.environment.digest:
            fields["environment"] = self.environment.digest
        return fields


def _describe(exc: ValidationError) -> list[str]:
    problems = []
    for error in exc.errors():
        where = ".".join(str(part) for part in error["loc"]) or "udcs.toml"
        problems.append(f"{where}: {error['msg']}")
    return problems


def load_spec(path: Path) -> ProjectSpec:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raise SpecError([f"{path} not found (run `udcs init`)"]) from None
    if len(raw) > MAX_SPEC_BYTES:
        raise SpecError([f"{SPEC_FILENAME} is larger than {MAX_SPEC_BYTES} bytes"])
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise SpecError([f"{SPEC_FILENAME} is not valid TOML: {exc}"]) from None
    try:
        spec = ProjectSpec.model_validate(data)
    except ValidationError as exc:
        raise SpecError(_describe(exc)) from None
    problems = []
    if spec.environment.requirements and not spec.environment.digest:
        problems.append(
            "environment.requirements need environment.digest: dependencies come only from an "
            "approved environment (run `udcs env list`, then `udcs env use NAME`)"
        )
    names = [d.name.casefold() for d in spec.datasets]
    if len(set(names)) != len(names):
        problems.append("datasets: names must be unique (case-insensitively)")
    if problems:
        raise SpecError(problems)
    return spec


def find_project(start: Path) -> Path:
    """The nearest directory, from `start` upward, that holds udcs.toml. The search
    stops at the user's home directory and at the volume root."""
    current = start.resolve()
    home = Path.home().resolve()
    while True:
        if (current / SPEC_FILENAME).is_file():
            return current
        if current == home or current.parent == current:
            raise SpecError([f"no {SPEC_FILENAME} in {start.resolve()} or above (run `udcs init`)"])
        current = current.parent


# -- writing (init, env use, dataset add) -------------------------------------------------------

_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")


def _key(key: str) -> str:
    return key if _BARE_KEY.match(key) else json.dumps(key, ensure_ascii=False)


def _value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, str):
        # JSON escapes are valid TOML; TOML also forbids a raw DEL, which JSON allows.
        return json.dumps(value, ensure_ascii=False).replace(chr(0x7F), chr(92) + "u007f")
    if isinstance(value, list):
        return "[" + ", ".join(_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{_key(k)} = {_value(v)}" for k, v in value.items()) + " }"
    raise TypeError(f"cannot write {type(value).__name__} to TOML")


def _table(header: str, data: dict[str, Any]) -> str:
    lines = [header]
    lines += [f"{_key(k)} = {_value(v)}" for k, v in data.items() if v is not None]
    return "\n".join(lines) + "\n"


HEADER = (
    "# UDCS project spec. Reference: docs/guides/researcher-client.md\n"
    "# `udcs env use` and `udcs dataset add` rewrite this file (comments are not kept).\n"
)


def render_spec(spec: ProjectSpec) -> str:
    data = spec.model_dump(mode="json", exclude_none=True)
    parts = [HEADER, _table("[project]", data["project"]), _table("[entry]", data["entry"])]
    env = data.get("environment") or {}
    if env.get("digest") or env.get("requirements"):
        parts.append(_table("[environment]", env))
    for dataset in data.get("datasets", []):
        parts.append(_table("[[datasets]]", dataset))
    parts.append(_table("[files]", data["files"]))
    parts.append(_table("[limits]", data["limits"]))
    if data.get("config"):
        parts.append(_table("[config]", data["config"]))
    return "\n".join(parts)


def write_spec(path: Path, spec: ProjectSpec) -> None:
    text = render_spec(spec)
    # Never write a file that does not read back to exactly the same spec.
    if ProjectSpec.model_validate(tomllib.loads(text)) != spec:
        raise SpecError(["udcs.toml cannot be rewritten without changing it; edit it by hand"])
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def initial_spec(name: str, entry: str) -> ProjectSpec:
    return ProjectSpec(
        project=ProjectSection(name=name, version="0.1.0"),
        entry=Entry(script=entry),
        files=FilesSection(include=["**/*.py"]),
    )
