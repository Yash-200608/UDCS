"""Agent configuration (`agent.toml` in the data directory)."""

from __future__ import annotations

import json
import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from udcs_shared.urls import url_problem

CONFIG_FILENAME = "agent.toml"
CREDENTIAL_FILENAME = "node-credential.bin"


def default_data_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "UDCS" / "agent"
    return Path("/var/lib/udcs-agent")


class ConfigError(Exception):
    pass


def validate_controller_url(url: str, *, allow_insecure_http: bool) -> str:
    problem = url_problem(url, allow_insecure_http=allow_insecure_http)
    if problem:
        raise ConfigError(problem)
    return url.rstrip("/")


@dataclass(frozen=True)
class AgentConfig:
    controller_url: str
    ca_bundle: Path | None = None
    allow_insecure_http: bool = False
    request_timeout_seconds: float = 10.0
    node_name: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "controller_url",
            validate_controller_url(
                self.controller_url, allow_insecure_http=self.allow_insecure_http
            ),
        )
        if self.ca_bundle is not None and not Path(self.ca_bundle).is_file():
            raise ConfigError(f"CA bundle not found: {self.ca_bundle}")
        if not 1 <= self.request_timeout_seconds <= 120:
            raise ConfigError("request_timeout_seconds must be between 1 and 120")


def load_config(data_dir: Path) -> AgentConfig:
    path = data_dir / CONFIG_FILENAME
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"{path} not found; run `udcs-agent enroll` first") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from None
    try:
        return AgentConfig(
            controller_url=raw["controller_url"],
            ca_bundle=Path(raw["ca_bundle"]) if raw.get("ca_bundle") else None,
            allow_insecure_http=bool(raw.get("allow_insecure_http", False)),
            request_timeout_seconds=float(raw.get("request_timeout_seconds", 10.0)),
            node_name=raw.get("node_name"),
        )
    except KeyError as exc:
        raise ConfigError(f"{path} is missing {exc.args[0]!r}") from None


def save_config(data_dir: Path, config: AgentConfig) -> Path:
    # json.dumps produces valid TOML basic strings (including Windows paths).
    lines = [
        "# UDCS node agent configuration",
        f"controller_url = {json.dumps(config.controller_url)}",
        f"allow_insecure_http = {'true' if config.allow_insecure_http else 'false'}",
        f"request_timeout_seconds = {config.request_timeout_seconds}",
    ]
    if config.ca_bundle is not None:
        lines.append(f"ca_bundle = {json.dumps(str(Path(config.ca_bundle).resolve()))}")
    if config.node_name:
        lines.append(f"node_name = {json.dumps(config.node_name)}")
    data_dir.mkdir(parents=True, exist_ok=True)
    path = data_dir / CONFIG_FILENAME
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
