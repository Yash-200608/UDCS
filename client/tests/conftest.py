"""Client tests drive the real controller in-process: `udcs_client.cli.main` gets an
http factory that returns a TestClient bound to https://testserver, so every request
goes through the real routes, auth, validation and database."""

from __future__ import annotations

import hashlib
import io
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from udcs_client import cli
from udcs_client.session import bind
from udcs_controller.auth.permissions import Role
from udcs_controller.auth.service import create_user
from udcs_controller.config import Settings
from udcs_controller.database.migrate import upgrade_to_head
from udcs_controller.main import create_app
from udcs_shared.agent_api import PROTOCOL_VERSION
from udcs_shared.hardware import (
    CpuInfo,
    HardwareInventory,
    IsolationCapability,
    MemoryInfo,
    OsInfo,
)
from udcs_shared.packages import CHUNK_RAW_SIZE_HEADER, CHUNK_SHA256_HEADER

PASSWORD = "correct-horse-battery"
SERVER = "https://testserver"
API = "/api/v1"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch) -> Path:
    directory = tmp_path / "udcs-config"
    monkeypatch.setenv("UDCS_CONFIG_DIR", str(directory))
    for name in ("UDCS_TOKEN", "UDCS_SERVER", "UDCS_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)
    return directory


@pytest.fixture
def app(tmp_path) -> Iterator[FastAPI]:
    settings = Settings(
        database_url=f"sqlite:///{(tmp_path / 'udcs.db').as_posix()}",
        log_json=False,
        blob_dir=str(tmp_path / "blobs"),
    )
    application = create_app(settings)
    upgrade_to_head(application.state.engine)
    with application.state.sessionmaker() as db:
        for username, role in (
            ("admin", Role.ADMIN),
            ("ada", Role.RESEARCHER),
            ("bob", Role.RESEARCHER),
        ):
            create_user(
                db, username=username, display_name=username.title(), password=PASSWORD, role=role
            )
        db.commit()
    yield application
    application.state.engine.dispose()


def set_user_code(app: FastAPI, enabled: bool) -> None:
    app.state.settings = app.state.settings.model_copy(update={"user_code_enabled": enabled})


@dataclass
class Run:
    code: int
    out: str
    err: str


@dataclass
class Cli:
    app: FastAPI
    requests: list[tuple[str, str]] = field(default_factory=list)
    sleeps: list[float] = field(default_factory=list)

    def factory(self, server: str, ca_bundle: str | None, token: str | None) -> httpx.Client:
        http = TestClient(self.app, base_url=server + API)

        def record(request: httpx.Request) -> None:
            self.requests.append((request.method, request.url.path))

        http.event_hooks["request"] = [record]
        return bind(http, server, token)

    def __call__(self, *argv: str, answers: tuple[str, ...] = (), password: str = PASSWORD) -> Run:
        out, err = io.StringIO(), io.StringIO()
        queue = list(answers)
        code = cli.main(
            ["--server", SERVER, *argv],
            http_factory=self.factory,
            out=out,
            err=err,
            sleep=self.sleeps.append,
            ask=lambda _prompt: queue.pop(0) if queue else "",
            ask_secret=lambda _prompt: password,
        )
        return Run(code, out.getvalue(), err.getvalue())

    def sent(self, method: str, suffix: str) -> int:
        return sum(1 for m, p in self.requests if m == method and p.endswith(suffix))


@pytest.fixture
def run(app) -> Cli:
    return Cli(app)


@pytest.fixture
def logged_in(run) -> Cli:
    result = run("login", "--username", "ada")
    assert result.code == 0, result.err
    return run


# -- direct API helpers (administrator actions and a simulated node) ----------------------------


def api_client(app: FastAPI, username: str) -> TestClient:
    http = TestClient(app, base_url=SERVER + API)
    token = http.post("/auth/login", json={"username": username, "password": PASSWORD}).json()
    http.headers["Authorization"] = f"Bearer {token['access_token']}"
    return http


def upload(http: TestClient, data: bytes, prefix: str = "/blobs", extra: dict | None = None):
    start = http.post(
        f"{prefix}/uploads", json={"sha256": sha(data), "size": len(data), **(extra or {})}
    )
    assert start.status_code == 200, start.text
    uid = start.json()["upload_id"]
    if uid is None:
        return
    if data:
        put = http.put(
            f"{prefix}/uploads/{uid}",
            params={"offset": 0},
            content=data,
            headers={CHUNK_SHA256_HEADER: sha(data), CHUNK_RAW_SIZE_HEADER: str(len(data))},
        )
        assert put.status_code == 200, put.text
    done = http.post(f"{prefix}/uploads/{uid}/complete")
    assert done.status_code == 200, done.text


@pytest.fixture
def approved(app) -> Callable[..., str]:
    """Register and approve an environment or dataset as the administrator."""
    admin = api_client(app, "admin")

    def _make(kind: str, name: str, version: str = "1", **fields) -> str:
        payload = f"{kind}:{name}:{version}".encode()
        upload(admin, payload)
        body = {
            "schema_version": 1,
            "kind": kind,
            "name": name,
            "version": version,
            "files": [{"path": "README.txt", "sha256": sha(payload), "size": len(payload)}],
            **fields,
        }
        made = admin.post("/packages", json=body)
        assert made.status_code == 201, made.text
        digest = made.json()["digest"]
        assert admin.post(f"/admin/packages/{digest}/approve").status_code == 200
        return digest

    return _make


@pytest.fixture
def environment(approved) -> str:
    return approved(
        "environment",
        "sci-py312",
        "2026.11",
        python="3.12",
        platform="win_amd64",
        lock=[{"name": "numpy", "version": "2.1.3"}, {"name": "scipy", "version": "1.14.1"}],
    )


def write_project(root: Path, files: dict[str, bytes | str], spec: str) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode() if isinstance(content, str) else content)
    (root / "udcs.toml").write_text(spec, encoding="utf-8")
    return root


SPEC = """
[project]
name = "demo"
version = "1.0"
python = "3.12"

[entry]
script = "main.py"

[files]
include = ["**/*.py"]
"""


@pytest.fixture
def project(tmp_path) -> Path:
    return write_project(
        tmp_path / "proj", {"main.py": "print('hi')\n", "lib/util.py": "X = 1\n"}, SPEC
    )


class SimulatedNode:
    """Takes a package job and reports outputs through the real node API. It executes
    nothing: it is how the client is tested in-process. It reports a verified
    AppContainer, and an administrator makes it eligible through the real endpoint."""

    def __init__(self, app: FastAPI, *, eligible: bool = True) -> None:
        admin = api_client(app, "admin")
        key = admin.post(
            "/admin/enrollment-keys",
            json={"lab": "L", "ttl_minutes": 60, "max_uses": 1, "auto_approve": True, "note": "t"},
        )
        assert key.status_code == 201, key.text
        inventory = HardwareInventory(
            agent_version="0.1.0",
            os=OsInfo(system="Windows", release="11", version="10.0.22631", hostname="sim"),
            cpu=CpuInfo(
                model="x",
                architecture="AMD64",
                physical_cores=4,
                logical_cores=8,
                max_frequency_mhz=3000.0,
            ),
            memory=MemoryInfo(total_bytes=16 * 2**30),
            network_interfaces=[],
            gpus=[],
            isolation=[IsolationCapability(name="appcontainer", available=True, verified=True)],
        )
        self.http = TestClient(app, base_url=SERVER + API)
        enrolled = self.http.post(
            "/agent/enroll",
            json={
                "enrollment_token": key.json()["key"],
                "protocol_version": PROTOCOL_VERSION,
                "inventory": inventory.model_dump(mode="json"),
            },
        )
        assert enrolled.status_code == 201, enrolled.text
        self.http.headers["Authorization"] = f"Bearer {enrolled.json()['node_credential']}"
        self.node_id = enrolled.json()["node_id"]
        if eligible:
            made = admin.post(
                f"/admin/nodes/{self.node_id}/user-code",
                json={"allowed": True, "reason": "test node"},
            )
            assert made.status_code == 200, made.text
        self.outputs: dict | None = None

    def _sync(self, reports: list[dict], *, accept: bool) -> dict:
        body = {
            "protocol_version": PROTOCOL_VERSION,
            "reports": reports,
            "capacity": {
                "accept": accept,
                "slots": 1 if accept else 0,
                "kinds": ["cpu"] if accept else [],
                "memory_available_mb": 4096,
                "user_code": True,
                "python": "3.12",
                "platform": "win_amd64",
            },
        }
        response = self.http.post("/agent/jobs/sync", json=body)
        assert response.status_code == 200, response.text
        return response.json()

    def take(self) -> dict:
        [assignment] = self._sync([], accept=True)["assignments"]
        return assignment

    def report_outputs(self, job_id: str, attempt: int, files: dict[str, bytes]) -> None:
        for data in files.values():
            upload(self.http, data, "/agent/blobs", {"job_id": job_id, "attempt": attempt})
        manifest = {
            "attempt": attempt,
            "files": [
                {"path": p, "sha256": sha(d), "size": len(d)} for p, d in sorted(files.items())
            ],
        }
        done = self.http.put(f"/agent/jobs/{job_id}/outputs", json=manifest)
        assert done.status_code == 204, done.text
        self.outputs = manifest

    def complete(self, job_id: str, attempt: int, *, units: int | None = None, exit_code: int = 0):
        """`units` given: a catalog job, reported with its checksum. Otherwise a package
        job: its exit code and the digest of the outputs it reported (ADR 0003)."""
        from udcs_shared.jobs import expected_checksum
        from udcs_shared.packages import OutputManifest

        report: dict = {"job_id": job_id, "attempt": attempt, "state": "completed"}
        if units is not None:
            report["units_done"] = units
            report["result"] = {"units": units, "checksum": str(expected_checksum(units))}
        else:
            files = self.outputs["files"] if self.outputs else []
            report["units_done"] = 0
            report["package_result"] = {
                "exit_code": exit_code,
                "outputs_sha256": OutputManifest.model_validate(self.outputs).digest()
                if self.outputs
                else None,
                "files": len(files),
                "bytes": sum(f["size"] for f in files),
            }
        self._sync([report], accept=False)


@pytest.fixture
def h():
    """Helpers for test modules (importlib mode cannot import conftest directly)."""
    from types import SimpleNamespace

    return SimpleNamespace(
        SPEC=SPEC,
        SimulatedNode=SimulatedNode,
        api_client=api_client,
        set_user_code=set_user_code,
        write_project=write_project,
        sha=sha,
        upload=upload,
    )
