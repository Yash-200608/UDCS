from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from udcs_controller.auth.permissions import Role
from udcs_controller.auth.service import create_user
from udcs_controller.config import Settings
from udcs_controller.database.migrate import upgrade_to_head
from udcs_controller.main import create_app
from udcs_shared.agent_api import PROTOCOL_VERSION
from udcs_shared.hardware import (
    CpuInfo,
    GpuInfo,
    HardwareInventory,
    IsolationCapability,
    MemoryInfo,
    NetworkInterfaceInfo,
    OsInfo,
)
from udcs_shared.telemetry import GpuTelemetry, TelemetrySnapshot

PASSWORD = "correct-horse-battery"
API = "/api/v1"


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 1, 5, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: float) -> None:
        self.now += timedelta(**kwargs)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def settings(tmp_path) -> Settings:
    url = (
        os.environ.get("UDCS_TEST_DATABASE_URL") or f"sqlite:///{(tmp_path / 'udcs.db').as_posix()}"
    )
    if os.environ.get("UDCS_REQUIRE_POSTGRES") == "1" and not url.startswith("postgresql"):
        pytest.fail("UDCS_REQUIRE_POSTGRES=1 but the test database is not PostgreSQL")
    return Settings(database_url=url, log_json=False, blob_dir=str(tmp_path / "blobs"))


@pytest.fixture
def app(settings: Settings, clock: FakeClock) -> Iterator[FastAPI]:
    application = create_app(settings, clock=clock)
    engine = application.state.engine
    if engine.dialect.name == "postgresql":  # CI: fresh schema per test
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
    upgrade_to_head(engine)
    yield application
    engine.dispose()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def make_user(app: FastAPI) -> Callable[..., object]:
    def _make(username: str, role: Role = Role.STUDENT, password: str = PASSWORD):
        with app.state.sessionmaker() as db:
            user = create_user(
                db, username=username, display_name=username.title(), password=password, role=role
            )
            db.commit()
            return user

    return _make


@pytest.fixture
def login(client: TestClient) -> Callable[..., dict[str, str]]:
    def _login(username: str, password: str = PASSWORD) -> dict[str, str]:
        response = client.post(
            f"{API}/auth/login", json={"username": username, "password": password}
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    return _login


@pytest.fixture
def admin_headers(make_user, login) -> dict[str, str]:
    make_user("admin", Role.ADMIN)
    return login("admin")


@pytest.fixture
def student_headers(make_user, login) -> dict[str, str]:
    make_user("student1", Role.STUDENT)
    return login("student1")


@pytest.fixture
def inventory_factory() -> Callable[..., HardwareInventory]:
    def _make(
        hostname: str = "lab-b-07",
        gpus: tuple[tuple[str, int, str], ...] = (("NVIDIA GeForce RTX 3060", 12 * 2**30, "8.6"),),
        memory_gib: int = 32,
        appcontainer: bool = False,
    ) -> HardwareInventory:
        isolation = (
            [IsolationCapability(name="appcontainer", available=True, verified=True)]
            if appcontainer
            else []
        )
        return HardwareInventory(
            isolation=isolation,
            agent_version="0.1.0",
            os=OsInfo(system="Windows", release="11", version="10.0.22631", hostname=hostname),
            cpu=CpuInfo(
                model="Intel Core i7-12700",
                architecture="AMD64",
                physical_cores=12,
                logical_cores=20,
                max_frequency_mhz=2100.0,
            ),
            memory=MemoryInfo(total_bytes=memory_gib * 2**30),
            network_interfaces=[
                NetworkInterfaceInfo(
                    name="Ethernet", is_up=True, speed_mbps=1000, ipv4_addresses=["10.20.30.40"]
                )
            ],
            gpus=[
                GpuInfo(
                    index=i,
                    vendor="nvidia",
                    name=name,
                    memory_total_bytes=mem,
                    compute_capability=cc,
                    driver_version="551.86",
                    cuda_driver_version="12.4",
                )
                for i, (name, mem, cc) in enumerate(gpus)
            ],
        )

    return _make


@pytest.fixture
def telemetry_factory(clock: FakeClock) -> Callable[..., TelemetrySnapshot]:
    def _make(cpu_percent: float = 12.5, **overrides) -> TelemetrySnapshot:
        fields = {
            "collected_at": clock.now,
            "cpu_percent": cpu_percent,
            "memory_total_bytes": 32 * 2**30,
            "memory_available_bytes": 20 * 2**30,
            "disk_free_bytes": 200 * 2**30,
            "uptime_seconds": 3600.0,
            "interactive_state": "active",
            "gpus": [
                GpuTelemetry(
                    index=0,
                    utilization_percent=3.0,
                    memory_used_bytes=2**30,
                    memory_total_bytes=12 * 2**30,
                    temperature_c=41.0,
                )
            ],
        }
        fields.update(overrides)
        return TelemetrySnapshot(**fields)

    return _make


@pytest.fixture
def new_enrollment_key(client: TestClient, admin_headers) -> Callable[..., str]:
    def _make(
        ttl_minutes: int = 60, max_uses: int = 1, auto_approve: bool = True, lab: str = "CS Lab B"
    ) -> str:
        response = client.post(
            f"{API}/admin/enrollment-keys",
            headers=admin_headers,
            json={
                "lab": lab,
                "ttl_minutes": ttl_minutes,
                "max_uses": max_uses,
                "auto_approve": auto_approve,
                "note": "test",
            },
        )
        assert response.status_code == 201, response.text
        return response.json()["key"]

    return _make


@pytest.fixture
def new_enrollment_token(new_enrollment_key) -> Callable[..., str]:
    """Milestone-1 style: a single-use, auto-approved key."""
    return new_enrollment_key


@pytest.fixture
def enroll(client: TestClient, new_enrollment_token, inventory_factory):
    """Enroll a node; returns (response_json, node_auth_headers, inventory)."""

    def _enroll(inventory: HardwareInventory | None = None, token: str | None = None):
        inventory = inventory or inventory_factory()
        response = client.post(
            f"{API}/agent/enroll",
            json={
                "enrollment_token": token or new_enrollment_token(),
                "protocol_version": PROTOCOL_VERSION,
                "inventory": inventory.model_dump(mode="json"),
            },
        )
        assert response.status_code == 201, response.text
        body = response.json()
        return body, {"Authorization": f"Bearer {body['node_credential']}"}, inventory

    return _enroll


@pytest.fixture
def heartbeat(client: TestClient, telemetry_factory):
    def _heartbeat(
        headers, inventory: HardwareInventory, telemetry: TelemetrySnapshot | None = None
    ):
        return client.post(
            f"{API}/agent/heartbeat",
            headers=headers,
            json={
                "protocol_version": PROTOCOL_VERSION,
                "telemetry": (telemetry or telemetry_factory()).model_dump(mode="json"),
                "inventory_fingerprint": inventory.fingerprint(),
            },
        )

    return _heartbeat
