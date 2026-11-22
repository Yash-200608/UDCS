"""Shared e2e fixtures: a real controller over TLS (throwaway CA), on a free port."""

from __future__ import annotations

import socket
import threading
import time
from datetime import timedelta
from types import SimpleNamespace

import pytest
import trustme
import uvicorn

from udcs_controller.auth.permissions import Role
from udcs_controller.auth.service import create_user
from udcs_controller.config import Settings
from udcs_controller.database.base import utcnow
from udcs_controller.database.migrate import upgrade_to_head
from udcs_controller.main import create_app
from udcs_controller.nodes.service import create_enrollment_key

ADMIN_PASSWORD = "e2e-admin-password"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def controller(tmp_path):
    ca = trustme.CA()
    server_cert = ca.issue_cert("127.0.0.1", "localhost")
    cert_file, key_file, ca_file = (tmp_path / n for n in ("server.pem", "server.key", "ca.pem"))
    server_cert.cert_chain_pems[0].write_to_path(str(cert_file))
    server_cert.private_key_pem.write_to_path(str(key_file))
    ca.cert_pem.write_to_path(str(ca_file))

    app = create_app(
        Settings(database_url=f"sqlite:///{(tmp_path / 'e2e.db').as_posix()}", log_json=False)
    )
    upgrade_to_head(app.state.engine)
    with app.state.sessionmaker() as db:
        admin = create_user(
            db, username="itadmin", display_name="IT", password=ADMIN_PASSWORD, role=Role.ADMIN
        )
        tokens = [
            create_enrollment_key(
                db,
                created_by=admin,
                lab="E2E Lab",
                ttl=timedelta(minutes=10),
                max_uses=1,
                auto_approve=True,
                note="e2e",
                now=utcnow(),
            )[1]
            for _ in range(2)
        ]
        db.commit()

    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            ssl_certfile=str(cert_file),
            ssl_keyfile=str(key_file),
            log_config=None,
            access_log=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 15
    while not server.started:
        if time.monotonic() > deadline:
            raise RuntimeError("controller did not start")
        time.sleep(0.05)
    yield SimpleNamespace(
        admin_password=ADMIN_PASSWORD,
        url=f"https://127.0.0.1:{port}",
        ca_file=ca_file,
        tokens=tokens,
    )
    server.should_exit = True
    thread.join(timeout=10)
