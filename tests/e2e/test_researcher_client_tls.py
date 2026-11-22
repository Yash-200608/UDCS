"""The researcher client against a real controller over TLS: the production HTTP
client (certificate verification, no redirects), the stored session (DPAPI user scope
on Windows) and the disabled-execution path. Nothing executes user code."""

from __future__ import annotations

import io
import sys

import pytest

from udcs_client import cli
from udcs_client.output import Exit
from udcs_controller.auth.permissions import Role
from udcs_controller.auth.service import create_user

pytestmark = pytest.mark.e2e
PASSWORD = "e2e-researcher-pass"


def _udcs(*argv: str, password: str = PASSWORD) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), out=out, err=err, ask=lambda _p: "", ask_secret=lambda _p: password)
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def server(controller_factory, tmp_path, monkeypatch):
    monkeypatch.setenv("UDCS_CONFIG_DIR", str(tmp_path / "config"))
    monkeypatch.delenv("UDCS_TOKEN", raising=False)
    running = controller_factory(blob_dir=str(tmp_path / "blobs"))
    with running.app.state.sessionmaker() as db:
        create_user(
            db, username="rita", display_name="Rita", password=PASSWORD, role=Role.RESEARCHER
        )
        db.commit()
    return running


def test_tls_is_verified_and_the_session_is_stored_protected(server, tmp_path):
    code, _, err = _udcs("--server", server.url, "login", "--username", "rita")
    assert code == Exit.SERVER and "cannot reach" in err  # the throwaway CA is not trusted
    assert not (tmp_path / "config" / "session").exists()
    code, out, err = _udcs(
        "--server", server.url, "--ca-bundle", str(server.ca_file), "login", "--username", "rita"
    )
    assert code == 0, err
    session = (tmp_path / "config" / "session").read_bytes()
    if sys.platform == "win32":
        assert session.startswith(b"UDCS-SESSION-DPAPI1")
    code, out, _ = _udcs("whoami")  # server and CA come from the saved config
    assert code == 0 and "rita" in out


def test_package_submit_stays_disabled_and_catalog_jobs_work(server, tmp_path):
    _udcs("--server", server.url, "--ca-bundle", str(server.ca_file), "login", "--username", "rita")
    project = tmp_path / "proj"
    assert _udcs("init", str(project), "--name", "proj")[0] == 0
    code, out, err = _udcs("submit", "-C", str(project), "--yes")
    assert code == Exit.DISABLED, err
    assert "No job was created" in out
    code, out, _ = _udcs("jobs")
    assert code == 0 and "no jobs" in out
    code, out, err = _udcs("submit", "--catalog", "cpu", "--units", "500")
    assert code == 0, err
    job_id = out.split()[3]
    code, out, _ = _udcs("status", job_id)
    assert code == 0 and "queued" in out


@pytest.mark.skip(
    reason="blocked on ADR 0001 gate 2 and administrator node eligibility: "
    "user code does not execute anywhere yet, so this path cannot be verified"
)
def test_package_job_end_to_end():
    """submit -> a real agent stages and runs the package in AppContainer -> outputs ->
    udcs fetch. Kept as a reminder that this path is untested until execution exists."""
