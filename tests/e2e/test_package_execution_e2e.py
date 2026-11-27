"""Researcher CLI -> HTTPS controller -> scheduler -> Windows agent -> AppContainer ->
result upload -> researcher fetch, all real on this machine (ADR 0003).

User-code execution is disabled by default everywhere. These tests switch it on *in
memory, in this test process only*: the controller's flag through its settings, the
agent's constant by monkeypatching, and the node's eligibility through the real
administrator endpoint. The node must still measure a working AppContainer itself.
Nothing on disk or in any shipped default changes.
"""

from __future__ import annotations

import io
import json
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

from udcs_agent.app import AgentApp
from udcs_agent.communication.client import ControllerClient
from udcs_agent.config import CREDENTIAL_FILENAME, AgentConfig, save_config
from udcs_agent.credentials import CredentialStore, NodeCredential
from udcs_agent.discovery import collect_inventory
from udcs_agent.discovery.nvidia import Nvml
from udcs_client import cli
from udcs_controller.auth.permissions import Role
from udcs_controller.auth.service import create_user

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows agent with AppContainer"),
]
PASSWORD = "e2e-researcher-pass"

MAIN = """\
import json, os, sys
from analysis.stats import mean
cfg = json.load(open("config.json"))
values = cfg["values"]
print("computing the mean of", len(values), "values")
with open("out/result.json", "w") as f:
    json.dump({"mean": mean(values), "n": len(values)}, f)
os.makedirs("out/plots", exist_ok=True)
with open("out/plots/summary.txt", "w") as f:
    f.write("ok\\n")
sys.exit(0)
"""
SLOW = "import time\nfor _ in range(600):\n    time.sleep(0.5)\n"


def _wait(predicate, timeout, interval=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return None


def _udcs(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(list(argv), out=out, err=err, ask=lambda _p: "", ask_secret=lambda _p: PASSWORD)
    return code, out.getvalue(), err.getvalue()


class Node:
    def __init__(self, controller, data_dir: Path, token: str, name: str) -> None:
        self.data_dir = data_dir
        config = AgentConfig(controller_url=controller.url, ca_bundle=controller.ca_file)
        save_config(data_dir, config)
        with Nvml() as nvml:
            inventory = collect_inventory(nvml)
        with ControllerClient(config) as client:
            enrolled = client.enroll(token, inventory, name)
        self.node_id = str(enrolled.node_id)
        CredentialStore(data_dir / CREDENTIAL_FILENAME).save(
            NodeCredential(node_id=enrolled.node_id, secret=enrolled.node_credential)
        )
        self.app: AgentApp | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        self.app = AgentApp(self.data_dir, stop=threading.Event(), helper_channel=False, max_jobs=1)
        self.thread = threading.Thread(target=self.app.run, name="pkg-node", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        if self.app is not None and self.thread is not None:
            self.app.stop.set()
            self.thread.join(timeout=30)
        self.app = self.thread = None


@pytest.fixture
def world(controller_factory, tmp_path, monkeypatch):
    import udcs_agent.jobs as agent_jobs

    monkeypatch.setattr(agent_jobs, "USER_CODE_ENABLED", True)  # this process only
    monkeypatch.setenv("UDCS_CONFIG_DIR", str(tmp_path / "researcher-config"))
    monkeypatch.delenv("UDCS_TOKEN", raising=False)
    controller = controller_factory(
        tokens=1, heartbeat_interval_seconds=5, job_lease_seconds=60, user_code_enabled=True
    )
    with controller.app.state.sessionmaker() as db:
        create_user(db, username="ada", display_name="Ada", password=PASSWORD, role=Role.RESEARCHER)
        db.commit()
    http = httpx.Client(base_url=f"{controller.url}/api/v1", verify=str(controller.ca_file))
    token = http.post(
        "/auth/login", json={"username": "itadmin", "password": controller.admin_password}
    ).json()["access_token"]
    admin = {"Authorization": f"Bearer {token}"}
    node = Node(controller, tmp_path / "node", controller.tokens[0], "pkg-node")
    node.start()
    try:
        # The node must measure a working AppContainer and report it before it is
        # useful; the administrator then makes it eligible.
        ready = _wait(
            lambda: any(
                c.get("name") == "appcontainer" and c.get("verified")
                for c in (
                    (
                        http.get(f"/admin/nodes/{node.node_id}", headers=admin)
                        .json()
                        .get("inventory")
                        or {}
                    ).get("isolation", [])
                )
            ),
            timeout=180,
        )
        assert ready, "the node never reported a verified AppContainer"
        made = http.post(
            f"/admin/nodes/{node.node_id}/user-code",
            headers=admin,
            json={"allowed": True, "reason": "e2e package execution test"},
        )
        assert made.status_code == 200 and made.json()["user_code_ready"], made.text
        code, _, err = _udcs(
            "--server",
            controller.url,
            "--ca-bundle",
            str(controller.ca_file),
            "login",
            "--username",
            "ada",
        )
        assert code == 0, err
        yield controller, http, admin, node, tmp_path
    finally:
        node.stop()
        http.close()


def _project(root: Path, main: str) -> Path:
    assert _udcs("init", str(root), "--name", "meanie")[0] == 0
    (root / "main.py").write_text(main, encoding="utf-8")
    (root / "analysis").mkdir()
    (root / "analysis" / "__init__.py").write_text("", encoding="utf-8")
    (root / "analysis" / "stats.py").write_text(
        "def mean(xs):\n    return sum(xs) / len(xs)\n", encoding="utf-8"
    )
    spec = (root / "udcs.toml").read_text(encoding="utf-8")
    spec += "\n[config]\nvalues = [1, 2, 3, 4]\n"
    (root / "udcs.toml").write_text(spec, encoding="utf-8")
    return root


def test_researcher_package_runs_in_appcontainer_and_results_are_fetched(world):
    _controller, http, admin, node, tmp = world
    project = _project(tmp / "meanie", MAIN)
    code, out, err = _udcs("submit", "-C", str(project), "--yes")
    assert code == 0, out + err
    job_id = next(line.split()[2] for line in out.splitlines() if line.startswith("submitted job"))

    code, out, err = _udcs("watch", job_id)
    assert code == 0, out + err
    job = http.get(f"/jobs/{job_id}", headers=admin).json()
    assert job["state"] == "succeeded" and job["exit_code"] == 0, job
    assert job["node_id"] == node.node_id

    target = tmp / "results"
    code, out, err = _udcs("fetch", job_id, "-o", str(target))
    assert code == 0, out + err
    assert json.loads((target / "result.json").read_text()) == {"mean": 2.5, "n": 4}
    assert (target / "plots" / "summary.txt").read_text() == "ok\n"
    assert "computing the mean of 4 values" in (target / "udcs-logs" / "stdout.txt").read_text()
    receipt = json.loads((target / "udcs-receipt.json").read_text())
    assert receipt["attempt"] == job["attempt"] and receipt["package"] == job["package"]
    logs = http.get(f"/jobs/{job_id}/logs", headers=admin).json()
    messages = [line["message"] for line in logs]
    assert any("package verified and staged" in m for m in messages)
    assert any("started (package, appcontainer)" in m for m in messages)

    # The node cleans up once the controller has acknowledged the result.
    staging = node.data_dir / "staging"
    assert _wait(lambda: not any(staging.iterdir()) if staging.exists() else True, timeout=60)


def test_cancelling_a_running_package_kills_it_and_cleans_up(world):
    _controller, http, admin, node, tmp = world
    project = _project(tmp / "slow", SLOW)
    code, out, err = _udcs("submit", "-C", str(project), "--yes")
    assert code == 0, out + err
    job_id = next(line.split()[2] for line in out.splitlines() if line.startswith("submitted job"))
    assert _wait(
        lambda: http.get(f"/jobs/{job_id}", headers=admin).json()["state"] == "running", 120
    ), http.get(f"/jobs/{job_id}/logs", headers=admin).json()[-5:]
    code, out, err = _udcs("cancel", job_id, "--yes")
    assert code == 0, out + err
    assert http.get(f"/jobs/{job_id}", headers=admin).json()["state"] == "cancelled"
    staging = node.data_dir / "staging"
    assert _wait(lambda: not staging.exists() or not any(staging.iterdir()), timeout=60), list(
        staging.iterdir()
    )
    outputs = http.get(f"/jobs/{job_id}/outputs", headers=admin).json()
    assert outputs["outputs"] is None  # a cancelled run publishes nothing
