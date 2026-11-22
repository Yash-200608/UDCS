"""The researcher workflow, end to end against the real controller (in-process).

User code execution is disabled by default; one test turns the controller flag on in
memory to show the job path, and a simulated node (which executes nothing) reports
outputs so that `fetch` can be tested.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

from udcs_client.output import Exit


def test_init_creates_a_valid_project_and_refuses_to_overwrite(h, run, tmp_path):
    target = tmp_path / "new-proj"
    first = run("init", str(target), "--name", "new-proj")
    assert first.code == 0, first.err
    assert (target / "udcs.toml").is_file() and (target / "main.py").is_file()
    spec = tomllib.loads((target / "udcs.toml").read_text(encoding="utf-8"))
    assert spec["files"]["include"] == ["**/*.py"] and spec["entry"]["script"] == "main.py"
    again = run("init", str(target))
    assert again.code == Exit.USAGE and "not overwritten" in again.err
    offline = run("check", "--offline", "-C", str(target))
    assert offline.code == 0, offline.err


def test_login_binds_the_token_to_the_origin_and_never_prints_it(h, run, app, isolated_config):
    result = run("login", "--username", "ada")
    assert result.code == 0, result.err
    session_file = isolated_config / "session"
    assert session_file.is_file()
    token = h.api_client(app, "ada").headers["Authorization"].split()[1]
    assert token not in result.out + result.err
    who = run("whoami")
    assert who.code == 0 and "ada" in who.out
    bad = run("login", "--username", "ada", password="wrong")
    assert bad.code == Exit.SERVER and "login failed" in bad.err
    assert run("logout").code == 0 and not session_file.exists()
    assert run("whoami").code == Exit.USAGE


def test_submit_while_disabled_registers_but_creates_no_job(
    h, logged_in, project, app, environment
):
    run = logged_in
    (project / "udcs.toml").write_text(
        h.SPEC + f'\n[environment]\ndigest = "{environment}"\nrequirements = ["numpy==2.1.3"]\n',
        encoding="utf-8",
    )
    checked = run("check", "-C", str(project))
    assert checked.code == 0, checked.err
    assert "turned off" in checked.out
    result = run("submit", "-C", str(project), "--yes")
    assert result.code == Exit.DISABLED, result.err
    assert "No job was created" in result.out
    assert run.sent("POST", "/jobs") == 0  # the client never even asked
    digest = next(line.split()[-1] for line in result.out.splitlines() if "registered" in line)
    ada = h.api_client(app, "ada")
    assert ada.get(f"/packages/{digest}").status_code == 200
    assert ada.get("/jobs").json() == []
    again = run("submit", "-C", str(project), "--yes")
    assert "uploaded 0 files" in again.out  # nothing is re-uploaded


def test_submit_with_execution_enabled_creates_a_package_job(h, logged_in, project, app):
    h.set_user_code(app, True)  # in memory, for this test only
    result = logged_in("submit", "-C", str(project), "--yes")
    assert result.code == 0, result.err
    [job] = h.api_client(app, "ada").get("/jobs").json()
    assert job["package"] is not None and job["state"] == "queued"
    status = logged_in("status", job["id"])
    assert "package" in status.out and "%" not in status.out  # no fake percentage


def test_a_pin_missing_from_the_environment_is_caught_before_any_upload(
    h, logged_in, project, environment
):
    (project / "udcs.toml").write_text(
        h.SPEC + f'\n[environment]\ndigest = "{environment}"\nrequirements = ["numpy==1.0.0"]\n',
        encoding="utf-8",
    )
    result = logged_in("submit", "-C", str(project), "--yes")
    assert result.code == Exit.INVALID
    assert "numpy==1.0.0" in result.err and "numpy==2.1.3" in result.err  # what it provides
    assert logged_in.sent("POST", "/blobs/uploads") == 0


def test_requirements_without_an_environment_are_rejected_offline(h, run, project):
    (project / "udcs.toml").write_text(
        h.SPEC + '\n[environment]\nrequirements = ["numpy==2.1.3"]\n', encoding="utf-8"
    )
    result = run("check", "--offline", "-C", str(project))
    assert result.code == Exit.INVALID and "approved environment" in result.err


def test_ranges_are_not_dependencies(h, run, project):
    (project / "udcs.toml").write_text(
        h.SPEC + '\n[environment]\nrequirements = ["numpy>=2"]\n', encoding="utf-8"
    )
    result = run("check", "--offline", "-C", str(project))
    assert result.code == Exit.INVALID and "exact pins" in result.err


def test_env_use_resolves_names_and_refuses_ambiguity(h, logged_in, project, approved):
    first = approved(
        "environment",
        "sci",
        "1",
        python="3.11",
        platform="win_amd64",
        lock=[{"name": "a", "version": "1"}],
    )
    approved(
        "environment",
        "sci",
        "2",
        python="3.12",
        platform="win_amd64",
        lock=[{"name": "a", "version": "1"}],
    )
    ambiguous = logged_in("env", "use", "sci", "-C", str(project))
    assert ambiguous.code == Exit.USAGE and "several" in ambiguous.err
    unknown = logged_in("env", "use", "nope", "-C", str(project))
    assert unknown.code == Exit.USAGE
    chosen = logged_in("env", "use", "sci==1", "-C", str(project))
    assert chosen.code == 0, chosen.err
    spec = tomllib.loads((project / "udcs.toml").read_text(encoding="utf-8"))
    assert spec["environment"]["digest"] == first and spec["project"]["python"] == "3.11"
    listed = logged_in("env", "list")
    assert "sci==1" in listed.out and "sci==2" in listed.out
    shown = logged_in("env", "show", "sci==2")
    assert "a==1" in shown.out


def test_dataset_push_approval_and_attach(h, logged_in, project, app, tmp_path):
    data = tmp_path / "measurements"
    data.mkdir()
    (data / "a.csv").write_text("x,y\n1,2\n")
    (data / ".env").write_text("SECRET=1")  # never packaged
    pushed = logged_in("dataset", "push", str(data), "--name", "meas", "--version", "1", "--yes")
    assert pushed.code == 0, pushed.err
    assert "awaiting administrator approval" in pushed.out
    digest = next(
        line.split()[-1] for line in pushed.out.splitlines() if "registered dataset" in line
    )
    unapproved = logged_in("dataset", "add", "train", digest, "-C", str(project))
    assert unapproved.code == Exit.USAGE  # not listed until approved
    admin = h.api_client(app, "admin")
    assert admin.post(f"/admin/packages/{digest}/approve").status_code == 200
    attached = logged_in("dataset", "add", "train", "meas", "-C", str(project))
    assert attached.code == 0, attached.err
    assert logged_in("check", "-C", str(project)).code == 0
    manifest = admin.get(f"/packages/{digest}").json()["manifest"]
    assert [f["path"] for f in manifest["files"]] == ["a.csv"]


def test_catalog_job_submit_status_and_locally_verified_result(h, logged_in, app):
    submitted = logged_in("submit", "--catalog", "cpu", "--units", "1000")
    assert submitted.code == 0, submitted.err
    job_id = submitted.out.split()[3]
    node = h.SimulatedNode(app)
    assignment = node.take()
    node.complete(job_id, assignment["attempt"], units=1000)
    watched = logged_in("watch", job_id)
    assert watched.code == 0 and "succeeded" in watched.out
    fetched = logged_in("fetch", job_id)
    assert fetched.code == 0 and "verified: checksum" in fetched.out


def test_fetch_downloads_verifies_and_never_overwrites(h, logged_in, project, app, tmp_path):
    h.set_user_code(app, True)  # in memory: a simulated node reports outputs, nothing runs
    assert logged_in("submit", "-C", str(project), "--yes").code == 0
    [job] = h.api_client(app, "ada").get("/jobs").json()
    node = h.SimulatedNode(app)
    attempt = node.take()["attempt"]
    outputs = {"result.csv": b"a,b\n1,2\n", "plots/p.svg": b"<svg/>", "empty.txt": b""}
    node.report_outputs(job["id"], attempt, outputs)
    early = logged_in("fetch", job["id"], "-o", str(tmp_path / "early"))
    assert early.code == Exit.USAGE and "succeeded jobs" in early.err
    node.complete(job["id"], attempt)
    target = tmp_path / "results"
    fetched = logged_in("fetch", job["id"], "-o", str(target))
    assert fetched.code == 0, fetched.err
    assert "match the hashes the node reported" in fetched.out
    for relative, data in outputs.items():
        assert (target / Path(relative)).read_bytes() == data
    receipt = json.loads((target / "udcs-receipt.json").read_text(encoding="utf-8"))
    assert receipt["attempt"] == attempt and receipt["package"] == job["package"]
    assert not (target / ".udcs-partial").exists()

    refused = logged_in("fetch", job["id"], "-o", str(target))
    assert refused.code == Exit.USAGE and "--resume" in refused.err
    resumed = logged_in("fetch", job["id"], "-o", str(target), "--resume")
    assert resumed.code == 0 and "0 B downloaded" in resumed.out
    (target / "result.csv").write_bytes(b"edited by the researcher")
    clash = logged_in("fetch", job["id"], "-o", str(target), "--resume")
    assert clash.code == Exit.VERIFICATION and "not overwritten" in clash.err
    assert (target / "result.csv").read_bytes() == b"edited by the researcher"


def test_other_users_jobs_are_invisible(h, logged_in, app):
    bob = h.api_client(app, "bob")
    job = bob.post("/jobs", json={"kind": "cpu", "total_units": 10}).json()
    result = logged_in("status", job["id"])
    assert result.code == Exit.USAGE and "not found" in result.err


def test_same_content_gives_the_same_digest_wherever_it_lives(h, run, tmp_path):
    files = {"main.py": "print(1)\n", "pkg/a.py": "A = 1\n"}
    one = h.write_project(tmp_path / "one", files, h.SPEC)
    two = h.write_project(tmp_path / "elsewhere" / "two", files, h.SPEC)
    a = run("check", "--offline", "-C", str(one))
    b = run("check", "--offline", "-C", str(two))
    digest = [line for line in a.out.splitlines() if line.startswith("digest")]
    assert digest and digest == [line for line in b.out.splitlines() if line.startswith("digest")]
