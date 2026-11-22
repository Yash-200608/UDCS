"""Regression tests for the researcher-client security review (2026-11-23). One or more
tests per confirmed finding; see ADR 0002, "Researcher client review"."""

from __future__ import annotations

import io
import json
import uuid

import httpx
import pytest

from udcs_client import cli
from udcs_client import select as select_module
from udcs_client.output import Exit, clip, sanitize
from udcs_client.session import Session, bind, load_session, save_session
from udcs_shared.transfer_http import place_new
from udcs_shared.urls import origin

TOKEN = "tok-" + "q" * 40
JOB = str(uuid.uuid4())


def _sha(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def _job(**overrides) -> dict:
    job = {
        "id": JOB,
        "kind": "cpu",
        "total_units": 1,
        "state": "succeeded",
        "local_state": None,
        "progress": 1.0,
        "units_done": 1,
        "attempt": 1,
        "cpu_seconds": 0.0,
        "error": None,
        "package": "a" * 64,
    }
    job.update(overrides)
    return job


def _mock(handler, *argv, server="https://udcs.example.edu"):
    seen: list[httpx.Request] = []

    def recording(request):
        seen.append(request)
        return handler(request)

    def factory(url, _ca, token):
        http = httpx.Client(base_url=url + "/api/v1", transport=httpx.MockTransport(recording))
        return bind(http, url, token)

    out, err = io.StringIO(), io.StringIO()
    code = cli.main(
        ["--server", server, *argv], http_factory=factory, out=out, err=err, sleep=lambda _s: None
    )
    return code, out.getvalue(), err.getvalue(), seen


def _logged_in(origin_url="https://udcs.example.edu"):
    save_session(
        Session(origin=origin_url, token=TOKEN, expires_at="2099-01-01T00:00:00Z", username="a"),
        use_dpapi=False,
    )


# -- credentials and origin --------------------------------------------------------------------


def test_default_port_is_the_same_origin_and_the_token_is_attached():
    assert origin("https://udcs.example.edu:443") == origin("https://UDCS.example.edu./x")
    assert origin("https://udcs.example.edu:8443") == "https://udcs.example.edu:8443"
    _logged_in()
    code, _, _, seen = _mock(
        lambda r: httpx.Response(200, json={"username": "a", "role": "researcher"}),
        "whoami",
        server="https://udcs.example.edu:443",
    )
    assert code == 0 and seen[0].headers["Authorization"] == f"Bearer {TOKEN}"


def test_logout_revokes_the_stored_session_at_its_own_origin(monkeypatch):
    _logged_in("https://issuer.example")
    monkeypatch.setenv("UDCS_TOKEN", "automation-token")
    monkeypatch.setenv("UDCS_SERVER", "https://elsewhere.example")
    code, _, err, seen = _mock(
        lambda r: httpx.Response(204), "logout", server="https://elsewhere.example"
    )
    assert code == 0
    [request] = seen
    assert request.url.host == "issuer.example"  # not --server, not UDCS_SERVER
    assert request.headers["Authorization"] == f"Bearer {TOKEN}"  # not UDCS_TOKEN
    assert "UDCS_TOKEN is not managed" in err
    assert load_session() is None


def test_logout_says_so_when_revocation_is_not_confirmed():
    _logged_in()
    code, _, err, _ = _mock(lambda r: httpx.Response(503), "logout")
    assert code == Exit.SERVER and "may still work until" in err
    assert load_session() is None  # deleted locally all the same


def test_redaction_survives_control_characters_and_truncation():
    split = TOKEN[:10] + "\x1b[0m" + TOKEN[10:]
    assert TOKEN not in sanitize(f"echo {split}", secrets=(TOKEN,))
    long = "x" * 190 + TOKEN
    shown = clip(sanitize(long, secrets=(TOKEN,)), 200)
    assert TOKEN[:6] not in shown
    _logged_in()
    _, out, err, _ = _mock(
        lambda r: httpx.Response(400, json={"detail": "y" * 190 + TOKEN}), "status", JOB
    )
    assert TOKEN[:6] not in out + err


def test_login_honours_environment_and_refuses_a_missing_ca_bundle(run, monkeypatch, tmp_path):
    monkeypatch.setenv("UDCS_CA_BUNDLE", str(tmp_path / "missing.pem"))
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(
        ["--server", "https://testserver", "login", "--username", "ada"],
        http_factory=run.factory,
        out=out,
        err=err,
        ask=lambda _p: "",
        ask_secret=lambda _p: "x",
    )
    assert code == Exit.USAGE and "does not exist" in err.getvalue()


def test_an_invalid_ca_bundle_is_a_clear_error_not_a_traceback(tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_text("not a certificate")
    _logged_in()
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(
        ["--server", "https://udcs.example.edu", "--ca-bundle", str(bad), "whoami"],
        out=out,
        err=err,
    )
    assert code == Exit.USAGE and "cannot load CA bundle" in err.getvalue()


# -- fetch -------------------------------------------------------------------------------------


def _fetch_server(outputs, blobs=None, job=None):
    def handler(request):
        path = request.url.path.removeprefix("/api/v1")
        if path == f"/jobs/{JOB}":
            return httpx.Response(200, json=job or _job())
        if path == f"/jobs/{JOB}/outputs":
            return httpx.Response(200, json={"job_id": JOB, "outputs": outputs})
        if path == "/packages/policy":
            return httpx.Response(200, json={})
        if path.startswith("/blobs/"):
            return httpx.Response(200, content=(blobs or {})[path.split("/")[-1]])
        return httpx.Response(404)

    return handler


def test_job_ids_are_validated_before_they_become_paths():
    _logged_in()
    with pytest.raises(SystemExit):
        cli.main(["--server", "https://udcs.example.edu", "fetch", "../../etc"], err=io.StringIO())
    code, _, err, _ = _mock(
        _fetch_server({"attempt": 1, "files": []}, job=_job(id="../x")), "fetch", JOB
    )
    assert code == Exit.VERIFICATION and "different job" in err


@pytest.mark.parametrize("name", [".udcs-partial/x", "UDCS-RECEIPT.json", ".UDCS-Partial/a/b"])
def test_outputs_cannot_use_the_clients_reserved_names(tmp_path, name):
    _logged_in()
    outputs = {"attempt": 1, "files": [{"path": name, "sha256": _sha(b"x"), "size": 1}]}
    code, _, err, _ = _mock(_fetch_server(outputs), "fetch", JOB, "-o", str(tmp_path / "t"))
    assert code == Exit.VERIFICATION and "reserves" in err


def test_resume_refuses_another_fetchs_directory(tmp_path):
    _logged_in()
    data = b"mine"
    outputs = {"attempt": 1, "files": [{"path": "r.txt", "sha256": _sha(data), "size": 4}]}
    target = tmp_path / "t"
    first, _, _, _ = _mock(
        _fetch_server(outputs, {_sha(data): data}), "fetch", JOB, "-o", str(target)
    )
    assert first == 0
    other = {"attempt": 1, "files": [{"path": "s.txt", "sha256": _sha(b"zz"), "size": 2}]}
    code, _, err, _ = _mock(
        _fetch_server(other, {_sha(b"zz"): b"zz"}), "fetch", JOB, "-o", str(target), "--resume"
    )
    assert code == Exit.USAGE and "different fetch" in err
    assert not (target / "s.txt").exists()


def test_the_client_bounds_output_size_whatever_the_controller_says(tmp_path):
    _logged_in()
    data = b"x" * 11
    outputs = {"attempt": 1, "files": [{"path": "r", "sha256": _sha(data), "size": 11}]}
    code, _, err, _ = _mock(
        _fetch_server(outputs, {_sha(data): data}),
        "fetch",
        JOB,
        "-o",
        str(tmp_path / "t"),
        "--max-bytes",
        "10",
    )
    assert code == Exit.VERIFICATION and "--max-bytes" in err


def test_place_new_never_replaces_an_existing_file(tmp_path):
    source, target = tmp_path / "s", tmp_path / "t"
    source.write_bytes(b"new")
    target.write_bytes(b"old")
    with pytest.raises(FileExistsError):
        place_new(source, target)
    assert target.read_bytes() == b"old"


# -- spec, selection, CLI ----------------------------------------------------------------------


def test_toml_dates_in_config_are_a_clear_error(run, h, tmp_path):
    root = h.write_project(
        tmp_path / "p", {"main.py": "1"}, h.SPEC + "\n[config]\nwhen = 2026-11-23T10:00:00Z\n"
    )
    result = run("check", "--offline", "-C", str(root))
    assert result.code == Exit.INVALID and "config.when" in result.err


def test_rewriting_the_spec_preserves_config(logged_in, h, project, environment):
    config = '\n[config]\nratio = 0.5\nlabels = ["a", "b"]\nnested = { k = "v\\u007fx" }\n'
    (project / "udcs.toml").write_text(h.SPEC + config, encoding="utf-8")
    result = logged_in("env", "use", environment[:12], "-C", str(project))  # a digest prefix
    assert result.code == 0, result.err
    import tomllib

    spec = tomllib.loads((project / "udcs.toml").read_text(encoding="utf-8"))
    assert spec["config"] == {"ratio": 0.5, "labels": ["a", "b"], "nested": {"k": "v\x7fx"}}


def test_more_credential_files_are_never_packaged(h, tmp_path):
    files = {
        "main.py": "1",
        ".npmrc": "//r/:_authToken=x",
        "infra/prod.tfstate": "{}",
        "gcp-credentials.json": "{}",
        ".pgpass": "h:5432:*:u:p",
        "cert.ppk": "x",
    }
    root = h.write_project(tmp_path / "p", files, h.SPEC)
    selection = select_module.select_files(root, ["**"], [])
    assert [rel for rel, _ in selection.files] == ["main.py"]


def test_naming_a_file_inside_a_denied_directory_is_an_error(h, tmp_path):
    root = h.write_project(tmp_path / "p", {"main.py": "1", ".git/hooks/post.py": "x"}, h.SPEC)
    selection = select_module.select_files(root, ["main.py", ".git/hooks/post.py"], [])
    assert any(".git/hooks/post.py is never packaged" in p for p in selection.problems)


def test_unreachable_directories_are_not_walked(h, tmp_path, monkeypatch):
    monkeypatch.setattr(select_module, "MAX_WALK_ENTRIES", 50)
    files = {"src/main.py": "1"} | {f"data/raw/{i}.bin": "x" for i in range(200)}
    root = h.write_project(tmp_path / "p", files, h.SPEC)
    selection = select_module.select_files(root, ["src/**/*.py"], [])
    assert not selection.problems and [r for r, _ in selection.files] == ["src/main.py"]


def test_dataset_push_checks_policy_before_uploading(logged_in, app, tmp_path):
    data = tmp_path / "d"
    data.mkdir()
    (data / "big.bin").write_bytes(b"x" * 5000)
    app.state.settings = app.state.settings.model_copy(
        update={"package_policy_json": json.dumps({"max_file_bytes": 1000})}
    )
    result = logged_in("dataset", "push", str(data), "--name", "d", "--version", "1", "--yes")
    assert result.code == Exit.INVALID and "policy" in result.err
    assert logged_in.sent("POST", "/blobs/uploads") == 0


def test_dataset_push_false_positive_can_be_allowed(logged_in, tmp_path):
    data = tmp_path / "d"
    data.mkdir()
    (data / "notes.txt").write_text('password = "example-only"\n')
    refused = logged_in("dataset", "push", str(data), "--name", "d", "--version", "1", "--yes")
    assert refused.code == Exit.INVALID and "--allow-flagged" in refused.err
    allowed = logged_in(
        "dataset",
        "push",
        str(data),
        "--name",
        "d",
        "--version",
        "1",
        "--yes",
        "--allow-flagged",
        "notes.txt",
    )
    assert allowed.code == 0, allowed.err


def test_init_turns_any_folder_name_into_a_valid_project(run, tmp_path):
    target = tmp_path / "My Analysis (2026)"
    assert run("init", str(target)).code == 0
    assert run("check", "--offline", "-C", str(target)).code == 0


def _watch(handler):
    _logged_in()
    return _mock(handler, "watch", JOB)


def _line(i: int) -> dict:
    return {"id": i, "at": "t", "attempt": 1, "source": "agent", "message": f"l{i}"}


def test_watch_prints_every_remaining_log_line_when_the_job_ends():
    pages = [[_line(i) for i in range(500)], [_line(500 + i) for i in range(3)]]

    def handler(request):
        if request.url.path.endswith("/logs"):
            return httpx.Response(200, json=pages.pop(0) if pages else [])
        return httpx.Response(200, json=_job(package=None))

    code, out, _, _ = _watch(handler)
    assert code == 0 and "l0" in out and "l502" in out


def test_watch_rides_out_a_controller_restart():
    replies = [httpx.Response(503), httpx.Response(200, json=_job(package=None))]

    def handler(request):
        if request.url.path.endswith("/logs"):
            return httpx.Response(200, json=[])
        return replies.pop(0) if replies else httpx.Response(200, json=_job(package=None))

    code, _, err, _ = _watch(handler)
    assert code == 0 and "retrying" in err


def test_watch_does_not_retry_authentication_failures():
    code, _, err, seen = _watch(lambda r: httpx.Response(401))
    assert code == Exit.SERVER and "udcs login" in err and len(seen) == 1


# -- defence in depth: each layer tested on its own ---------------------------------------------


def test_selection_itself_refuses_a_file_link(h, tmp_path):
    import os

    outside = tmp_path / "secret.py"
    outside.write_text("KEY = 1")
    root = h.write_project(tmp_path / "p", {"main.py": "1"}, h.SPEC)
    try:
        os.symlink(outside, root / "link.py")
    except OSError:
        pytest.skip("creating symlinks needs privilege or developer mode here")
    selection = select_module.select_files(root, ["**/*.py"], [])
    assert any("link.py: a link or special file" in p for p in selection.problems)
    assert "link.py" not in [r for r, _ in selection.files]


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="NTFS junctions")
def test_fetch_resolution_check_holds_even_if_the_link_check_is_raced(tmp_path, monkeypatch):
    """Simulate a junction swapped in after the per-segment link check (the check is
    disabled): the resolved-path check must still refuse to write outside the target."""
    import os
    import subprocess

    from udcs_client import results

    _logged_in()
    data = b"payload"
    outputs = {"attempt": 1, "files": [{"path": "sub/r.txt", "sha256": _sha(data), "size": 7}]}
    target, victim = tmp_path / "t", tmp_path / "victim"
    target.mkdir()
    victim.mkdir()
    cmd = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
    subprocess.run(  # noqa: S603 -- fixed system binary, test-controlled paths
        [cmd, "/c", "mklink", "/J", str(target / "sub"), str(victim)],
        check=True,
        capture_output=True,
    )
    from udcs_shared.packages import OutputManifest

    (target / results.PARTIAL_DIR).mkdir()
    marker = results.binding(_job(), OutputManifest.model_validate(outputs))
    (target / results.PARTIAL_DIR / results.MARKER).write_text(json.dumps(marker))
    monkeypatch.setattr(results, "is_reparse", lambda _p: False)
    code, _, err, _ = _mock(
        _fetch_server(outputs, {_sha(data): data}), "fetch", JOB, "-o", str(target), "--resume"
    )
    assert code == Exit.VERIFICATION and "resolves outside" in err
    assert not any(victim.iterdir())
