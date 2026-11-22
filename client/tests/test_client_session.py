"""Credentials on the researcher's machine, TLS rules, and `watch` behaviour."""

from __future__ import annotations

import io
import os
import sys
import uuid

import httpx
import pytest

from udcs_client import cli
from udcs_client.output import ClientError, Exit
from udcs_client.session import (
    Session,
    bind,
    load_session,
    save_session,
    token_for,
    validate_server,
)

TOKEN = "tok-" + "z" * 40


def _session(origin="https://udcs.example.edu") -> Session:
    return Session(origin=origin, token=TOKEN, expires_at="2099-01-01T00:00:00Z", username="ada")


@pytest.mark.parametrize(
    "url",
    [
        "http://udcs.example.edu",
        "ftp://x",
        "https://user:pw@udcs.example.edu",
        "https://x/?q=1",
        "https://",
    ],
)
def test_only_plain_https_servers_are_accepted(url):
    with pytest.raises(ClientError):
        validate_server(url)


def test_a_token_is_never_used_for_another_server():
    save_session(_session(), use_dpapi=False)
    assert token_for("https://udcs.example.edu") == TOKEN
    with pytest.raises(ClientError, match="logged in to"):
        token_for("https://evil.example")


def test_env_token_overrides_and_is_never_written(isolated_config, monkeypatch):
    monkeypatch.setenv("UDCS_TOKEN", "from-env")
    with pytest.raises(ClientError, match="needs UDCS_SERVER"):
        token_for("https://ci.example")  # an unbound env token is never sent anywhere
    monkeypatch.setenv("UDCS_SERVER", "https://ci.example:443")
    assert token_for("https://ci.example") == "from-env"  # default port is the same origin
    with pytest.raises(ClientError, match="belongs to"):
        token_for("https://other.example")
    assert not (isolated_config / "session").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_posix_session_file_is_private_and_refused_when_not(isolated_config):
    save_session(_session(), use_dpapi=False)
    path = isolated_config / "session"
    assert (path.stat().st_mode & 0o777) == 0o600
    os.chmod(path, 0o644)
    with pytest.raises(ClientError, match="readable by other users"):
        load_session()


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI")
def test_windows_session_is_dpapi_protected_in_user_scope(isolated_config):
    save_session(_session())
    raw = (isolated_config / "session").read_bytes()
    assert TOKEN.encode() not in raw and raw.startswith(b"UDCS-SESSION-DPAPI1")
    assert load_session().token == TOKEN


def test_a_corrupt_session_is_reported_not_crashed(isolated_config):
    isolated_config.mkdir(parents=True, exist_ok=True)
    (isolated_config / "session").write_bytes(b"garbage")
    if sys.platform != "win32":
        os.chmod(isolated_config / "session", 0o600)  # private, so only the content is wrong
    with pytest.raises(ClientError, match="unreadable"):
        load_session()


# -- watch ---------------------------------------------------------------------------------------


JOB = str(uuid.uuid4())


def _job(state, units=0, attempt=1):
    return {
        "id": JOB,
        "kind": "cpu",
        "total_units": 10,
        "state": state,
        "local_state": None,
        "progress": units / 10,
        "units_done": units,
        "attempt": attempt,
        "cpu_seconds": 0.0,
        "error": "boom" if state == "failed" else None,
        "package": None,
    }


def _watch(states, logs=None):
    sequence = list(states)
    log_batches = list(logs or [])
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path.removeprefix("/api/v1")
        if path == f"/jobs/{JOB}":
            return httpx.Response(200, json=sequence.pop(0) if len(sequence) > 1 else sequence[0])
        if path == f"/jobs/{JOB}/logs":
            return httpx.Response(200, json=log_batches.pop(0) if log_batches else [])
        return httpx.Response(404)

    def factory(url, _ca, token):
        return bind(
            httpx.Client(base_url=url + "/api/v1", transport=httpx.MockTransport(handler)),
            url,
            token,
        )

    save_session(_session("https://udcs.example.edu"), use_dpapi=False)
    sleeps, out = [], io.StringIO()
    code = cli.main(
        ["--server", "https://udcs.example.edu", "watch", JOB],
        http_factory=factory,
        out=out,
        err=io.StringIO(),
        sleep=sleeps.append,
    )
    return code, sleeps, out.getvalue(), requests


def test_watch_backs_off_while_nothing_changes_and_resets_on_change():
    states = (
        [_job("queued")] * 5
        + [_job("running", 3)]
        + [_job("running", 3)] * 2
        + [_job("succeeded", 10)]
    )
    code, sleeps, out, _ = _watch(states)
    assert code == 0 and "succeeded" in out
    base = [s / 1.2 for s in sleeps]  # upper bound of the jitter
    assert sleeps[0] <= 2 * 1.2 and sleeps[3] > sleeps[1]  # backing off while queued
    assert sleeps[5] <= 2 * 1.2  # reset after progress
    assert max(sleeps) <= 30 * 1.2 and all(b > 0 for b in base)


def test_watch_exit_codes_and_log_cursor():
    logs = [[{"id": 5, "at": "t", "attempt": 1, "source": "agent", "message": "started"}], []]
    code, _, out, requests = _watch([_job("running", 1), _job("failed")], logs=logs)
    assert code == Exit.JOB_FAILED and "boom" in out and "started" in out
    log_requests = [r for r in requests if r.url.path.endswith("/logs")]
    assert "after" not in log_requests[0].url.params
    assert log_requests[1].url.params["after"] == "5"  # only new lines next time
    code, _, _, _ = _watch([_job("cancelled")])
    assert code == Exit.JOB_FAILED


def test_ctrl_c_detaches_without_cancelling():
    def handler(request):
        if request.url.path.endswith("/logs"):
            raise KeyboardInterrupt
        return httpx.Response(200, json=_job("running", 1))

    def factory(url, _ca, token):
        return bind(
            httpx.Client(base_url=url + "/api/v1", transport=httpx.MockTransport(handler)),
            url,
            token,
        )

    save_session(_session(), use_dpapi=False)
    out = io.StringIO()
    code = cli.main(
        ["--server", "https://udcs.example.edu", "watch", JOB],
        http_factory=factory,
        out=out,
        err=io.StringIO(),
    )
    assert code == 0 and "keeps running" in out.getvalue()
