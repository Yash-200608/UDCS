"""A hostile or compromised controller: unsafe output paths, mixed attempts, wrong
bytes, redirects to steal the token, and terminal escape sequences."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import uuid

import httpx
import pytest

from udcs_client import cli
from udcs_client.output import Exit, sanitize
from udcs_client.session import Session, bind, save_session

SERVER = "https://evil.example"
JOB = str(uuid.uuid4())
TOKEN = "tok-" + "s" * 40


def _job(**overrides) -> dict:
    job = {
        "id": JOB,
        "name": "",
        "owner_id": str(uuid.uuid4()),
        "kind": "cpu",
        "total_units": 1,
        "memory_mb": 256,
        "priority": 0,
        "state": "succeeded",
        "local_state": None,
        "progress": 1.0,
        "units_done": 1,
        "attempt": 1,
        "failures": 0,
        "requeues": 0,
        "created_at": "2026-11-22T00:00:00Z",
        "started_at": None,
        "finished_at": None,
        "cpu_seconds": 0.0,
        "memory_bytes": 0,
        "error": None,
        "node_id": None,
        "package": "a" * 64,
    }
    job.update(overrides)
    return job


def _bind_target(target, outputs: dict, job: dict | None = None) -> None:
    """Make `target` look like an interrupted fetch of this job (its marker)."""
    from udcs_client.results import MARKER, PARTIAL_DIR, binding
    from udcs_shared.packages import OutputManifest

    (target / PARTIAL_DIR).mkdir(parents=True, exist_ok=True)
    marker = binding(job or _job(), OutputManifest.model_validate(outputs))
    (target / PARTIAL_DIR / MARKER).write_text(json.dumps(marker), encoding="utf-8")


def _sha(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


class Server:
    """Scripted responses; records every request (and its Authorization header)."""

    def __init__(self, *, outputs=None, blobs=None, job=None, logs=None) -> None:
        self.outputs = outputs
        self.blobs = blobs or {}
        self.job = job or _job()
        self.logs = logs or []
        self.seen: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.seen.append(request)
        path = request.url.path.removeprefix("/api/v1")
        if path == f"/jobs/{JOB}":
            return httpx.Response(200, json=self.job)
        if path == f"/jobs/{JOB}/outputs":
            return httpx.Response(200, json={"job_id": JOB, "outputs": self.outputs})
        if path == f"/jobs/{JOB}/logs":
            return httpx.Response(200, json=self.logs if "after" not in request.url.params else [])
        if path == "/packages/policy":
            return httpx.Response(200, json={})
        if path.startswith("/blobs/"):
            body = self.blobs[path.split("/")[-1]]
            if isinstance(body, httpx.Response):
                return body
            return httpx.Response(200, content=body)
        return httpx.Response(404, json={"detail": "not found"})


def _run(server: Server, *argv: str) -> tuple[int, str, str]:
    def factory(url, _ca, token):
        http = httpx.Client(base_url=url + "/api/v1", transport=httpx.MockTransport(server.handler))
        return bind(http, url, token)

    save_session(
        Session(origin=SERVER, token=TOKEN, expires_at="2099-01-01T00:00:00Z", username="ada"),
        use_dpapi=False,
    )
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(
        ["--server", SERVER, *argv], http_factory=factory, out=out, err=err, sleep=lambda _s: None
    )
    return code, out.getvalue(), err.getvalue()


@pytest.mark.parametrize(
    "path",
    ["../escape.txt", "/etc/passwd", "C:/Windows/x.txt", "a/../../b.txt", "CON", "x:stream"],
)
def test_unsafe_output_paths_are_refused_before_writing(tmp_path, path):
    server = Server(
        outputs={"attempt": 1, "files": [{"path": path, "sha256": _sha(b"x"), "size": 1}]}
    )
    code, _, err = _run(server, "fetch", JOB, "-o", str(tmp_path / "t"))
    assert code == Exit.VERIFICATION and "unsafe" in err
    assert not (tmp_path / "escape.txt").exists()


def test_a_file_and_directory_clash_is_refused(tmp_path):
    files = [
        {"path": "a", "sha256": _sha(b"1"), "size": 1},
        {"path": "a/b", "sha256": _sha(b"2"), "size": 1},
    ]
    code, _, err = _run(
        Server(outputs={"attempt": 1, "files": files}), "fetch", JOB, "-o", str(tmp_path / "t")
    )
    assert code == Exit.VERIFICATION and "both a file and a directory" in err


def test_outputs_from_another_attempt_are_refused(tmp_path):
    server = Server(
        outputs={"attempt": 1, "files": []},
        job=_job(attempt=2),
    )
    code, _, err = _run(server, "fetch", JOB, "-o", str(tmp_path / "t"))
    assert code == Exit.VERIFICATION and "attempt" in err


def test_wrong_bytes_are_never_put_in_place(tmp_path):
    good = b"real result"
    server = Server(
        outputs={
            "attempt": 1,
            "files": [{"path": "r.txt", "sha256": _sha(good), "size": len(good)}],
        },
        blobs={_sha(good): b"fake result"},  # same length, different content
    )
    code, _, err = _run(server, "fetch", JOB, "-o", str(tmp_path / "t"))
    assert code == Exit.VERIFICATION and "does not match" in err
    assert not (tmp_path / "t" / "r.txt").exists()


def test_more_bytes_than_declared_are_refused(tmp_path):
    data = b"abc"
    server = Server(
        outputs={"attempt": 1, "files": [{"path": "r.txt", "sha256": _sha(data), "size": 3}]},
        blobs={_sha(data): b"abc" + b"x" * 10_000},
    )
    code, _, err = _run(server, "fetch", JOB, "-o", str(tmp_path / "t"))
    assert code == Exit.VERIFICATION and "more bytes than declared" in err


def test_declared_totals_above_policy_are_refused(tmp_path):
    big = {"path": "huge.bin", "sha256": _sha(b"x"), "size": 10**15}
    code, _, err = _run(
        Server(outputs={"attempt": 1, "files": [big]}), "fetch", JOB, "-o", str(tmp_path / "t")
    )
    assert code == Exit.VERIFICATION and "output limit" in err


def test_a_redirect_is_not_followed_and_the_token_goes_nowhere_else(tmp_path):
    server = Server()
    redirect = httpx.Response(302, headers={"Location": "https://attacker.example/steal"})
    server.job = None

    def handler(request):
        server.seen.append(request)
        return redirect

    server.handler = handler
    code, _, err = _run(server, "status", JOB)
    assert code == Exit.SERVER and "redirect" in err
    assert all(r.url.host == "evil.example" for r in server.seen)


def test_the_token_is_only_attached_to_its_own_origin():
    seen = []
    http = bind(
        httpx.Client(
            transport=httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200))
        ),
        "https://udcs.example.edu",
        TOKEN,
    )
    http.get("https://udcs.example.edu/api/v1/auth/me")
    http.get("https://other.example/api/v1/auth/me", headers={"Authorization": "Bearer planted"})
    assert seen[0].headers["Authorization"] == f"Bearer {TOKEN}"
    assert "Authorization" not in seen[1].headers


def test_escape_sequences_in_logs_are_stripped(tmp_path):
    hostile = "\x1b]0;pwned\x07\x1b[2J\x1b[31mred\x1b[0m and a bell\x07 \x9b31m"
    server = Server(
        logs=[{"id": 1, "at": "t", "attempt": 1, "source": "agent", "message": hostile}]
    )
    code, out, _ = _run(server, "logs", JOB)
    assert code == 0
    assert "\x1b" not in out and "\x07" not in out and "\x9b" not in out
    assert "red and a bell" in out


def test_server_errors_never_echo_the_token():
    assert TOKEN not in sanitize(f"bad token {TOKEN}", secrets=(TOKEN,))

    server = Server()
    server.handler = lambda request: httpx.Response(500, json={"detail": f"boom {TOKEN}"})
    code, out, err = _run(server, "status", JOB)
    assert code == Exit.SERVER and TOKEN not in out + err


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions")
def test_a_junction_planted_in_the_target_is_not_written_through(tmp_path):
    data = b"payload"
    server = Server(
        outputs={
            "attempt": 1,
            "files": [{"path": "sub/r.txt", "sha256": _sha(data), "size": len(data)}],
        },
        blobs={_sha(data): data},
    )
    target = tmp_path / "t"
    target.mkdir()
    _bind_target(target, server.outputs)  # get past the resume check to the write path
    victim = tmp_path / "victim"
    victim.mkdir()
    cmd = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
    subprocess.run(  # noqa: S603 -- fixed system binary, test-controlled paths
        [cmd, "/c", "mklink", "/J", str(target / "sub"), str(victim)],
        check=True,
        capture_output=True,
    )
    code, _, err = _run(server, "fetch", JOB, "-o", str(target), "--resume")
    assert code == Exit.VERIFICATION and "not a plain directory" in err
    assert not any(victim.iterdir())


def test_resume_continues_a_partial_download(tmp_path):
    data = os.urandom(300_000)
    digest = _sha(data)
    calls = []

    def blob(request):
        calls.append(request.headers.get("Range"))
        if request.headers.get("Range"):
            start = int(request.headers["Range"].split("=")[1].rstrip("-"))
            return httpx.Response(206, content=data[start:])
        return httpx.Response(200, content=data)

    server = Server(
        outputs={"attempt": 1, "files": [{"path": "big.bin", "sha256": digest, "size": len(data)}]}
    )
    original = server.handler

    def handler(request):
        if request.url.path.endswith(f"/blobs/{digest}"):
            server.seen.append(request)
            return blob(request)
        return original(request)

    server.handler = handler
    target = tmp_path / "t"
    _bind_target(target, server.outputs)
    (target / ".udcs-partial" / f"{digest}-{len(data)}").write_bytes(data[:100_000])
    code, _, err = _run(server, "fetch", JOB, "-o", str(target), "--resume")
    assert code == 0, err
    assert calls == ["bytes=100000-"]
    assert (target / "big.bin").read_bytes() == data
    receipt = json.loads((target / "udcs-receipt.json").read_text(encoding="utf-8"))
    assert receipt["outputs"]["files"][0]["sha256"] == digest
