"""User-code packaging (ADR 0002): validator, CAS, resumable transfer, pipeline integration.

User code stays disabled. The integration tests switch the controller flag on in
memory to exercise scheduling, staging and outputs. No real node offers user code,
and nothing here executes a package.
"""

from __future__ import annotations

import hashlib
import json
import uuid
import zlib

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from udcs_agent.packages import (
    ChunkedUploader,
    NodeCache,
    VerificationError,
    collect_outputs,
    fetch_blob,
    stage_package,
)
from udcs_shared.agent_api import PROTOCOL_VERSION
from udcs_shared.packages import (
    CHUNK_ENCODING_HEADER,
    CHUNK_RAW_SIZE_HEADER,
    CHUNK_SHA256_HEADER,
    PackageManifest,
    PackagePolicy,
    path_problem,
    policy_problems,
)

API = "/api/v1"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest(**overrides) -> dict:
    body = {
        "schema_version": 1,
        "kind": "package",
        "name": "demo",
        "version": "1.0",
        "files": [{"path": "main.py", "sha256": sha(b"print(1)"), "size": 8}],
        "entry": {"script": "main.py"},
    }
    body.update(overrides)
    return body


# -- validator ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "../evil.py",
        "a/../../evil.py",
        "/etc/passwd",
        "C:/Windows/evil.py",
        "\\\\server\\share\\x",
        "a\\..\\b",
        "file.txt:hidden",  # NTFS alternate data stream
        "CON",
        "nul.txt",
        "a/COM1.log",
        "x.",
        "trailing ",
        " leading",
        "a//b",
        "./a",
        "a/./b",
        "",
        "ctrl\x01char",
        "e\u0301.py",  # not NFC
        "a" * 241,
        ("seg" * 40) + "/x",
    ],
)
def test_unsafe_paths_are_rejected(path):
    assert path_problem(path) is not None
    with pytest.raises(ValidationError):
        PackageManifest.model_validate(
            _manifest(files=[{"path": path, "sha256": sha(b"x"), "size": 1}])
        )


@pytest.mark.parametrize("path", ["main.py", "pkg/sub/mod.py", "COM10.txt", "data/con_fig.json"])
def test_safe_paths_are_accepted(path):
    assert path_problem(path) is None


@pytest.mark.parametrize(
    ("files", "why"),
    [
        (["a.py", "a.py"], "duplicate"),
        (["A.py", "a.py"], "duplicate"),  # one file on Windows
        (["b.py", "a.py"], "sorted"),
        (["lib", "lib/x.py"], "both a file and a directory"),
    ],
)
def test_structural_attacks_are_rejected(files, why):
    entries = [{"path": p, "sha256": sha(p.encode()), "size": 1} for p in files]
    with pytest.raises(ValidationError, match=why):
        PackageManifest.model_validate(_manifest(files=entries, entry={"script": "a.py"}))


@pytest.mark.parametrize(
    ("overrides", "why"),
    [
        ({"schema_version": 2}, "schema_version"),
        ({"surprise": True}, "Extra inputs"),
        ({"entry": None}, "entry script"),
        ({"entry": {"script": "missing.py"}}, "entry script"),
        ({"entry": {"script": "main.sh"}}, "entry script"),
        ({"requirements": [{"name": "numpy", "version": "1.26.4"}]}, "approved environment"),
        ({"requirements": [{"name": "numpy", "version": ">=1"}]}, "exact release"),
        ({"name": "../x"}, "invalid package name"),
        ({"files": [{"path": "main.py", "sha256": "z" * 64, "size": 8}]}, "pattern"),
        ({"files": [{"path": "main.py", "sha256": sha(b"x"), "size": -1}]}, "greater"),
    ],
)
def test_malformed_manifests_are_rejected(overrides, why):
    with pytest.raises(ValidationError, match=why):
        PackageManifest.model_validate(_manifest(**overrides))


def test_environment_and_dataset_rules():
    env = {
        "schema_version": 1,
        "kind": "environment",
        "name": "sci",
        "version": "2026.1",
        "lock": [{"name": "NumPy", "version": "1.26.4"}],
        "platform": "win_amd64",
        "files": [{"path": "site/numpy/__init__.py", "sha256": sha(b"n"), "size": 1}],
    }
    assert PackageManifest.model_validate(env).lock[0].name == "numpy"  # PEP 503
    hook = dict(env, files=[{"path": "site/evil.pth", "sha256": sha(b"x"), "size": 1}])
    with pytest.raises(ValidationError, match=r"\.pth"):
        PackageManifest.model_validate(hook)
    with pytest.raises(ValidationError, match="lock"):
        PackageManifest.model_validate(dict(env, lock=[]))
    dataset = {"schema_version": 1, "kind": "dataset", "name": "d", "version": "1", "files": []}
    with pytest.raises(ValidationError, match="no entry"):
        PackageManifest.model_validate(dict(dataset, entry={"script": "x.py"}))


def test_policy_limits_are_configurable_not_hardcoded():
    manifest = PackageManifest.model_validate(
        _manifest(
            files=[{"path": "main.py", "sha256": sha(b"x"), "size": 10_000}],
            config={"k": "v" * 500},
            limits={"max_runtime_seconds": 7200},
        )
    )
    assert policy_problems(manifest, PackagePolicy()) == []
    strict = PackagePolicy(max_file_bytes=1000, max_config_bytes=100, max_runtime_seconds=60)
    problems = " | ".join(policy_problems(manifest, strict))
    assert "file over 1000" in problems and "config too large" in problems
    assert "runtime limit above policy" in problems


def test_digest_is_canonical():
    a = PackageManifest.model_validate(_manifest(config={"b": 1, "a": 2}))
    b = PackageManifest.model_validate(json.loads(json.dumps(_manifest(config={"a": 2, "b": 1}))))
    assert a.digest() == b.digest()
    assert a.digest() != PackageManifest.model_validate(_manifest(version="1.1")).digest()


# -- transfer ---------------------------------------------------------------------------------


def _put(
    client, headers, upload_id, offset, data, *, chunk_sha=None, encoding="identity", body=None
):
    return client.put(
        f"{API}/blobs/uploads/{upload_id}",
        params={"offset": offset},
        content=data if body is None else body,
        headers={
            **headers,
            CHUNK_SHA256_HEADER: chunk_sha or sha(data),
            CHUNK_ENCODING_HEADER: encoding,
            CHUNK_RAW_SIZE_HEADER: str(len(data)),
        },
    )


def _start(client, headers, data):
    response = client.post(
        f"{API}/blobs/uploads", headers=headers, json={"sha256": sha(data), "size": len(data)}
    )
    assert response.status_code == 200, response.text
    return response.json()


def _upload(client, headers, data):
    start = _start(client, headers, data)
    if start["upload_id"] is None:
        return
    if data:  # an empty file has no chunks, as in ChunkedUploader
        assert _put(client, headers, start["upload_id"], 0, data).status_code == 200
    done = client.post(f"{API}/blobs/uploads/{start['upload_id']}/complete", headers=headers)
    assert done.status_code == 200, done.text


def test_upload_resume_retry_and_dedup(client, student_headers):
    data = b"A" * 1000 + b"B" * 1000
    uid = _start(client, student_headers, data)["upload_id"]
    assert _put(client, student_headers, uid, 0, data[:1000]).json()["received"] == 1000
    # The client crashed; it starts again and resumes where the server says it is.
    again = _start(client, student_headers, data)
    assert again["upload_id"] == uid and again["received"] == 1000
    # A retried chunk (lost response) at the same offset is harmless.
    assert _put(client, student_headers, uid, 0, data[:1000]).json()["received"] == 1000
    assert _put(client, student_headers, uid, 1000, data[1000:]).json()["received"] == 2000
    done = client.post(f"{API}/blobs/uploads/{uid}/complete", headers=student_headers)
    assert done.json()["sha256"] == sha(data)
    # Owned now: the next upload of the same content moves no bytes.
    assert _start(client, student_headers, data)["upload_id"] is None
    assert client.get(f"{API}/blobs/{sha(data)}", headers=student_headers).content == data
    ranged = client.get(
        f"{API}/blobs/{sha(data)}", headers={**student_headers, "Range": "bytes=1500-"}
    )
    assert ranged.status_code == 206 and ranged.content == data[1500:]


def test_corrupted_gapped_and_mismatched_uploads_are_rejected(client, student_headers, app):
    data = b"payload" * 100
    uid = _start(client, student_headers, data)["upload_id"]
    assert _put(client, student_headers, uid, 0, data, chunk_sha="0" * 64).status_code == 422
    assert _put(client, student_headers, uid, 5, data[5:]).status_code == 409  # gap
    status = client.get(f"{API}/blobs/uploads/{uid}", headers=student_headers).json()
    assert status["received"] == 0
    # Every chunk is valid, but the whole is not the declared blob.
    other = b"z" * len(data)
    lying = client.post(
        f"{API}/blobs/uploads",
        headers=student_headers,
        json={"sha256": sha(b"declared-but-not-sent" * 34)[:64], "size": len(other)},
    ).json()["upload_id"]
    assert _put(client, student_headers, lying, 0, other).status_code == 200
    final = client.post(f"{API}/blobs/uploads/{lying}/complete", headers=student_headers)
    assert final.status_code == 422
    assert not any(app.state.blob_store.root.glob(f"*/{sha(other)}"))
    assert not list((app.state.blob_store.root / "uploads").glob("*.part"))


def test_decompression_bombs_and_oversize_are_rejected(client, student_headers, app):
    app.state.settings = app.state.settings.model_copy(
        update={"package_policy_json": json.dumps({"max_file_bytes": 8192, "chunk_bytes": 65536})}
    )
    too_big = client.post(
        f"{API}/blobs/uploads", headers=student_headers, json={"sha256": sha(b"x"), "size": 10**9}
    )
    assert too_big.status_code == 413
    data = b"\0" * 4000
    uid = _start(client, student_headers, data)["upload_id"]
    # Declares 4000 raw bytes but inflates to 2 MB: decoding stops after 4001 bytes.
    bomb = zlib.compress(b"\0" * 2_000_000)
    assert (
        _put(client, student_headers, uid, 0, data, encoding="zlib", body=bomb).status_code == 413
    )
    # A ~20-byte body claiming 4000 bytes exceeds the 100x ratio policy: refused undecoded.
    tiny = zlib.compress(data)
    assert len(data) > len(tiny) * PackagePolicy().max_compression_ratio
    assert (
        _put(client, student_headers, uid, 0, data, encoding="zlib", body=tiny).status_code == 413
    )
    garbage = _put(client, student_headers, uid, 0, data, encoding="zlib", body=b"not zlib" * 10)
    assert garbage.status_code == 422
    status = client.get(f"{API}/blobs/uploads/{uid}", headers=student_headers).json()
    assert status["received"] == 0  # nothing was written by any rejected chunk


def test_no_cross_user_existence_oracle(client, make_user, login, student_headers):
    data = b"secret dataset bytes"
    _upload(client, student_headers, data)
    make_user("mallory")
    mallory = login("mallory")
    # Mallory knows the hash, but she is still asked to upload (no "already exists" answer),
    # and she cannot download it.
    assert _start(client, mallory, data)["upload_id"] is not None
    assert client.get(f"{API}/blobs/{sha(data)}", headers=mallory).status_code == 404
    # A package naming a blob she does not possess is refused.
    manifest = _manifest(files=[{"path": "main.py", "sha256": sha(data), "size": len(data)}])
    refused = client.post(f"{API}/packages", headers=mallory, json=manifest)
    assert refused.status_code == 422 and "not uploaded by you" in refused.text


# -- registration, approval, pipeline -----------------------------------------------------------


@pytest.fixture
def uploaded_package(client, student_headers):
    main = b"print('hello from a package')\n"
    _upload(client, student_headers, main)
    body = _manifest(files=[{"path": "main.py", "sha256": sha(main), "size": len(main)}])
    response = client.post(f"{API}/packages", headers=student_headers, json=body)
    assert response.status_code == 201, response.text
    return response.json()["digest"], main


def test_registration_checks_sizes_and_approvals(client, student_headers, admin_headers):
    main = b"x = 1\n"
    _upload(client, student_headers, main)
    wrong = _manifest(files=[{"path": "main.py", "sha256": sha(main), "size": 999}])
    assert client.post(f"{API}/packages", headers=student_headers, json=wrong).status_code == 422
    site = b"# numpy stand-in\n"
    _upload(client, student_headers, site)
    env = {
        "schema_version": 1,
        "kind": "environment",
        "name": "sci",
        "version": "1",
        "python": "3.12",
        "lock": [{"name": "numpy", "version": "1.26.4"}],
        "platform": "win_amd64",
        "files": [{"path": "site/numpy.py", "sha256": sha(site), "size": len(site)}],
    }
    env_digest = client.post(f"{API}/packages", headers=student_headers, json=env).json()["digest"]
    needs = _manifest(
        files=[{"path": "main.py", "sha256": sha(main), "size": len(main)}],
        environment=env_digest,
        requirements=[{"name": "numpy", "version": "1.26.4"}],
    )
    unapproved = client.post(f"{API}/packages", headers=student_headers, json=needs)
    assert unapproved.status_code == 422 and "approved environment" in unapproved.text
    approve = f"{API}/admin/packages/{env_digest}/approve"
    assert client.post(approve, headers=student_headers).status_code == 403
    assert client.post(approve, headers=admin_headers).status_code == 200
    assert client.post(f"{API}/packages", headers=student_headers, json=needs).status_code == 201
    mismatch = dict(needs, requirements=[{"name": "numpy", "version": "2.0.0"}])
    bad = client.post(f"{API}/packages", headers=student_headers, json=mismatch)
    assert bad.status_code == 422 and "not in the approved environment" in bad.text
    bad = client.post(f"{API}/packages", headers=student_headers, json=dict(needs, python="3.11"))
    assert bad.status_code == 422 and "Python 3.11" in bad.text


def test_package_jobs_are_refused_while_user_code_is_disabled(
    client, student_headers, uploaded_package
):
    digest, _ = uploaded_package
    response = client.post(
        f"{API}/jobs",
        headers=student_headers,
        json={"kind": "cpu", "total_units": 1, "package": digest},
    )
    assert response.status_code == 403 and "disabled" in response.text


def _sync(client, headers, *, user_code=False):
    return client.post(
        f"{API}/agent/jobs/sync",
        headers=headers,
        json={
            "protocol_version": PROTOCOL_VERSION,
            "reports": [],
            "capacity": {
                "accept": True,
                "slots": 2,
                "kinds": ["cpu"],
                "memory_available_mb": 4096,
                "user_code": user_code,
            },
        },
    ).json()


def _package_job(app, client, headers, digest):
    app.state.settings = app.state.settings.model_copy(update={"user_code_enabled": True})
    response = client.post(
        f"{API}/jobs", headers=headers, json={"kind": "cpu", "total_units": 1, "package": digest}
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_end_to_end_package_pipeline_without_execution(
    app, client, student_headers, enroll, inventory_factory, uploaded_package, tmp_path
):
    """User upload -> registration -> scheduling -> node fetch, verify and stage -> outputs
    -> user download. The package never executes: here a test node offers user code only
    to drive the pipeline."""
    digest, main = uploaded_package
    job = _package_job(app, client, student_headers, digest)
    _, node, _ = enroll(inventory_factory(hostname="pkg-node"))
    _, other, _ = enroll(inventory_factory(hostname="other-node"))
    assert _sync(client, node, user_code=False)["assignments"] == []  # only to offering nodes
    [assignment] = _sync(client, node, user_code=True)["assignments"]
    assert assignment["spec"]["package"] == digest
    attempt = assignment["attempt"]

    closure = client.get(
        f"{API}/agent/jobs/{job['id']}/package", headers=node, params={"attempt": attempt}
    ).json()
    manifests = {d: PackageManifest.model_validate(m) for d, m in closure["manifests"].items()}
    package = manifests[digest]
    blob_url = f"{API}/agent/blobs/{sha(main)}"
    # Fencing: another node, or a stale attempt, cannot read the package.
    params = {"job": job["id"], "attempt": attempt}
    assert client.get(blob_url, headers=other, params=params).status_code == 404
    stale = {"job": job["id"], "attempt": attempt + 1}
    assert client.get(blob_url, headers=node, params=stale).status_code == 404

    node_http = TestClient(app, headers=node)
    data_dir = tmp_path / "node"
    cache = NodeCache(data_dir)
    for item in package.files:
        _, moved = fetch_blob(
            node_http,
            f"{API}/agent/blobs/{item.sha256}",
            item.sha256,
            item.size,
            cache,
            params=params,
        )
        assert moved == item.size
    _, moved = fetch_blob(node_http, "unused", sha(main), len(main), cache)
    assert moved == 0  # node-local deduplication

    staged = stage_package(data_dir, job["id"], attempt, package, manifests, cache)
    assert staged.entry.read_bytes() == main
    assert staged.output.is_dir() and staged.config.read_bytes() == b"{}"
    assert staged.root.name.endswith(f"-{attempt}")  # unique per job and attempt

    # Pretend the (disabled) execution produced outputs; collect and return them.
    (staged.output / "result.csv").write_bytes(b"a,b\n1,2\n")
    (staged.output / "plots").mkdir()
    (staged.output / "plots" / "p.svg").write_bytes(b"<svg/>")
    outputs, paths = collect_outputs(
        staged.output,
        attempt=attempt,
        snapshot_dir=staged.collected,
        max_files=10,
        max_bytes=10_000,
    )
    assert all(p.is_relative_to(staged.collected) for p in paths.values())  # private copy
    uploader = ChunkedUploader(
        node_http, prefix=f"{API}/agent/blobs", extra={"job_id": job["id"], "attempt": attempt}
    )
    for item in outputs.files:
        uploader.upload(paths[item.path], sha256=item.sha256)
    url = f"{API}/agent/jobs/{job['id']}/outputs"
    assert node_http.put(url, json=outputs.model_dump(mode="json")).status_code == 204
    stale_outputs = dict(outputs.model_dump(mode="json"), attempt=attempt + 1)
    assert node_http.put(url, json=stale_outputs).status_code == 409

    listed = client.get(f"{API}/jobs/{job['id']}/outputs", headers=student_headers).json()
    assert [f["path"] for f in listed["outputs"]["files"]] == ["plots/p.svg", "result.csv"]
    csv = next(f for f in listed["outputs"]["files"] if f["path"] == "result.csv")
    assert (
        client.get(f"{API}/blobs/{csv['sha256']}", headers=student_headers).content == b"a,b\n1,2\n"
    )


def test_output_limits_and_missing_blobs_are_enforced(
    app, client, student_headers, enroll, inventory_factory, uploaded_package
):
    digest, _ = uploaded_package
    job = _package_job(app, client, student_headers, digest)
    _, node, _ = enroll(inventory_factory(hostname="lim-node"))
    [assignment] = _sync(client, node, user_code=True)["assignments"]
    url = f"{API}/agent/jobs/{job['id']}/outputs"
    never = {
        "attempt": assignment["attempt"],
        "files": [{"path": "out.bin", "sha256": sha(b"never"), "size": 5}],
    }
    assert client.put(url, headers=node, json=never).status_code == 422
    too_big = {
        "attempt": assignment["attempt"],
        "files": [{"path": "big.bin", "sha256": sha(b"x"), "size": 10**12}],
    }
    assert client.put(url, headers=node, json=too_big).status_code == 413


def test_tampered_node_cache_is_caught_at_staging(
    tmp_path, client, student_headers, uploaded_package
):
    digest, main = uploaded_package
    package = PackageManifest.model_validate(
        client.get(f"{API}/packages/{digest}", headers=student_headers).json()["manifest"]
    )
    cache = NodeCache(tmp_path)
    blob = cache.path(sha(main))
    blob.parent.mkdir(parents=True)
    evil = b"x" * len(main)  # same length: only the hash can catch it
    assert evil != main
    blob.write_bytes(evil)  # replaced after download
    with pytest.raises(VerificationError):
        stage_package(tmp_path, str(uuid.uuid4()), 1, package, {digest: package}, cache)
    assert not any((tmp_path / "staging").iterdir())  # nothing left behind


def test_chunked_uploader_resumes_after_a_dropped_connection(client, student_headers, app):
    data = bytes(range(256)) * 600  # 153600 bytes: three 64 KiB chunks
    app.state.settings = app.state.settings.model_copy(
        update={"package_policy_json": json.dumps({"chunk_bytes": 65536})}
    )
    real = TestClient(app, headers=student_headers)
    dropped = {"count": 0}

    class Flaky(httpx.BaseTransport):
        def handle_request(self, request):
            query = request.url.query.decode() if isinstance(request.url.query, bytes) else ""
            if request.method == "PUT" and dropped["count"] == 0 and "offset=65536" in query:
                dropped["count"] += 1
                raise httpx.ReadError("connection dropped")
            return real._transport.handle_request(request)

    flaky = httpx.Client(transport=Flaky(), base_url=str(real.base_url), headers=dict(real.headers))
    path = app.state.blob_store.root.parent / "big.bin"
    path.write_bytes(data)
    stats = ChunkedUploader(flaky, prefix=f"{API}/blobs", compress=False).upload(path)
    assert dropped["count"] == 1 and stats.size == len(data)
    assert client.get(f"{API}/blobs/{sha(data)}", headers=student_headers).content == data


def test_decompression_is_always_bounded(client, student_headers, monkeypatch):
    """A bomb must be stopped *while* decoding, not after inflating it fully."""
    import udcs_controller.packages.service as service

    calls = []
    real = zlib.decompressobj

    class Spy:
        def __init__(self):
            self._inner = real()

        def decompress(self, data, max_length=0):
            calls.append(max_length)
            return self._inner.decompress(data, max_length)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    monkeypatch.setattr(service.zlib, "decompressobj", Spy)
    data = b"\0" * 4000
    uid = _start(client, student_headers, data)["upload_id"]
    bomb = zlib.compress(b"\0" * 100_000)
    _put(client, student_headers, uid, 0, data, encoding="zlib", body=bomb)
    assert calls and all(0 < bound <= len(data) + 1 for bound in calls)


# -- security review regressions (ADR 0002, "Review findings") ---------------------------------


def _node_put_blob(client, node, job_id, attempt, data):
    start = client.post(
        f"{API}/agent/blobs/uploads",
        headers=node,
        json={"sha256": sha(data), "size": len(data), "job_id": job_id, "attempt": attempt},
    )
    if start.status_code != 200 or start.json()["upload_id"] is None:
        return start
    uid = start.json()["upload_id"]
    if data:
        put = client.put(
            f"{API}/agent/blobs/uploads/{uid}",
            params={"offset": 0},
            content=data,
            headers={**node, CHUNK_SHA256_HEADER: sha(data), CHUNK_RAW_SIZE_HEADER: str(len(data))},
        )
        assert put.status_code == 200, put.text
    return client.post(f"{API}/agent/blobs/uploads/{uid}/complete", headers=node)


def _assigned(app, client, student_headers, enroll, inventory_factory, digest, host):
    job = _package_job(app, client, student_headers, digest)
    _, node, _ = enroll(inventory_factory(hostname=host))
    [assignment] = _sync(client, node, user_code=True)["assignments"]
    return job, node, assignment["attempt"]


def test_outputs_cannot_claim_another_users_blob(
    app, client, student_headers, make_user, login, enroll, inventory_factory, uploaded_package
):
    """F1 (high): naming a hash in an output manifest must not grant the job owner a blob
    that exists in the store but was never uploaded by this attempt."""
    make_user("victim")
    victim = login("victim")
    secret = b"the victim's private thesis data"
    _upload(client, victim, secret)
    digest, _ = uploaded_package
    job, node, attempt = _assigned(
        app, client, student_headers, enroll, inventory_factory, digest, "f1-node"
    )
    url = f"{API}/agent/jobs/{job['id']}/outputs"
    claim = {"attempt": attempt, "files": [{"path": "x", "sha256": sha(secret), "size": 32}]}
    missing = {"attempt": attempt, "files": [{"path": "x", "sha256": sha(b"nope"), "size": 4}]}
    refused = client.put(url, headers=node, json=claim)
    absent = client.put(url, headers=node, json=missing)
    # The same answer for "exists but not uploaded here" and "does not exist": no oracle.
    assert refused.status_code == absent.status_code == 422
    assert refused.json()["detail"] == absent.json()["detail"]
    assert client.get(f"{API}/blobs/{sha(secret)}", headers=student_headers).status_code == 404

    # Uploaded by this attempt: accepted, and only once per attempt.
    result = b"a real output"
    assert _node_put_blob(client, node, job["id"], attempt, result).status_code == 200
    ok = {"attempt": attempt, "files": [{"path": "r.txt", "sha256": sha(result), "size": 13}]}
    assert client.put(url, headers=node, json=ok).status_code == 204
    assert client.put(url, headers=node, json=ok).status_code == 409


def test_node_uploads_are_bounded_per_attempt_and_fenced(
    app, client, student_headers, enroll, inventory_factory
):
    """A node cannot fill the store before it reports, nor upload after its attempt ends."""
    main = b"print(2)"
    _upload(client, student_headers, main)
    body = _manifest(
        files=[{"path": "main.py", "sha256": sha(main), "size": len(main)}],
        limits={"max_output_files": 2, "max_output_bytes": 100},
    )
    digest = client.post(f"{API}/packages", headers=student_headers, json=body).json()["digest"]
    job, node, attempt = _assigned(
        app, client, student_headers, enroll, inventory_factory, digest, "f2-node"
    )
    assert _node_put_blob(client, node, job["id"], attempt, b"one").status_code == 200
    again = _node_put_blob(client, node, job["id"], attempt, b"one")
    assert again.status_code == 200 and again.json()["upload_id"] is None  # already proven
    assert _node_put_blob(client, node, job["id"], attempt, b"x" * 101).status_code == 413
    assert _node_put_blob(client, node, job["id"], attempt, b"two").status_code == 200
    third = _node_put_blob(client, node, job["id"], attempt, b"three")
    assert third.status_code == 413 and "output files" in third.text

    from udcs_controller.jobs.models import Job
    from udcs_shared.jobs import JobState

    with app.state.sessionmaker() as db:
        db.get(Job, uuid.UUID(job["id"])).state = JobState.CANCELLED
        db.commit()
    late = client.post(
        f"{API}/agent/blobs/uploads",
        headers=node,
        json={"sha256": sha(b"late"), "size": 4, "job_id": job["id"], "attempt": attempt},
    )
    assert late.status_code == 409


def test_abandoned_sessions_are_swept_and_reserve_quota(app, client, student_headers):
    """Expired partial files are deleted; open sessions count against the quota; the
    quota is re-checked at completion."""
    from datetime import timedelta

    from udcs_controller.packages.models import BlobUpload

    data = b"y" * 70_000
    uid = _start(client, student_headers, data)["upload_id"]
    assert _put(client, student_headers, uid, 0, data).status_code == 200
    partial = app.state.blob_store.partial(uuid.UUID(uid))
    assert partial.exists()
    with app.state.sessionmaker() as db:
        db.get(BlobUpload, uuid.UUID(uid)).expires_at -= timedelta(days=2)
        db.commit()
    _start(client, student_headers, b"any new upload runs the sweep")
    assert not partial.exists()
    done = client.post(f"{API}/blobs/uploads/{uid}/complete", headers=student_headers)
    assert done.status_code == 409

    app.state.settings = app.state.settings.model_copy(
        update={"package_policy_json": json.dumps({"user_storage_bytes": 200_000})}
    )
    first = client.post(
        f"{API}/blobs/uploads", headers=student_headers, json={"sha256": sha(b"a"), "size": 150_000}
    )
    assert first.status_code == 200
    second = client.post(
        f"{API}/blobs/uploads", headers=student_headers, json={"sha256": sha(b"b"), "size": 100_000}
    )
    assert second.status_code == 413


def test_oversized_request_bodies_are_refused_before_buffering(client, student_headers):
    """Chunk and JSON bodies are bounded by declared length and by bytes that arrive."""
    data = b"z" * 1000
    uid = _start(client, student_headers, data)["upload_id"]
    limit = PackagePolicy().chunk_bytes
    declared = client.put(
        f"{API}/blobs/uploads/{uid}",
        params={"offset": 0},
        content=b"\0" * (limit + 1),
        headers={**student_headers, CHUNK_SHA256_HEADER: sha(data)},
    )
    assert declared.status_code == 413

    def streamed():  # no Content-Length: chunked transfer encoding
        for _ in range(5):
            yield b"\0" * (2 * 2**20)

    counted = client.put(
        f"{API}/blobs/uploads/{uid}",
        params={"offset": 0},
        content=streamed(),
        headers={**student_headers, CHUNK_SHA256_HEADER: sha(data)},
    )
    assert counted.status_code == 413
    big_json = client.post(
        f"{API}/packages",
        headers={**student_headers, "content-type": "application/json"},
        content=b'{"x": "' + b"a" * (5 * 2**20) + b'"}',
    )
    assert big_json.status_code == 413
    assert _put(client, student_headers, uid, 0, data).status_code == 200  # normal use works


def test_identical_content_registered_by_two_users_is_usable_by_both(
    app, client, student_headers, make_user, login, uploaded_package
):
    """Registering someone's content first must not lock them out."""
    digest, main = uploaded_package
    make_user("second")
    second = login("second")
    _upload(client, second, main)  # possession proven independently
    body = _manifest(files=[{"path": "main.py", "sha256": sha(main), "size": len(main)}])
    again = client.post(f"{API}/packages", headers=second, json=body)
    assert again.status_code == 201 and again.json()["digest"] == digest
    app.state.settings = app.state.settings.model_copy(update={"user_code_enabled": True})
    for headers in (student_headers, second):
        made = client.post(
            f"{API}/jobs",
            headers=headers,
            json={"kind": "cpu", "total_units": 1, "package": digest},
        )
        assert made.status_code == 201, made.text


def test_zero_byte_files_upload_and_register(client, student_headers):
    """An empty __init__.py is a normal package file."""
    _upload(client, student_headers, b"")
    main = b"import pkg\n"
    _upload(client, student_headers, main)
    body = _manifest(
        files=[
            {"path": "main.py", "sha256": sha(main), "size": len(main)},
            {"path": "pkg/__init__.py", "sha256": sha(b""), "size": 0},
        ]
    )
    assert client.post(f"{API}/packages", headers=student_headers, json=body).status_code == 201


def test_kill_switch_stops_dispatch_and_node_endpoints(
    app, client, student_headers, enroll, inventory_factory, uploaded_package
):
    """Turning user code off on the controller keeps package jobs from nodes, even ones
    that claim to offer user code, and closes the package endpoints."""
    digest, main = uploaded_package
    job = _package_job(app, client, student_headers, digest)  # submitted while on
    app.state.settings = app.state.settings.model_copy(update={"user_code_enabled": False})
    _, node, _ = enroll(inventory_factory(hostname="ks-node"))
    assert _sync(client, node, user_code=True)["assignments"] == []
    closure = client.get(
        f"{API}/agent/jobs/{job['id']}/package", headers=node, params={"attempt": 1}
    )
    assert closure.status_code == 404
    blob = client.get(
        f"{API}/agent/blobs/{sha(main)}", headers=node, params={"job": job["id"], "attempt": 1}
    )
    assert blob.status_code == 404
