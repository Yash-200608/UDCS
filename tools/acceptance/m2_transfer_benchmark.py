"""Measure package transfer performance and storage overhead (ADR 0002).

    uv run python tools/acceptance/m2_transfer_benchmark.py [--mib 64]

It starts a throwaway controller over TLS on loopback (temporary SQLite database and
blob store), then measures:
- upload throughput for incompressible and compressible data, and bytes on the wire;
- deduplicated re-upload (owned, skipped) and cross-package storage sharing;
- resume after an interrupted upload (bytes re-sent);
- download throughput and Range resume;
- staging (verify-while-copy) throughput;
- storage on disk versus logical bytes.

The results go to docs/acceptance/data/m2-transfer-benchmark.json. This is loopback on
one PC: it measures UDCS's own overhead, not a campus network.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import secrets
import socket
import ssl
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx
import trustme
import uvicorn

from udcs_agent.packages import (
    ChunkedUploader,
    NodeCache,
    TransferError,
    fetch_blob,
    manifest_from_dir,
    sha256_file,
    stage_package,
)
from udcs_controller.auth.permissions import Role
from udcs_controller.auth.service import create_user
from udcs_controller.config import Settings
from udcs_controller.database.migrate import upgrade_to_head
from udcs_controller.main import create_app

PASSWORD = secrets.token_urlsafe(24)  # generated per run; throwaway user, throwaway database


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _controller(tmp: Path):
    ca = trustme.CA()
    cert = ca.issue_cert("127.0.0.1")
    cert.cert_chain_pems[0].write_to_path(str(tmp / "server.pem"))
    cert.private_key_pem.write_to_path(str(tmp / "server.key"))
    ca.cert_pem.write_to_path(str(tmp / "ca.pem"))
    app = create_app(
        Settings(
            database_url=f"sqlite:///{(tmp / 'bench.db').as_posix()}",
            log_json=False,
            blob_dir=str(tmp / "blobs"),
            log_level="WARNING",
        )
    )
    upgrade_to_head(app.state.engine)
    with app.state.sessionmaker() as db:
        create_user(
            db, username="bench", display_name="Bench", password=PASSWORD, role=Role.RESEARCHER
        )
        db.commit()
    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            ssl_certfile=str(tmp / "server.pem"),
            ssl_keyfile=str(tmp / "server.key"),
            log_config=None,
            access_log=False,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    return server, thread, f"https://127.0.0.1:{port}/api/v1", tmp / "ca.pem"


def _disk_bytes(root: Path) -> int:
    return sum(p.stat().st_size for p in root.rglob("*") if p.is_file())


def _rate(size: int, seconds: float) -> float:
    return round(size / 2**20 / max(seconds, 1e-9), 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mib", type=int, default=64, help="size of each large test file")
    mib = parser.parse_args(argv).mib
    tmp = Path(tempfile.mkdtemp(prefix="udcs-bench-"))
    server, thread, base, ca = _controller(tmp)
    http = httpx.Client(
        base_url=base, verify=ssl.create_default_context(cafile=str(ca)), timeout=120
    )
    login = http.post("/auth/login", json={"username": "bench", "password": PASSWORD})
    http.headers["Authorization"] = f"Bearer {login.json()['access_token']}"
    results: dict = {"machine_note": "loopback TLS on one PC (i5-6500, SSD)", "file_mib": mib}
    data = tmp / "data"
    data.mkdir()
    rng = random.Random(42)  # noqa: S311 -- reproducible test data, not security
    (data / "random.bin").write_bytes(os.urandom(mib * 2**20))
    words = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon", b"zeta", b"theta"]
    with open(data / "text.csv", "wb") as handle:
        while handle.tell() < mib * 2**20:
            handle.write(b",".join(rng.choice(words) for _ in range(16)) + b"\n")
    small = data / "src"
    small.mkdir()
    for i in range(200):
        (small / f"mod_{i:03}.py").write_bytes(os.urandom(1024).hex().encode())

    uploader = ChunkedUploader(http, prefix="/blobs")
    for name in ("random.bin", "text.csv"):
        path = data / name
        size = path.stat().st_size
        started = time.perf_counter()
        stats = uploader.upload(path)
        seconds = time.perf_counter() - started
        results[f"upload_{name}"] = {
            "mib": round(size / 2**20, 1),
            "seconds": round(seconds, 2),
            "mib_per_s": _rate(size, seconds),
            "wire_mib": round(stats.sent_bytes / 2**20, 1),
            "wire_ratio": round(stats.sent_bytes / size, 3),
        }
        started = time.perf_counter()
        again = uploader.upload(path)
        results[f"reupload_{name}"] = {
            "skipped": again.skipped,
            "seconds": round(time.perf_counter() - started, 3),
            "note": "includes hashing the local file to learn its digest",
        }

    started = time.perf_counter()
    for path in sorted(small.iterdir()):
        uploader.upload(path)
    seconds = time.perf_counter() - started
    results["upload_200_small_files"] = {
        "seconds": round(seconds, 2),
        "files_per_s": round(200 / seconds, 1),
        "note": "per-file round trips (start, chunk, complete) dominate",
    }

    # Interrupted upload: the client "crashes" after 3 chunks, then a new client resumes.
    resume_file = data / "resume.bin"
    resume_file.write_bytes(os.urandom(mib * 2**20))

    class Crash(Exception):
        pass

    seen = {"chunks": 0}

    def crash_after_three(_offset: int) -> None:
        seen["chunks"] += 1
        if seen["chunks"] == 3:
            raise Crash

    try:
        ChunkedUploader(http, prefix="/blobs", compress=False).upload(
            resume_file, on_chunk=crash_after_three
        )
    except Crash:
        pass
    started = time.perf_counter()
    resumed = ChunkedUploader(http, prefix="/blobs", compress=False).upload(resume_file)
    results["resume_after_interruption"] = {
        "resumed_from_mib": round(resumed.resumed_from / 2**20, 1),
        "resent_mib": round(resumed.sent_bytes / 2**20, 1),
        "total_mib": mib,
        "seconds": round(time.perf_counter() - started, 2),
    }

    cache = NodeCache(tmp / "node")
    big = data / "random.bin"
    digest, size = sha256_file(big), big.stat().st_size
    started = time.perf_counter()
    fetch_blob(http, f"/blobs/{digest}", digest, size, cache)
    seconds = time.perf_counter() - started
    results["download_random.bin"] = {
        "mib_per_s": _rate(size, seconds),
        "seconds": round(seconds, 2),
        "includes": "transfer plus full SHA-256 verification",
    }
    cache2 = NodeCache(tmp / "node2")
    partial = cache2.path(digest).with_suffix(".part")
    partial.parent.mkdir(parents=True, exist_ok=True)
    with open(big, "rb") as src:
        partial.write_bytes(src.read(size // 2))
    _, moved = fetch_blob(http, f"/blobs/{digest}", digest, size, cache2)
    results["download_resume"] = {
        "already_had_mib": round(size / 2 / 2**20, 1),
        "fetched_mib": round(moved / 2**20, 1),
    }

    # Storage: two packages sharing 199 of 200 files.
    pkg_a, _ = manifest_from_dir(small, name="a", version="1", entry="mod_000.py")
    (small / "mod_199.py").write_bytes(b"changed = True\n")
    uploader.upload(small / "mod_199.py")
    pkg_b, _ = manifest_from_dir(small, name="b", version="1", entry="mod_000.py")
    for manifest in (pkg_a, pkg_b):
        response = http.post("/packages", json=manifest.model_dump(mode="json"))
        if response.status_code != 201:
            raise TransferError(response.text)
    logical = sum((data / n).stat().st_size for n in ("random.bin", "text.csv", "resume.bin"))
    logical += pkg_a.total_bytes + pkg_b.total_bytes
    stored = _disk_bytes(tmp / "blobs")
    results["storage"] = {
        "logical_mib": round(logical / 2**20, 2),
        "blob_store_mib": round(stored / 2**20, 2),
        "dedup_saving_mib": round((logical - stored) / 2**20, 2),
        "manifest_bytes_200_files": len(pkg_a.canonical_bytes()),
        "manifest_bytes_per_file": round(len(pkg_a.canonical_bytes()) / 200, 1),
        "database_mib": round((tmp / "bench.db").stat().st_size / 2**20, 2),
    }

    for item in pkg_a.files:
        fetch_blob(http, f"/blobs/{item.sha256}", item.sha256, item.size, cache)
    started = time.perf_counter()
    stage_package(tmp / "node", "bench-job", 1, pkg_a, {}, cache)
    results["stage_200_files"] = {
        "seconds": round(time.perf_counter() - started, 3),
        "note": "copy with SHA-256 verification of every byte",
    }

    server.should_exit = True
    thread.join(timeout=10)
    out = Path(__file__).resolve().parents[2] / "docs/acceptance/data/m2-transfer-benchmark.json"
    out.write_text(json.dumps(results, indent=1), encoding="utf-8")
    print(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
