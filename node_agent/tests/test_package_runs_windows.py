"""Researcher packages executing for real: staged, run in AppContainer inside a Job
Object, collected after the whole process tree is gone (ADR 0003).

The hostile packages here try what a malicious or careless package would: read the
node credential, another job's files and the user's profile, write outside out/,
reach the network, leave a child running, plant links in out/, exhaust memory, run
forever and fill the disk. Each attempt is made from inside the sandbox and recorded
by the package itself; the test then checks the boundary held.
"""

from __future__ import annotations

import hashlib
import json
import socket
import sys
import time
import uuid
from pathlib import Path

import pytest

from udcs_agent import package_runs
from udcs_agent.governor.classifier import Assessment
from udcs_agent.packages import NodeCache, stage_package
from udcs_agent.workloads.manager import WorkloadManager, WorkloadSpec, WorkloadState
from udcs_shared.jobs import FailureKind, PackageRunLimits
from udcs_shared.packages import PackageManifest
from udcs_shared.protection import ProtectionLevel, ProtectionPolicy

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows AppContainer")

L = ProtectionLevel
POLICY = ProtectionPolicy()
RAM = 16 * 2**30
LIMITS = PackageRunLimits(
    max_runtime_seconds=120,
    max_output_bytes=8 * 2**20,
    max_output_files=100,
    max_output_entries=1000,
    max_output_depth=16,
)


@pytest.fixture(scope="module")
def isolation(tmp_path_factory):
    from udcs_agent.workloads.isolation import AppContainerIsolation

    backend = AppContainerIsolation(tmp_path_factory.mktemp("pkg-iso"))
    backend.ensure_runtime()
    return backend


def _stage(data_dir: Path, files: dict[str, str], *, args=()) -> Path:
    cache = NodeCache(data_dir)
    entries = []
    for path, text in sorted(files.items()):
        data = text.encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        blob = cache.path(digest)
        blob.parent.mkdir(parents=True, exist_ok=True)
        blob.write_bytes(data)
        entries.append({"path": path, "sha256": digest, "size": len(data)})
    manifest = PackageManifest.model_validate(
        {
            "schema_version": 1,
            "kind": "package",
            "name": "t",
            "version": "1",
            "files": entries,
            "entry": {"script": "main.py", "args": list(args)},
            "config": {"seed": 7},
        }
    )
    staged = stage_package(data_dir, str(uuid.uuid4()), 1, manifest, {}, cache)
    for name in ("state", "logs", "tmp"):
        (staged.root / name).mkdir(exist_ok=True)
    return staged.root


def _run(data_dir: Path, isolation, root: Path, *, runtime=0, storage=0, memory_mb=256, timeout=90):
    manager = WorkloadManager(data_dir, restart_backoff_seconds=0.5, isolation=isolation)
    wid = "pkg-" + uuid.uuid4().hex[:12]
    manager.add(
        WorkloadSpec(
            id=wid,
            kind="cpu",
            memory_mb=memory_mb,
            checkpointable=False,
            isolation="appcontainer",
            package_root=str(root),
            entry="main.py",
            import_paths=[str(root / "src")],
            read_only=[str(root / "src"), str(root / "config.json")],
            max_runtime_seconds=runtime,
            storage_bytes=storage,
        )
    )
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            manager.enforce(POLICY.envelopes[L.OPEN], Assessment(L.OPEN, ()), POLICY, RAM)
            if manager.states()[wid] in (WorkloadState.COMPLETED, WorkloadState.FAILED):
                break
            time.sleep(0.2)
        return manager.job_snapshot("pkg-")[wid]
    finally:
        manager.shutdown()


def _report(root: Path) -> dict:
    return json.loads((root / "out" / "report.json").read_text(encoding="utf-8"))


def test_a_package_runs_in_appcontainer_and_its_outputs_are_collected(tmp_path, isolation):
    root = _stage(
        tmp_path,
        {
            "main.py": (
                "import json, sys\n"
                "from lib.util import double\n"
                "cfg = json.load(open('config.json'))\n"
                "print('hello from the package')\n"
                "open('out/result.txt', 'w').write(str(double(cfg['seed'])))\n"
                "open('state/checkpoint.bin', 'wb').write(b'progress-1')\n"
                "sys.exit(0)\n"
            ),
            "lib/__init__.py": "",
            "lib/util.py": "def double(x):\n    return 2 * x\n",
        },
    )
    item = _run(tmp_path, isolation, root)
    assert item["state"] == "completed", item["events"][-5:]
    assert item["outcome"] == "exited" and item["last_exit_code"] == 0
    assert any("started (package, appcontainer)" in what for _t, what in item["events"])
    manifest, paths = package_runs.collect(root, 1, LIMITS)
    names = {f.path: f for f in manifest.files}
    assert paths["result.txt"].read_bytes() == b"14"
    assert "udcs-logs/stdout.txt" in names
    assert b"hello from the package" in paths["udcs-logs/stdout.txt"].read_bytes()
    assert (root / "state" / "checkpoint.bin").read_bytes() == b"progress-1"


def test_exit_codes_and_crashes_are_results_not_retries(tmp_path, isolation):
    root = _stage(tmp_path, {"main.py": "import sys\nsys.exit(3)\n"})
    item = _run(tmp_path, isolation, root)
    assert item["state"] == "completed" and item["last_exit_code"] == 3
    assert item["failures"] == 0  # the package's exit code is not an infrastructure failure

    root = _stage(tmp_path, {"main.py": "raise RuntimeError('boom from the package')\n"})
    item = _run(tmp_path, isolation, root)
    assert item["state"] == "completed" and item["last_exit_code"] == 1
    assert "boom from the package" in (root / "logs" / "stderr.txt").read_text(encoding="utf-8")


HOSTILE = r"""
import json, os, socket, subprocess, sys
report = {}
def attempt(name, fn):
    try:
        fn()
        report[name] = "ALLOWED"
    except Exception as exc:
        report[name] = "denied: " + type(exc).__name__
target = json.load(open("src/targets.json"))
attempt("read_node_credential", lambda: open(target["credential"], "rb").read())
attempt("read_other_job", lambda: open(target["other_job"], "rb").read())
attempt("list_data_dir", lambda: os.listdir(target["data_dir"]))
attempt("read_user_profile", lambda: os.listdir(target["profile"]))
attempt("write_source", lambda: open("src/main.py", "a").write("#x"))
attempt("write_outside_out", lambda: open(target["outside"], "w").write("x"))
attempt("write_config", lambda: open("config.json", "a").write("x"))
def connect():
    with socket.create_connection(("127.0.0.1", target["port"]), timeout=3):
        pass
attempt("network_loopback", connect)
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
report["child_pid"] = child.pid
json.dump(report, open("out/report.json", "w"))
"""


def test_a_hostile_package_cannot_reach_credentials_other_jobs_or_the_network(tmp_path, isolation):
    data_dir = tmp_path
    (data_dir / "node-credential.bin").write_bytes(b"NODE SECRET")
    other = _stage(data_dir, {"main.py": "print(1)\n", "secret.py": "TOKEN = 'other-job'\n"})
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.1)
    import os

    targets = {
        "credential": str(data_dir / "node-credential.bin"),
        "other_job": str(other / "src" / "secret.py"),
        "data_dir": str(data_dir),
        "profile": os.path.join(os.environ["USERPROFILE"], "Documents"),
        "outside": str(data_dir / "planted.txt"),
        "port": listener.getsockname()[1],
    }
    root = _stage(data_dir, {"main.py": HOSTILE, "targets.json": json.dumps(targets)})
    try:
        item = _run(data_dir, isolation, root)
        accepted = None
        try:
            accepted, _ = listener.accept()
        except OSError:
            pass
    finally:
        listener.close()
    assert item["state"] == "completed", item["events"][-5:]
    report = _report(root)
    allowed = {k: v for k, v in report.items() if v == "ALLOWED"}
    assert not allowed, report
    assert accepted is None, "the sandbox reached a loopback listener"
    assert not (data_dir / "planted.txt").exists()
    import psutil

    assert not psutil.pid_exists(report["child_pid"]), "a child outlived the run"


def test_links_planted_in_out_are_refused_at_collection(tmp_path, isolation):
    secret_dir = tmp_path / "victim"
    secret_dir.mkdir()
    (secret_dir / "thesis.docx").write_bytes(b"years of work")
    code = (
        "import _winapi, os, json\n"
        "r = {}\n"
        f"try:\n    _winapi.CreateJunction({str(secret_dir)!r}, 'out/loot')\n"
        "    r['junction'] = 'made'\n"
        "except OSError as e:\n    r['junction'] = 'refused'\n"
        "try:\n    os.link('src/main.py', 'out/hard.txt')\n    r['hardlink'] = 'made'\n"
        "except OSError as e:\n    r['hardlink'] = 'refused'\n"
        "json.dump(r, open('out/r.json', 'w'))\n"
    )
    root = _stage(tmp_path, {"main.py": code})
    item = _run(tmp_path, isolation, root)
    assert item["state"] == "completed", item["events"][-5:]
    made = json.loads((root / "out" / "r.json").read_text())
    if made["junction"] == "made" or made["hardlink"] == "made":
        with pytest.raises(package_runs.RunFailed) as refused:
            package_runs.collect(root, 1, LIMITS)
        assert refused.value.kind == FailureKind.WORKLOAD
    else:  # the sandbox could not even create them: nothing to collect through
        manifest, _ = package_runs.collect(root, 1, LIMITS)
        assert [f.path for f in manifest.files if not f.path.startswith("udcs-logs/")] == ["r.json"]
    assert (secret_dir / "thesis.docx").read_bytes() == b"years of work"


def test_runtime_limit_kills_a_runaway_package(tmp_path, isolation):
    root = _stage(tmp_path, {"main.py": "while True:\n    pass\n"})
    started = time.monotonic()
    item = _run(tmp_path, isolation, root, runtime=3, timeout=60)
    assert item["state"] == "failed" and item["outcome"] == "runtime_limit"
    assert time.monotonic() - started < 45


def test_storage_limit_stops_a_package_filling_the_disk(tmp_path, isolation):
    code = (
        "chunk = b'x' * (1 << 20)\n"
        "with open('out/big.bin', 'wb') as f:\n"
        "    for _ in range(400):\n"
        "        f.write(chunk)\n"
        "        f.flush()\n"
        "        import time; time.sleep(0.02)\n"
    )
    root = _stage(tmp_path, {"main.py": code})
    item = _run(tmp_path, isolation, root, storage=16 * 2**20, timeout=90)
    assert item["state"] == "failed" and item["outcome"] == "storage_limit", item["events"][-5:]
    assert (root / "out" / "big.bin").stat().st_size < 400 * 2**20


def test_memory_is_capped_by_the_job_object(tmp_path, isolation):
    code = (
        "import sys\n"
        "try:\n    hog = bytearray(1024 * 1024 * 1024)\n    sys.exit(0)\n"
        "except MemoryError:\n    sys.exit(42)\n"
    )
    root = _stage(tmp_path, {"main.py": code})
    item = _run(tmp_path, isolation, root, memory_mb=128)
    assert item["state"] == "completed"
    assert item["last_exit_code"] != 0  # 42 (MemoryError) or killed by the job's limit


def test_outputs_over_the_limit_are_the_packages_failure(tmp_path, isolation):
    code = "for i in range(5):\n    open(f'out/f{i}.txt', 'w').write('x' * 1000)\n"
    root = _stage(tmp_path, {"main.py": code})
    item = _run(tmp_path, isolation, root)
    assert item["state"] == "completed"
    tight = LIMITS.model_copy(update={"max_output_files": 3})
    with pytest.raises(package_runs.RunFailed) as refused:
        package_runs.collect(root, 1, tight)
    assert refused.value.kind == FailureKind.WORKLOAD


def test_outputs_cannot_impersonate_the_run_logs(tmp_path, isolation):
    code = (
        "import os\nos.makedirs('out/udcs-logs')\n"
        "open('out/udcs-logs/stdout.txt', 'w').write('fake')\n"
    )
    root = _stage(tmp_path, {"main.py": code})
    item = _run(tmp_path, isolation, root)
    assert item["state"] == "completed"
    with pytest.raises(package_runs.RunFailed, match="reserved"):
        package_runs.collect(root, 1, LIMITS)


def test_a_package_imports_from_its_approved_environment(tmp_path, isolation):
    """The environment is staged read-only and is on the import path; nothing is
    installed and site-packages processing (.pth) never runs (-I -S)."""
    cache = NodeCache(tmp_path)

    def blob(text: str) -> dict:
        data = text.encode()
        digest = hashlib.sha256(data).hexdigest()
        path = cache.path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return {"sha256": digest, "size": len(data)}

    env = PackageManifest.model_validate(
        {
            "schema_version": 1,
            "kind": "environment",
            "name": "sci",
            "version": "1",
            "python": "3.12",
            "platform": "win_amd64",
            "lock": [{"name": "fakenum", "version": "1.0"}],
            "files": [{"path": "fakenum/__init__.py", **blob("def answer():\n    return 42\n")}],
        }
    )
    package = PackageManifest.model_validate(
        {
            "schema_version": 1,
            "kind": "package",
            "name": "p",
            "version": "1",
            "python": "3.12",
            "environment": env.digest(),
            "requirements": [{"name": "fakenum", "version": "1.0"}],
            "files": [
                {
                    "path": "main.py",
                    **blob("import fakenum\nopen('out/a.txt', 'w').write(str(fakenum.answer()))\n"),
                }
            ],
            "entry": {"script": "main.py"},
        }
    )
    staged = stage_package(tmp_path, str(uuid.uuid4()), 1, package, {env.digest(): env}, cache)
    for name in ("state", "logs", "tmp"):
        (staged.root / name).mkdir(exist_ok=True)
    manager = WorkloadManager(tmp_path, restart_backoff_seconds=0.5, isolation=isolation)
    wid = "pkg-env-" + uuid.uuid4().hex[:8]
    manager.add(
        WorkloadSpec(
            id=wid,
            kind="cpu",
            checkpointable=False,
            isolation="appcontainer",
            package_root=str(staged.root),
            entry="main.py",
            import_paths=[str(staged.source), str(staged.environment)],
            read_only=[str(p) for p in staged.read_only],
        )
    )
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and manager.states()[wid] not in (
            WorkloadState.COMPLETED,
            WorkloadState.FAILED,
        ):
            manager.enforce(POLICY.envelopes[L.OPEN], Assessment(L.OPEN, ()), POLICY, RAM)
            time.sleep(0.2)
        item = manager.job_snapshot("pkg-env-")[wid]
    finally:
        manager.shutdown()
    assert item["last_exit_code"] == 0, (staged.root / "logs" / "stderr.txt").read_text()
    assert (staged.root / "out" / "a.txt").read_text() == "42"
    with pytest.raises(PermissionError):
        (staged.environment / "fakenum" / "__init__.py").write_text("tampered")
