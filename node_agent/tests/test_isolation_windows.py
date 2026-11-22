"""AppContainer isolation: the boundary itself, the catalog inside it, and no fallback."""

from __future__ import annotations

import json
import sys
import time

import pytest

from udcs_agent.governor.classifier import Assessment
from udcs_agent.workloads.manager import WorkloadManager, WorkloadSpec, WorkloadState
from udcs_shared.protection import ProtectionLevel, ProtectionPolicy

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows AppContainer")

L = ProtectionLevel
POLICY = ProtectionPolicy()
RAM = 16 * 2**30


@pytest.fixture(scope="module")
def isolation(tmp_path_factory):
    from udcs_agent.workloads.isolation import AppContainerIsolation

    backend = AppContainerIsolation(tmp_path_factory.mktemp("iso-data"))
    backend.ensure_runtime()  # one-time grant on the interpreter directory (slow on first run)
    return backend


def _step(manager, level=L.OPEN, times=1, wait=0.3):
    for _ in range(times):
        manager.enforce(POLICY.envelopes[level], Assessment(level, ()), POLICY, RAM)
        time.sleep(wait)


def _until(predicate, timeout=60.0, step=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if step:
            step()
        if predicate():
            return True
        time.sleep(0.2)
    return False


def test_isolation_selftest_denies_every_prohibited_operation(tmp_path, isolation):
    from udcs_agent.diagnostics.isolation import run_selftest

    report = run_selftest(tmp_path / "selftest", isolation)
    failed = [c for c in report["checks"] if not c["pass"]]
    assert not failed, json.dumps(failed, indent=1)
    assert report["kill_tree"]["pass"], report["kill_tree"]
    assert report["passed"]
    # Each prohibited check is meaningful only if the unsandboxed control could do it.
    meaningful = {
        c["name"]
        for c in report["checks"]
        if c["expected"] == "denied" and c["host_control"] == "allowed"
    }
    for name in (
        "read:outside_secret",
        "read:other_workload",
        "read:agent_credential",
        "connect:loopback",
        "open_process:agent_terminate",
        "registry:hkcu_secret",
    ):
        assert name in meaningful, f"{name} proves nothing on this machine"


def _source(name):
    from pathlib import Path

    import udcs_agent.workloads.isolation as module

    return (Path(module.__file__).parent / name).read_bytes()


def test_selftest_leaves_the_runtime_untouched(tmp_path, isolation):
    # Regression: the unsandboxed control once appended to runtime/synthetic.py, which
    # broke every later isolated workload on the node.
    from udcs_agent.diagnostics.isolation import run_selftest

    run_selftest(tmp_path / "selftest", isolation)
    assert (isolation.runtime / "synthetic.py").read_bytes() == _source("synthetic.py")


def test_modified_runtime_is_restored_before_the_next_launch(tmp_path, isolation):
    from udcs_agent.winplat.jobs import JobObject

    (isolation.runtime / "synthetic.py").write_text("raise SystemExit(99)  # tampered")
    workdir = tmp_path / "w"
    job = JobObject()
    try:
        process = isolation.launch(
            "iso-tamper",
            "synthetic",
            ["--kind", "cpu", "--dir", str(workdir), "--total-units", "3", "--memory-mb", "16"],
            job,
            workdir,
        )
        assert process.wait(60) == 0
        process.close()
    finally:
        job.close()
        isolation.release("iso-tamper")
    assert (isolation.runtime / "synthetic.py").read_bytes() == _source("synthetic.py")


def test_detection_reports_a_verified_appcontainer(tmp_path):
    from udcs_agent.diagnostics.isolation import detect_isolation

    caps = {c.name: c for c in detect_isolation(tmp_path)}
    assert caps["appcontainer"].available and caps["appcontainer"].verified
    assert caps["mxc_processcontainer"].available is False  # not integrated: never claimed
    for name in ("windows_sandbox", "hyperv", "wsl"):
        assert caps[name].available is False and caps[name].detail


@pytest.mark.parametrize("kind", ["cpu", "memory", "disk", "gpu"])
def test_catalog_workloads_run_inside_appcontainer(tmp_path, isolation, kind):
    if kind == "gpu":
        from udcs_agent.discovery.nvidia import Nvml

        with Nvml() as nvml:
            if not nvml.gpu_inventory():
                pytest.skip("no NVIDIA GPU")
    manager = WorkloadManager(tmp_path, restart_backoff_seconds=0.5, isolation=isolation)
    try:
        wid = f"iso-{kind}"
        manager.add(
            WorkloadSpec(id=wid, kind=kind, total_units=20, memory_mb=32, isolation="appcontainer")
        )
        assert _until(
            lambda: manager.states()[wid] == WorkloadState.COMPLETED,
            timeout=120,
            step=lambda: _step(manager, wait=0),
        ), (manager.states(), manager.events[-5:])
        snap = manager.job_snapshot("iso-")[wid]
        assert snap["result"]["units"] == 20
        assert any(what == "started (appcontainer)" for _t, what in snap["events"])
        assert snap["cpu_seconds"] > 0  # accounted by the same Job Object as before
    finally:
        manager.shutdown()


def test_governor_pause_still_applies_inside_appcontainer(tmp_path, isolation):
    manager = WorkloadManager(tmp_path, restart_backoff_seconds=0.5, isolation=isolation)
    try:
        manager.add(WorkloadSpec(id="iso-cap", kind="cpu", isolation="appcontainer"))
        _step(manager, L.OPEN, times=3)
        assert _until(lambda: manager.status_of("iso-cap").get("units_done", 0) > 0)
        running = manager._running["iso-cap"]
        _step(manager, L.PROTECTED)  # cap 0: threads suspended
        before = running.job.accounting().cpu_seconds
        time.sleep(1.5)
        assert running.job.accounting().cpu_seconds - before < 0.05
    finally:
        manager.shutdown()


def test_required_isolation_missing_never_falls_back_to_the_host(tmp_path):
    manager = WorkloadManager(tmp_path, restart_backoff_seconds=0.5, isolation=None)
    try:
        manager.add(WorkloadSpec(id="needs-ac", kind="cpu", isolation="appcontainer"))
        _step(manager, L.OPEN, times=2)
        assert manager.states()["needs-ac"] == WorkloadState.FAILED
        assert "needs-ac" not in manager._running
        events = [(w, e) for _t, w, e in manager.events]
        assert ("needs-ac", "isolation_unavailable: appcontainer") in events
    finally:
        manager.shutdown()


def test_isolation_launch_failure_fails_the_workload_and_starts_nothing(tmp_path):
    from udcs_agent.workloads.isolation import IsolationUnavailable

    class Broken:
        def launch(self, *args, **kwargs):
            raise IsolationUnavailable("simulated: AppContainer API refused")

        def release(self, workload_id, **kwargs):
            pass

    manager = WorkloadManager(tmp_path, restart_backoff_seconds=0.1, isolation=Broken())
    try:
        manager.add(WorkloadSpec(id="broken-ac", kind="cpu", isolation="appcontainer"))
        for _ in range(6):
            _step(manager, L.OPEN, wait=0.15)
        assert "broken-ac" not in manager._running, "must not run without its isolation"
        assert manager.states()["broken-ac"] == WorkloadState.FAILED  # after MAX_FAILURES
        assert any(e.startswith("start_failed: simulated") for _t, _w, e in manager.events)
    finally:
        manager.shutdown()


def test_purge_releases_the_workloads_appcontainer_profile(tmp_path, isolation):
    from udcs_agent.winplat import appcontainer as ac

    manager = WorkloadManager(tmp_path, restart_backoff_seconds=0.5, isolation=isolation)
    try:
        manager.add(WorkloadSpec(id="iso-purge", kind="cpu", isolation="appcontainer"))
        _step(manager, L.OPEN, times=2)
        assert _until(lambda: "iso-purge" in manager._running)
        WorkloadManager.queue_request(tmp_path, "remove", workload_id="iso-purge", purge=True)
        _step(manager, L.OPEN)
        assert "iso-purge" not in manager.states()
        # DeleteAppContainerProfile reports success even for unknown names, so check the
        # registry mapping of existing profiles instead.
        assert isolation.profile_name("iso-purge") not in ac.list_profiles("udcs.")
    finally:
        manager.shutdown()


def test_orphan_profiles_are_swept_when_the_manager_starts(tmp_path, isolation):
    from udcs_agent.winplat import appcontainer as ac

    orphan = isolation.profile_name("gone-workload")
    ac.ensure_profile(orphan)
    assert orphan in ac.list_profiles("udcs.")
    WorkloadManager(tmp_path, isolation=isolation).shutdown()  # no record for it
    assert orphan not in ac.list_profiles("udcs.")


def test_profile_names_fit_windows_limits_and_are_scoped_per_agent(tmp_path):
    from udcs_agent.workloads.isolation import AppContainerIsolation

    a, b = AppContainerIsolation(tmp_path / "a"), AppContainerIsolation(tmp_path / "b")
    longest = "x" * 64
    assert len(a.profile_name(longest)) <= 64
    assert a.profile_name("w1") != b.profile_name("w1")
