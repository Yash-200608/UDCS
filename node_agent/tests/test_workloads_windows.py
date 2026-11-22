"""Workload manager against real Windows Job Objects and real child processes."""

import sys
import time

import pytest

from udcs_agent.governor.classifier import Assessment
from udcs_agent.workloads.manager import WorkloadManager, WorkloadSpec, WorkloadState
from udcs_shared.protection import ProtectionLevel, ProtectionPolicy

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows Job Objects")

L = ProtectionLevel
POLICY = ProtectionPolicy(checkpoint_deadline_seconds=10)
TOTAL_RAM = 16 * 2**30


def _ok(level=L.OPEN, **flags):
    return Assessment(level, (), **flags)


def _step(wm, level=L.OPEN, assessment=None, *, times=1, wait=0.5):
    for _ in range(times):
        wm.enforce(POLICY.envelopes[level], assessment or _ok(level), POLICY, TOTAL_RAM)
        time.sleep(wait)


def _wait_for(predicate, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    return False


@pytest.fixture
def manager(tmp_path):
    wm = WorkloadManager(tmp_path, restart_backoff_seconds=0.5)
    yield wm
    wm.shutdown()


def test_cpu_workload_runs_is_capped_and_pauses_to_zero(manager):
    manager.add(WorkloadSpec(id="cpu1", kind="cpu"))
    _step(manager, L.OPEN, times=4)
    assert _wait_for(lambda: manager.status_of("cpu1").get("units_done", 0) > 0)
    running = manager._running["cpu1"]
    assert running.job.contains(running.process.handle)

    _step(manager, L.PROTECTED)  # cap 0 -> paused (threads suspended)
    assert manager.states()["cpu1"] == WorkloadState.PAUSED
    before = running.job.accounting().cpu_seconds
    time.sleep(1.5)
    assert running.job.accounting().cpu_seconds - before < 0.05, "a paused job must not run"

    _step(manager, L.OPEN, times=2)
    assert manager.states()["cpu1"] in (WorkloadState.RUNNING, WorkloadState.THROTTLED)


def test_memory_class_is_paused_while_a_student_is_active(manager):
    manager.add(WorkloadSpec(id="mem1", kind="memory", memory_mb=64))
    _step(manager, L.OPEN, times=3)
    assert _wait_for(lambda: manager.status_of("mem1").get("state") == "running")
    _step(manager, L.SHARED)  # memory class not allowed at SHARED (measured interference)
    assert manager.states()["mem1"] == WorkloadState.PAUSED
    assert manager._running["mem1"].suspended


def test_checkpoint_evict_and_resume_preserves_progress(manager):
    manager.add(WorkloadSpec(id="cp1", kind="cpu"))
    _step(manager, L.OPEN, times=3)
    assert _wait_for(lambda: manager.status_of("cp1").get("units_done", 0) >= 20)

    critical = _ok(L.CONSTRAINED, memory_critical=True)
    _step(manager, L.CONSTRAINED, critical)  # cpu-class is evicted only if over budget...
    manager.enforce(POLICY.envelopes[L.MAINTENANCE], critical, POLICY, TOTAL_RAM)  # budget 0
    assert _wait_for(
        lambda: (
            (manager.enforce(POLICY.envelopes[L.MAINTENANCE], critical, POLICY, TOTAL_RAM) or True)
            and manager.states()["cp1"] == WorkloadState.EVICTED
        )
    )
    assert ("cp1", "evicted_checkpointed") in [(w, e) for _, w, e in manager.events]
    saved = manager.status_of("cp1")["units_done"]
    assert manager.status_of("cp1")["state"] == "checkpointed"

    time.sleep(0.6)  # restart back-off
    _step(manager, L.OPEN, times=3)
    assert _wait_for(lambda: manager.status_of("cp1").get("resumed_from") == saved)


def test_agent_restart_resumes_workloads_from_the_registry(tmp_path):
    first = WorkloadManager(tmp_path, restart_backoff_seconds=0.5)
    first.add(WorkloadSpec(id="rs1", kind="cpu"))
    _step(first, L.OPEN, times=3)
    assert _wait_for(lambda: first.status_of("rs1").get("units_done", 0) >= 40)
    first._running["rs1"].job.close()  # simulate the agent dying: kill-on-close
    first._running.clear()

    second = WorkloadManager(tmp_path, restart_backoff_seconds=0.5)  # "service restarted"
    try:
        assert second.states()["rs1"] == WorkloadState.WAITING
        _step(second, L.OPEN, times=3)
        assert _wait_for(lambda: second.status_of("rs1").get("resumed_from", 0) > 0)
    finally:
        second.shutdown()


def test_completed_workload_is_not_restarted(manager):
    manager.add(WorkloadSpec(id="short", kind="cpu", total_units=5))
    _step(manager, L.OPEN, times=2)
    assert _wait_for(
        lambda: (
            (_step(manager, L.OPEN, wait=0.2) or True)
            and manager.states()["short"] == WorkloadState.COMPLETED
        )
    )


def test_memory_pressure_freezes_new_allocations(manager):
    manager.add(WorkloadSpec(id="alloc", kind="memory", memory_mb=512))
    pressure = Assessment(L.AWAY, ("memory_pressure",))
    # No new workloads start under pressure, so start it calmly first...
    manager.enforce(POLICY.envelopes[L.AWAY], _ok(L.AWAY), POLICY, TOTAL_RAM)
    assert "alloc" in manager._running
    # ...then pressure arrives before it has allocated: its commit is frozen at ~current use.
    for _ in range(10):
        manager.enforce(POLICY.envelopes[L.AWAY], pressure, POLICY, TOTAL_RAM)
        time.sleep(0.3)
    assert manager._private_of(manager._running["alloc"]) < 300 * 2**20
    assert manager.status_of("alloc").get("units_done", 0) == 0


def test_invalid_workload_ids_are_rejected():
    with pytest.raises(ValueError):
        WorkloadSpec(id="../../evil", kind="cpu")


def test_gpu_admission_clears_only_after_the_hold_period(tmp_path):
    now = [0.0]
    wm = WorkloadManager(tmp_path, clock=lambda: now[0])
    policy = ProtectionPolicy(relax_after_seconds=30)
    demand = Assessment(L.OPEN, (), gpu_demand=True)
    quiet = Assessment(L.OPEN, (), gpu_demand=False)
    assert wm._admission(demand, policy, 0.0).gpu_demand
    assert wm._admission(quiet, policy, 1.0).gpu_demand, "one quiet sample must not resume"
    assert wm._admission(quiet, policy, 20.0).gpu_demand
    assert not wm._admission(quiet, policy, 32.0).gpu_demand
    assert wm._admission(demand, policy, 33.0).gpu_demand  # re-arms immediately


def test_cli_requests_are_applied_by_the_running_manager(manager, tmp_path):
    WorkloadManager.queue_request(
        tmp_path, "add", spec=WorkloadSpec(id="queued1", kind="cpu", total_units=3)
    )
    _step(manager, L.OPEN)
    assert "queued1" in manager.states()
    WorkloadManager.queue_request(tmp_path, "remove", workload_id="queued1")
    _step(manager, L.OPEN)
    assert "queued1" not in manager.states()
    assert not list((tmp_path / "workloads" / "requests").glob("*.json"))


def test_purge_removes_a_running_workloads_directory(manager, tmp_path):
    # Windows will not delete a directory that a just-terminated process still uses as its
    # working directory; the manager waits for the exit and retries.
    manager.add(WorkloadSpec(id="job-purge", kind="cpu"))
    _step(manager, L.OPEN, times=3)
    assert _wait_for(lambda: manager.status_of("job-purge").get("units_done", 0) > 0)
    WorkloadManager.queue_request(tmp_path, "remove", workload_id="job-purge", purge=True)
    _step(manager, L.OPEN, wait=0)
    assert "job-purge" not in manager.states()
    assert _wait_for(
        lambda: (
            (_step(manager, L.OPEN, wait=0) or True)
            and not (tmp_path / "workloads" / "job-purge").exists()
        ),
        timeout=5,
    )


def test_job_snapshot_keeps_cpu_time_after_the_process_exits(manager):
    manager.add(WorkloadSpec(id="job-cpu", kind="cpu", total_units=20))
    assert _wait_for(
        lambda: (
            (_step(manager, L.OPEN, wait=0.2) or True)
            and manager.states()["job-cpu"] == WorkloadState.COMPLETED
        )
    )
    snap = manager.job_snapshot("job-")["job-cpu"]
    assert snap["state"] == "completed" and snap["cpu_seconds"] > 0
    assert snap["result"]["units"] == 20
