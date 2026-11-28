"""Owns every UDCS workload process and applies the governor's decisions to them.

Each workload lives in its own Job Object (created suspended inside it, IDLE
priority, boost disabled, very low memory priority). The action ladder:
throttle (CPU cap) -> freeze allocations (commit cap) -> pause (cooperative +
thread suspension) -> checkpoint and evict -> kill.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path

import psutil

from udcs_agent.governor.classifier import Assessment
from udcs_agent.workloads.synthetic import EXIT_CHECKPOINTED
from udcs_shared.protection import LevelEnvelope, ProtectionPolicy, WorkloadClass

logger = logging.getLogger(__name__)

RESTART_BACKOFF_SECONDS = 30.0
STORAGE_CHECK_SECONDS = 5.0  # package runs: how often their writable area is measured
TREE_EXIT_WAIT_SECONDS = 10.0  # after the main process exits, until the job is empty
STORAGE_SCAN_MAX_ENTRIES = 200_000
GPU_PAUSE_ACK_SECONDS = 2.0  # then threads are suspended too
EVICT_AFTER_PAUSED_SECONDS = 600.0  # a long pause still holds RAM/VRAM; give it back
MAX_FAILURES = 3


class WorkloadState(StrEnum):
    WAITING = "waiting"  # desired, not allowed to run right now
    RUNNING = "running"
    THROTTLED = "throttled"
    PAUSED = "paused"
    CHECKPOINTING = "checkpointing"
    EVICTED = "evicted"  # checkpointed (or killed) to release memory; will resume
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class WorkloadSpec:
    id: str
    kind: WorkloadClass
    total_units: int = 10**9
    memory_mb: int = 256
    checkpointable: bool = True
    # "host" (Job Object only; built-in catalog code) or "appcontainer" (required: the
    # workload never starts without it). See workloads/isolation.py.
    isolation: str = "host"
    # Package runs (ADR 0003): a staged researcher package instead of a catalog workload.
    package_root: str = ""
    entry: str = ""
    args: list[str] = field(default_factory=list)
    import_paths: list[str] = field(default_factory=list)
    read_only: list[str] = field(default_factory=list)
    max_runtime_seconds: int = 0  # running time, excluding pauses; 0 = none
    storage_bytes: int = 0  # out/, state/, logs/ and tmp/ together; 0 = none

    def __post_init__(self) -> None:
        self.kind = WorkloadClass(self.kind)
        if not self.id.replace("-", "").isalnum() or len(self.id) > 64:
            raise ValueError("workload id must be alphanumeric/hyphen, <= 64 chars")
        if self.isolation not in ("host", "appcontainer"):
            raise ValueError(f"unknown isolation level {self.isolation!r}")
        if self.package_root and self.isolation != "appcontainer":
            raise ValueError("a package run requires appcontainer isolation")

    @property
    def is_package(self) -> bool:
        return bool(self.package_root)

    def writable(self) -> tuple[Path, ...]:
        root = Path(self.package_root)
        return (root / "out", root / "state", root / "logs", root / "tmp")


@dataclass(frozen=True)
class UdcsUsage:
    cpu_seconds: float  # cumulative across all workload jobs (+ ones already reaped)
    private_bytes: int
    io_bytes: int  # cumulative
    pids: frozenset[int]


@dataclass
class _Running:
    spec: WorkloadSpec
    workdir: Path
    job: object  # JobObject
    process: object  # LaunchedProcess
    state: WorkloadState = WorkloadState.RUNNING
    suspended: bool = False
    paused_since: float | None = None
    coop_seq: int = 0
    coop_command: str = "run"
    coop_sent_at: float = 0.0
    checkpoint_deadline: float | None = None
    evict_reason: str = ""
    active_seconds: float = 0.0  # time actually running (not paused), for runtime limits
    last_tick: float | None = None
    next_storage_check: float = 0.0


@dataclass
class _Record:
    spec: WorkloadSpec
    state: WorkloadState = WorkloadState.WAITING
    restart_after: float = 0.0
    failures: int = 0
    evictions: int = 0
    last_exit_code: int | None = None
    cpu_seconds: float = 0.0  # cumulative over every process this workload has had
    history: list[str] = field(default_factory=list)
    # How a package run ended: exited | runtime_limit | storage_limit | start_failed |
    # isolation_unavailable | tree_survived. Empty while it has not ended.
    outcome: str = ""


class WorkloadManager:
    def __init__(
        self,
        data_dir: Path,
        *,
        python: str | None = None,
        clock=time.monotonic,
        restart_backoff_seconds: float = RESTART_BACKOFF_SECONDS,
        isolation=None,  # AppContainerIsolation, or None where unavailable
    ) -> None:
        self.root = data_dir / "workloads"
        self.root.mkdir(parents=True, exist_ok=True)
        self._isolation = isolation
        self._python = python or getattr(sys, "_base_executable", sys.executable)
        self._clock = clock
        self._backoff = restart_backoff_seconds
        self._records: dict[str, _Record] = {}
        self._running: dict[str, _Running] = {}
        self._reaped_cpu = 0.0
        self._reaped_io = 0
        self.events: list[tuple[float, str, str]] = []
        self.evictions_total = 0
        self._dirty = False
        # gpu/disk admission: set immediately, clear only after relax_after_seconds of calm
        self._gpu_clear_since: float | None = None
        self._disk_clear_since: float | None = None
        # The governor thread mutates; other threads (telemetry, job sync) only read, and
        # only through snapshot methods that take this lock.
        self._lock = threading.RLock()
        # Directories to delete. Windows refuses while a just-terminated process still has
        # the directory as its working directory, so failures are retried every tick.
        self._purge_pending: set[str] = set()
        self._load_registry()
        self._ingest_requests()
        if self._isolation is not None and hasattr(self._isolation, "sweep_orphans"):
            # Profiles of workloads that no longer exist (agent died before a purge).
            self._isolation.sweep_orphans(set(self._records))

    # -- registry (survives service restarts) ------------------------------------------------

    @property
    def _registry_path(self) -> Path:
        return self.root / "registry.json"

    def _load_registry(self) -> None:
        try:
            raw = json.loads(self._registry_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except ValueError:
            logger.error("workload registry is corrupt; ignoring it")
            return
        for item in raw.get("workloads", []):
            spec = WorkloadSpec(**item["spec"])
            state = WorkloadState(item.get("state", "waiting"))
            if state not in (WorkloadState.COMPLETED, WorkloadState.FAILED):
                state = WorkloadState.WAITING  # whatever was running died with the old agent
            self._records[spec.id] = _Record(
                spec,
                state,
                failures=item.get("failures", 0),
                evictions=item.get("evictions", 0),
                cpu_seconds=float(item.get("cpu_seconds", 0.0)),
                last_exit_code=item.get("last_exit_code"),
                outcome=str(item.get("outcome", "")),
            )

    def _save_registry(self) -> None:
        data = {
            "workloads": [
                {
                    "spec": {**asdict(r.spec), "kind": r.spec.kind.value},
                    "state": r.state.value,
                    "failures": r.failures,
                    "evictions": r.evictions,
                    "cpu_seconds": round(r.cpu_seconds, 3),
                    "last_exit_code": r.last_exit_code,
                    "outcome": r.outcome,
                }
                for r in self._records.values()
            ]
        }
        tmp = self._registry_path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
            os.replace(tmp, self._registry_path)
            self._dirty = False
        except OSError:
            logger.warning("could not save workload registry; will retry", exc_info=True)

    def add(self, spec: WorkloadSpec) -> None:
        with self._lock:
            if spec.id in self._records:
                raise ValueError(f"workload {spec.id} already exists")
            self._records[spec.id] = _Record(spec)
            self._save_registry()

    def remove(self, workload_id: str) -> None:
        with self._lock:
            running = self._running.pop(workload_id, None)
            if running is not None:
                self._terminate(running)
            self._records.pop(workload_id, None)
            self._save_registry()

    @property
    def _requests_dir(self) -> Path:
        return self.root / "requests"

    @staticmethod
    def queue_request(
        data_dir: Path,
        action: str,
        spec: WorkloadSpec | None = None,
        workload_id: str | None = None,
        *,
        purge: bool = False,
    ) -> Path:
        """Used by the CLI. The running agent applies queued requests on its next tick, so
        registry.json has exactly one writer (no lost updates)."""
        import uuid as _uuid

        requests = data_dir / "workloads" / "requests"
        requests.mkdir(parents=True, exist_ok=True)
        body: dict[str, object] = {"action": action}
        if spec is not None:
            body["spec"] = {**asdict(spec), "kind": spec.kind.value}
        if workload_id is not None:
            body["id"] = workload_id
        if purge:
            body["purge"] = True  # also delete the workload's directory (checkpoint, result)
        # Names sort in submission order (a remove followed by an add must apply in order).
        path = requests / f"{time.time_ns():020d}-{_uuid.uuid4().hex}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(body), encoding="utf-8")
        os.replace(tmp, path)
        return path

    def _ingest_requests(self) -> None:
        try:
            pending = sorted(self._requests_dir.glob("*.json"), key=lambda q: q.name)
        except OSError:
            return
        for path in pending:
            try:
                body = json.loads(path.read_text(encoding="utf-8"))
                if body["action"] == "add":
                    spec = WorkloadSpec(**body["spec"])
                    if spec.id not in self._records:
                        self._records[spec.id] = _Record(spec)
                elif body["action"] == "remove":
                    workload_id = WorkloadSpec(id=str(body["id"]), kind="cpu").id  # validated
                    running = self._running.pop(workload_id, None)
                    if running is not None:
                        self._terminate(running, wait_seconds=2.0 if body.get("purge") else 0)
                    removed = self._records.pop(workload_id, None)
                    if (
                        removed is not None
                        and removed.spec.isolation == "appcontainer"
                        and self._isolation is not None
                    ):
                        self._isolation.release(workload_id)  # its AppContainer profile
                    if body.get("purge"):
                        self._purge_pending.add(workload_id)
                self._dirty = True
            except (ValueError, KeyError, TypeError, OSError):
                logger.warning("ignoring malformed workload request %s", path.name)
            path.unlink(missing_ok=True)
        self._purge()

    def _purge(self) -> None:
        for workload_id in list(self._purge_pending):
            if workload_id in self._records:  # re-added since: keep it
                self._purge_pending.discard(workload_id)
                continue
            shutil.rmtree(self.root / workload_id, ignore_errors=True)
            if not (self.root / workload_id).exists():
                self._purge_pending.discard(workload_id)

    def states(self) -> dict[str, WorkloadState]:
        with self._lock:
            return {wid: rec.state for wid, rec in self._records.items()}

    def job_snapshot(self, prefix: str) -> dict[str, dict[str, object]]:
        """Thread-safe view of the workloads whose id starts with `prefix` (controller jobs):
        local state, progress, resource use, result, failures and event history."""
        with self._lock:
            out: dict[str, dict[str, object]] = {}
            for wid, record in self._records.items():
                if not wid.startswith(prefix):
                    continue
                cpu, memory = record.cpu_seconds, 0
                running = self._running.get(wid)
                if running is not None:
                    try:
                        cpu += running.job.accounting().cpu_seconds
                    except OSError:
                        pass
                    memory = self._private_of(running)
                out[wid] = {
                    "state": record.state.value,
                    "failures": record.failures,
                    "last_exit_code": record.last_exit_code,
                    "outcome": record.outcome,
                    "cpu_seconds": cpu,
                    "memory_bytes": memory,
                    "events": [(t, what) for t, w, what in self.events if w == wid],
                }
        for wid, item in out.items():  # file reads outside the lock
            status = self.status_of(wid)
            item["units_done"] = int(status.get("units_done", 0) or 0)
            item["result"] = self.result_of(wid)
        return out

    def result_of(self, workload_id: str) -> dict[str, object] | None:
        try:
            return json.loads((self.root / workload_id / "result.json").read_text("utf-8"))
        except (FileNotFoundError, ValueError):
            return None

    def status_of(self, workload_id: str) -> dict[str, object]:
        try:
            return json.loads((self.root / workload_id / "status.json").read_text("utf-8"))
        except (FileNotFoundError, ValueError):
            return {}

    # -- measurement ---------------------------------------------------------------------------

    def usage(self) -> UdcsUsage:
        cpu, io, private, pids = self._reaped_cpu, self._reaped_io, 0, set()
        for running in self._running.values():
            try:
                acct = running.job.accounting()
                job_pids = running.job.process_ids()
            except OSError:
                continue
            cpu += acct.cpu_seconds
            io += acct.read_bytes + acct.write_bytes
            pids.update(job_pids)
            for pid in job_pids:
                try:
                    private += psutil.Process(pid).memory_info().private
                except (psutil.Error, AttributeError):
                    pass
        return UdcsUsage(cpu, private, io, frozenset(pids))

    # -- the control step, called by the governor every tick -----------------------------------

    def enforce(
        self,
        envelope: LevelEnvelope,
        assessment: Assessment,
        policy: ProtectionPolicy,
        memory_total_bytes: int,
        usage: UdcsUsage | None = None,
    ) -> None:
        with self._lock:
            self._enforce(envelope, assessment, policy, memory_total_bytes, usage)

    def _enforce(
        self,
        envelope: LevelEnvelope,
        assessment: Assessment,
        policy: ProtectionPolicy,
        memory_total_bytes: int,
        usage: UdcsUsage | None,
    ) -> None:
        now = self._clock()
        self._ingest_requests()
        self._reap(now)
        budget = memory_total_bytes * envelope.udcs_memory_budget_percent / 100.0
        usage_private = (usage or self.usage()).private_bytes
        # Memory already on its way out (checkpointing) must not cause further evictions.
        for running in self._running.values():
            if running.state == WorkloadState.CHECKPOINTING:
                usage_private = max(0, usage_private - self._private_of(running))
        held = self._admission(assessment, policy, now)
        under_pressure = bool(
            {"cpu_pressure", "memory_pressure", "paging", "signals_unavailable"}
            & set(assessment.reasons)
        )

        def must_evict() -> bool:
            return assessment.memory_critical or usage_private > budget

        for record in list(self._records.values()):
            if record.state in (WorkloadState.COMPLETED, WorkloadState.FAILED):
                continue
            running = self._running.get(record.spec.id)
            allowed = self._allowed(record.spec.kind, envelope, held)
            if running is None:
                if (
                    allowed
                    and now >= record.restart_after
                    and not must_evict()
                    and not under_pressure
                ):
                    self._start(record, now)
                elif record.state not in (WorkloadState.EVICTED,):
                    self._set(record, WorkloadState.WAITING)
                continue
            if record.spec.is_package and self._package_limits(record, running, now):
                continue  # killed for exceeding a limit
            if running.state == WorkloadState.CHECKPOINTING:
                if running.checkpoint_deadline is not None and now >= running.checkpoint_deadline:
                    self._event(now, record.spec.id, "checkpoint_deadline_kill")
                    self._finish_eviction(record, running, now, killed=True)
                continue
            # Memory is the one resource a pause cannot give back: evict (checkpoint + exit)
            # until UDCS is under its budget. CPU-class work is evicted only if it is itself
            # what keeps UDCS over budget.
            if must_evict() and (record.spec.kind != WorkloadClass.CPU or usage_private > budget):
                self._begin_eviction(
                    record,
                    running,
                    now,
                    policy,
                    "memory_critical" if assessment.memory_critical else "memory_budget",
                )
                usage_private = max(0, usage_private - self._private_of(running))
                continue
            if not allowed:
                self._pause(record, running, now)
                if (
                    running.paused_since is not None
                    and now - running.paused_since > EVICT_AFTER_PAUSED_SECONDS
                    and record.spec.kind in (WorkloadClass.MEMORY, WorkloadClass.GPU)
                ):
                    self._begin_eviction(record, running, now, policy, "long_pause")
                continue
            self._resume(record, running, now)

        self._apply_caps(envelope, memory_total_bytes, assessment)
        if self._dirty:
            self._save_registry()

    def _admission(
        self, assessment: Assessment, policy: ProtectionPolicy, now: float
    ) -> Assessment:
        """GPU demand / disk pressure take effect at once but clear only after they have
        stayed clear for relax_after_seconds, so one quiet sample does not resume work."""
        from dataclasses import replace

        def held(flag: bool, attr: str) -> bool:
            if flag:
                setattr(self, attr, None)
                return True
            since = getattr(self, attr)
            if since is None:
                setattr(self, attr, now)
                return True
            return now - since < policy.relax_after_seconds

        return replace(
            assessment,
            gpu_demand=held(assessment.gpu_demand, "_gpu_clear_since"),
            disk_pressure=held(assessment.disk_pressure, "_disk_clear_since"),
        )

    @staticmethod
    def _allowed(kind: WorkloadClass, envelope: LevelEnvelope, assessment: Assessment) -> bool:
        if kind == WorkloadClass.CPU:
            return envelope.cpu_cap_percent > 0
        if kind == WorkloadClass.MEMORY:
            return envelope.allow_memory_class and envelope.cpu_cap_percent > 0
        if kind == WorkloadClass.DISK:
            return (
                envelope.allow_disk_class
                and not assessment.disk_pressure
                and envelope.cpu_cap_percent > 0
            )
        return (
            envelope.allow_gpu_class and not assessment.gpu_demand and envelope.cpu_cap_percent > 0
        )

    def _apply_caps(
        self, envelope: LevelEnvelope, memory_total: int, assessment: Assessment
    ) -> None:
        active = [
            r
            for r in self._running.values()
            if r.state in (WorkloadState.RUNNING, WorkloadState.THROTTLED)
        ]
        if not active:
            return
        cap = envelope.cpu_cap_percent / len(active)
        memory_share = int(memory_total * envelope.udcs_memory_budget_percent / 100 / len(active))
        for running in active:
            try:
                running.job.set_cpu_cap(None if cap >= 100 else max(cap, 0.5))
                if "memory_pressure" in assessment.reasons:
                    # Freeze: no new allocations beyond what the job already holds.
                    running.job.set_memory_limit(max(self._private_of(running), 64 * 2**20))
                elif running.spec.is_package:
                    limit = min(memory_share, max(running.spec.memory_mb, 64) * 2**20)
                    running.job.set_memory_limit(max(limit, 64 * 2**20))
                else:
                    running.job.set_memory_limit(max(memory_share, 64 * 2**20))
            except OSError:
                logger.exception("failed to apply limits to %s", running.spec.id)
            record = self._records[running.spec.id]
            # 'throttled' = the level imposes a cap (not merely a fair share of 100%)
            throttled = envelope.cpu_cap_percent < 100
            self._set(record, WorkloadState.THROTTLED if throttled else WorkloadState.RUNNING)
            running.state = record.state

    # -- actions ---------------------------------------------------------------------------------

    # -- package runs (ADR 0003) -----------------------------------------------------------

    def _package_limits(self, record: _Record, running: _Running, now: float) -> bool:
        """Enforce a package run's runtime and storage limits. True if it was killed."""
        if running.last_tick is not None and running.state in (
            WorkloadState.RUNNING,
            WorkloadState.THROTTLED,
        ):
            running.active_seconds += max(0.0, now - running.last_tick)
        running.last_tick = now
        spec = record.spec
        if spec.max_runtime_seconds and running.active_seconds > spec.max_runtime_seconds:
            self._end_package(record, running, now, "runtime_limit")
            return True
        if spec.storage_bytes and now >= running.next_storage_check:
            running.next_storage_check = now + STORAGE_CHECK_SECONDS
            used = self._storage_used(spec)
            if used is None or used > spec.storage_bytes:
                self._end_package(record, running, now, "storage_limit")
                return True
        return False

    @staticmethod
    def _storage_used(spec: WorkloadSpec) -> int | None:
        """Bytes in the run's writable area, never following links. None if the tree is
        too large to even count (itself a limit breach)."""
        total = entries = 0
        stack = [p for p in spec.writable() if p.is_dir()]
        while stack:
            try:
                with os.scandir(stack.pop()) as listing:
                    for entry in listing:
                        entries += 1
                        if entries > STORAGE_SCAN_MAX_ENTRIES:
                            return None
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            # Not entry.stat(): NTFS directory entries report a stale
                            # size for files still open for writing (measured). os.stat
                            # opens the file and asks it.
                            total += os.stat(entry.path, follow_symlinks=False).st_size
            except OSError:
                continue
        return total

    def _end_package(self, record: _Record, running: _Running, now: float, outcome: str) -> None:
        """A package run has ended (exit or limit): kill whatever is left of its process
        tree and wait until the job is empty, so nothing can still write its outputs when
        they are collected. Only then is the run marked finished."""
        gone = self._terminate_tree(running)
        self._terminate(running)
        self._running.pop(record.spec.id, None)
        record.outcome = outcome if gone else "tree_survived"
        if record.outcome == "exited":
            self._set(record, WorkloadState.COMPLETED)
        else:
            self._set(record, WorkloadState.FAILED)
        self._event(now, record.spec.id, f"package_{record.outcome}:{record.last_exit_code}")

    @staticmethod
    def _terminate_tree(running: _Running) -> bool:
        try:
            running.job.terminate(1)
        except OSError:
            pass
        deadline = time.monotonic() + TREE_EXIT_WAIT_SECONDS
        while time.monotonic() < deadline:
            try:
                if not running.job.process_ids():
                    return True
            except OSError:
                return False
            time.sleep(0.05)
        return False

    def _start_package(self, record: _Record, now: float) -> None:
        from udcs_agent.packages import remove_staging
        from udcs_agent.winplat.jobs import JobObject

        spec = record.spec
        root = Path(spec.package_root)
        if self._isolation is None:
            self._set(record, WorkloadState.FAILED)
            record.outcome = "isolation_unavailable"
            self._event(now, spec.id, "isolation_unavailable: appcontainer")
            return
        # Every run starts with empty outputs and logs (an evicted run restarts from the
        # beginning); state/ is kept: it is where a package keeps its own checkpoint.
        for name in ("out", "logs", "tmp"):
            remove_staging(root / name)
            (root / name).mkdir(parents=True, exist_ok=True)
        workdir = self.root / spec.id
        workdir.mkdir(parents=True, exist_ok=True)
        job = JobObject()
        job.set_cpu_cap(5)  # start gently; the next tick applies the real envelope
        job.set_memory_limit(max(spec.memory_mb, 64) * 2**20)
        from udcs_agent.workloads.isolation import IsolationUnavailable

        try:
            process = self._isolation.launch_package(
                spec.id,
                job,
                root,
                entry=root / "src" / Path(*spec.entry.split("/")),
                args=list(spec.args),
                import_paths=[Path(p) for p in spec.import_paths],
                read_only=tuple(Path(p) for p in spec.read_only),
                writable=spec.writable(),
            )
        except (IsolationUnavailable, OSError) as exc:
            job.close()
            record.failures += 1
            record.restart_after = now + self._backoff
            self._event(now, spec.id, f"start_failed: {str(exc)[:120]}")
            if record.failures >= MAX_FAILURES:
                record.outcome = "start_failed"
                self._set(record, WorkloadState.FAILED)
            else:
                self._set(record, WorkloadState.WAITING)
            return
        self._running[spec.id] = _Running(spec, workdir, job, process, last_tick=now)
        self._set(record, WorkloadState.RUNNING)
        self._event(now, spec.id, "started (package, appcontainer)")

    def _start(self, record: _Record, now: float) -> None:
        if record.spec.is_package:
            self._start_package(record, now)
            return
        from udcs_agent.winplat.jobs import JobObject
        from udcs_agent.winplat.launch import launch_in_job

        workdir = self.root / record.spec.id
        workdir.mkdir(parents=True, exist_ok=True)
        (workdir / "control.json").unlink(missing_ok=True)
        job = JobObject()
        job.set_cpu_cap(5)  # start gently; the next tick applies the real envelope
        # -I (isolated): ignore PYTHON* env vars and the user site, so nothing in the
        # environment can redirect what runs. Isolation also ignores PYTHONPATH, so the
        # agent's own import path is passed explicitly instead.
        paths = [p for p in sys.path if p and Path(p).is_dir()]
        bootstrap = (
            f"import sys; sys.path[:0] = {paths!r}; "
            "from udcs_agent.workloads.synthetic import main; sys.exit(main())"
        )
        workload_args = [
            "--kind",
            record.spec.kind.value,
            "--dir",
            str(workdir),
            "--total-units",
            str(record.spec.total_units),
            "--memory-mb",
            str(record.spec.memory_mb),
        ]
        # -B (host-side, agent identity): never write .pyc into the agent's own install.
        argv = [self._python, "-I", "-B", "-c", bootstrap, *workload_args]
        env = {
            k: v
            for k, v in os.environ.items()
            if k.upper() in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH", "PATHEXT", "COMSPEC")
        }
        if record.spec.isolation == "appcontainer" and self._isolation is None:
            # Required isolation is missing on this node: never run it any other way.
            job.close()
            self._set(record, WorkloadState.FAILED)
            self._event(now, record.spec.id, "isolation_unavailable: appcontainer")
            return
        try:
            if record.spec.isolation == "appcontainer":
                from udcs_agent.workloads.isolation import IsolationUnavailable

                try:
                    process = self._isolation.launch(
                        record.spec.id, "synthetic", workload_args, job, workdir
                    )
                except IsolationUnavailable as exc:
                    raise OSError(str(exc)) from exc
            else:
                process = launch_in_job(argv, job, cwd=workdir, env=env)
        except OSError as exc:
            job.close()
            record.failures += 1
            record.restart_after = now + self._backoff
            logger.exception("could not start workload %s", record.spec.id)
            self._event(now, record.spec.id, f"start_failed: {str(exc)[:120]}")
            self._set(
                record,
                WorkloadState.FAILED if record.failures >= MAX_FAILURES else WorkloadState.WAITING,
            )
            return
        self._running[record.spec.id] = _Running(record.spec, workdir, job, process)
        self._set(record, WorkloadState.RUNNING)
        self._event(now, record.spec.id, f"started ({record.spec.isolation})")

    def _command(self, running: _Running, command: str, now: float) -> None:
        if running.coop_command == command:
            return
        running.coop_seq += 1
        running.coop_command, running.coop_sent_at = command, now
        tmp = running.workdir / "control.tmp"
        tmp.write_text(json.dumps({"seq": running.coop_seq, "command": command}), "utf-8")
        os.replace(tmp, running.workdir / "control.json")

    def _pause(self, record: _Record, running: _Running, now: float) -> None:
        if running.paused_since is None:
            running.paused_since = now
            self._event(now, record.spec.id, "paused")
        self._command(running, "pause", now)
        # CPU/memory/disk: freeze immediately (no RAM is released, but contention stops at
        # once). GPU: give the workload time to stop submitting kernels cooperatively.
        if not running.suspended and (
            record.spec.kind != WorkloadClass.GPU
            or now - running.coop_sent_at >= GPU_PAUSE_ACK_SECONDS
        ):
            running.job.suspend()
            running.suspended = True
        running.state = WorkloadState.PAUSED
        self._set(record, WorkloadState.PAUSED)

    def _resume(self, record: _Record, running: _Running, now: float) -> None:
        if running.suspended:
            running.job.resume()
            running.suspended = False
        if running.paused_since is not None:
            self._event(now, record.spec.id, "resumed")
            running.paused_since = None
        running.state = WorkloadState.RUNNING  # caps are (re)applied in _apply_caps
        self._command(running, "run", now)

    def _begin_eviction(
        self, record: _Record, running: _Running, now: float, policy: ProtectionPolicy, reason: str
    ) -> None:
        self._event(now, record.spec.id, f"evicting:{reason}")
        running.evict_reason = reason
        if not record.spec.checkpointable:
            self._finish_eviction(record, running, now, killed=True)
            return
        running.job.set_cpu_cap(10)  # let it checkpoint, but gently
        if running.suspended:
            running.job.resume()
            running.suspended = False
        self._command(running, "checkpoint", now)
        running.state = WorkloadState.CHECKPOINTING
        running.checkpoint_deadline = now + policy.checkpoint_deadline_seconds
        self._set(record, WorkloadState.CHECKPOINTING)

    def _finish_eviction(
        self, record: _Record, running: _Running, now: float, *, killed: bool
    ) -> None:
        self._terminate(running)
        self._running.pop(record.spec.id, None)
        record.evictions += 1
        self.evictions_total += 1
        record.restart_after = now + self._backoff
        self._set(record, WorkloadState.EVICTED)
        self._event(now, record.spec.id, "evicted_killed" if killed else "evicted_checkpointed")

    def _reap(self, now: float) -> None:
        for wid, running in list(self._running.items()):
            code = running.process.exit_code()
            if code is None:
                continue
            record = self._records[wid]
            record.last_exit_code = code
            if record.spec.is_package and running.state != WorkloadState.CHECKPOINTING:
                # Any exit is a finished run: the exit code is the package's result,
                # not a reason to restart it. Children are killed before it counts.
                self._end_package(record, running, now, "exited")
                continue
            state = self.status_of(wid).get("state")
            if running.state == WorkloadState.CHECKPOINTING:
                self._finish_eviction(record, running, now, killed=code != EXIT_CHECKPOINTED)
                continue
            self._terminate(running)
            self._running.pop(wid)
            if code == 0 and state == "completed":
                self._set(record, WorkloadState.COMPLETED)
                self._event(now, wid, "completed")
            else:
                record.failures += 1
                record.restart_after = now + self._backoff
                self._set(
                    record,
                    WorkloadState.FAILED
                    if record.failures >= MAX_FAILURES
                    else WorkloadState.WAITING,
                )
                self._event(now, wid, f"exited:{code}")

    def _terminate(self, running: _Running, *, wait_seconds: float = 0.0) -> None:
        try:
            acct = running.job.accounting()
            self._reaped_cpu += acct.cpu_seconds
            self._reaped_io += acct.read_bytes + acct.write_bytes
            record = self._records.get(running.spec.id)
            if record is not None:
                record.cpu_seconds += acct.cpu_seconds
                self._dirty = True
        except OSError:
            pass
        try:
            running.job.terminate(1)
        except OSError:
            pass
        if wait_seconds > 0:
            try:
                running.process.wait(wait_seconds)
            except OSError:
                pass
        running.job.close()
        running.process.close()

    def _private_of(self, running: _Running) -> int:
        total = 0
        try:
            for pid in running.job.process_ids():
                try:
                    total += psutil.Process(pid).memory_info().private
                except (psutil.Error, AttributeError):
                    pass
        except OSError:
            pass
        return total

    def emergency_pause(self) -> None:
        """Freeze every workload now (used when the governor itself is failing)."""
        with self._lock:
            self._emergency_pause()

    def _emergency_pause(self) -> None:
        for running in list(self._running.values()):
            if not running.suspended:
                try:
                    running.job.suspend()
                    running.suspended = True
                    running.state = WorkloadState.PAUSED
                    self._records[running.spec.id].state = WorkloadState.PAUSED
                except OSError:
                    logger.exception(
                        "emergency pause failed for %s; terminating it", running.spec.id
                    )
                    self._terminate(running)
                    self._running.pop(running.spec.id, None)
                    record = self._records[running.spec.id]
                    record.restart_after = self._clock() + self._backoff
                    self._set(record, WorkloadState.WAITING)

    def shutdown(self) -> None:
        """Stop everything promptly (service stop): checkpoint files already exist."""
        with self._lock:
            self._shutdown()

    def _shutdown(self) -> None:
        for running in list(self._running.values()):
            self._terminate(running)
        self._running.clear()
        for record in self._records.values():
            if record.state not in (WorkloadState.COMPLETED, WorkloadState.FAILED):
                record.state = WorkloadState.WAITING
        self._save_registry()

    # -- bookkeeping -------------------------------------------------------------------------------

    def _set(self, record: _Record, state: WorkloadState) -> None:
        if record.state != state:
            self._dirty = True
            record.history.append(f"{state.value}")
            del record.history[:-50]
            record.state = state

    def _event(self, now: float, workload_id: str, what: str) -> None:
        self.events.append((now, workload_id, what))
        del self.events[:-500]
        logger.info("workload %s: %s", workload_id, what)

    def counts(self) -> dict[str, int]:
        with self._lock:
            states = [r.state for r in self._records.values()]
        return {
            "running": sum(s == WorkloadState.RUNNING for s in states),
            "throttled": sum(s == WorkloadState.THROTTLED for s in states),
            "paused": sum(s in (WorkloadState.PAUSED, WorkloadState.CHECKPOINTING) for s in states),
        }
