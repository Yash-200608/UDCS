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
import sys
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

    def __post_init__(self) -> None:
        self.kind = WorkloadClass(self.kind)
        if not self.id.replace("-", "").isalnum() or len(self.id) > 64:
            raise ValueError("workload id must be alphanumeric/hyphen, <= 64 chars")


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


@dataclass
class _Record:
    spec: WorkloadSpec
    state: WorkloadState = WorkloadState.WAITING
    restart_after: float = 0.0
    failures: int = 0
    evictions: int = 0
    last_exit_code: int | None = None
    history: list[str] = field(default_factory=list)


class WorkloadManager:
    def __init__(
        self,
        data_dir: Path,
        *,
        python: str | None = None,
        clock=time.monotonic,
        restart_backoff_seconds: float = RESTART_BACKOFF_SECONDS,
    ) -> None:
        self.root = data_dir / "workloads"
        self.root.mkdir(parents=True, exist_ok=True)
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
        self._load_registry()
        self._ingest_requests()

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
                spec, state, failures=item.get("failures", 0), evictions=item.get("evictions", 0)
            )

    def _save_registry(self) -> None:
        data = {
            "workloads": [
                {
                    "spec": {**asdict(r.spec), "kind": r.spec.kind.value},
                    "state": r.state.value,
                    "failures": r.failures,
                    "evictions": r.evictions,
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
        if spec.id in self._records:
            raise ValueError(f"workload {spec.id} already exists")
        self._records[spec.id] = _Record(spec)
        self._save_registry()

    def remove(self, workload_id: str) -> None:
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
        path = requests / f"{_uuid.uuid4().hex}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(body), encoding="utf-8")
        os.replace(tmp, path)
        return path

    def _ingest_requests(self) -> None:
        try:
            pending = sorted(self._requests_dir.glob("*.json"), key=lambda q: q.stat().st_mtime)
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
                    running = self._running.pop(str(body["id"]), None)
                    if running is not None:
                        self._terminate(running)
                    self._records.pop(str(body["id"]), None)
                self._dirty = True
            except (ValueError, KeyError, TypeError, OSError):
                logger.warning("ignoring malformed workload request %s", path.name)
            path.unlink(missing_ok=True)

    def states(self) -> dict[str, WorkloadState]:
        return {wid: rec.state for wid, rec in self._records.items()}

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

    def _start(self, record: _Record, now: float) -> None:
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
        argv = [
            self._python,
            "-I",
            "-c",
            bootstrap,
            "--kind",
            record.spec.kind.value,
            "--dir",
            str(workdir),
            "--total-units",
            str(record.spec.total_units),
            "--memory-mb",
            str(record.spec.memory_mb),
        ]
        env = {
            k: v
            for k, v in os.environ.items()
            if k.upper() in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH", "PATHEXT", "COMSPEC")
        }
        try:
            process = launch_in_job(argv, job, cwd=workdir, env=env)
        except OSError:
            job.close()
            record.failures += 1
            record.restart_after = now + self._backoff
            logger.exception("could not start workload %s", record.spec.id)
            self._set(
                record,
                WorkloadState.FAILED if record.failures >= MAX_FAILURES else WorkloadState.WAITING,
            )
            return
        self._running[record.spec.id] = _Running(record.spec, workdir, job, process)
        self._set(record, WorkloadState.RUNNING)
        self._event(now, record.spec.id, "started")

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

    def _terminate(self, running: _Running) -> None:
        try:
            acct = running.job.accounting()
            self._reaped_cpu += acct.cpu_seconds
            self._reaped_io += acct.read_bytes + acct.write_bytes
        except OSError:
            pass
        try:
            running.job.terminate(1)
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
        states = [r.state for r in self._records.values()]
        return {
            "running": sum(s == WorkloadState.RUNNING for s in states),
            "throttled": sum(s == WorkloadState.THROTTLED for s in states),
            "paused": sum(s in (WorkloadState.PAUSED, WorkloadState.CHECKPOINTING) for s in states),
        }
