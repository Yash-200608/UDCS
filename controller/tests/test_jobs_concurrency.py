"""Genuine concurrency on PostgreSQL: independent sessions racing for the same job.

Each "agent" is a thread with its own Session, and therefore its own database
connection and transaction, calling the real `sync_node_jobs`.
- A barrier, hooked in front of the scheduler's candidate SELECT, releases all
  transactions into the claim phase together. All are open; none has claimed yet.
  That is the race window that sequential tests cannot reach.
- If a thread never reaches the barrier, the barrier breaks and the test fails, so
  the overlap is checked, not assumed.

SQLite serializes writers and has no row locks, so this module needs PostgreSQL.
Repetitions: UDCS_RACE_ROUNDS (CI raises it).
"""

from __future__ import annotations

import os
import threading
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import event, func, select

from udcs_agent.jobs import JobSync
from udcs_controller.auth.models import User
from udcs_controller.jobs import service
from udcs_controller.jobs.models import Job, JobLog
from udcs_controller.nodes.models import Node
from udcs_shared.agent_api import PROTOCOL_VERSION
from udcs_shared.jobs import (
    AgentJobReport,
    JobResult,
    JobSpec,
    JobState,
    JobSyncRequest,
    LocalJobState,
    NodeJobCapacity,
    expected_checksum,
)
from udcs_shared.protection import WorkloadClass

pytestmark = pytest.mark.skipif(
    not os.environ.get("UDCS_TEST_DATABASE_URL", "").startswith("postgresql"),
    reason="needs PostgreSQL (SQLite serializes writers, so there is nothing to race)",
)
ROUNDS = int(os.environ.get("UDCS_RACE_ROUNDS", "5"))
CANDIDATE_MARK = "ORDER BY jobs.priority DESC"


def _offer(slots: int) -> JobSyncRequest:
    return JobSyncRequest(
        protocol_version=PROTOCOL_VERSION,
        reports=[],
        capacity=NodeJobCapacity(
            accept=True, slots=slots, kinds=[WorkloadClass.CPU], memory_available_mb=8192
        ),
    )


def _sync(app, node_id: uuid.UUID, request: JobSyncRequest):
    with app.state.sessionmaker() as db:
        response = service.sync_node_jobs(
            db,
            db.get(Node, node_id),
            request,
            now=datetime.now(UTC),
            settings=app.state.settings,
            controller_started_at=app.state.started_at,
        )
        db.commit()
        return response


def _submit(app, owner_id: uuid.UUID, count: int) -> list[uuid.UUID]:
    with app.state.sessionmaker() as db:
        owner = db.get(User, owner_id)
        ids = [
            service.submit_job(
                db,
                owner=owner,
                spec=JobSpec(kind=WorkloadClass.CPU, total_units=10),
                name="race",
                priority=0,
                now=datetime.now(UTC),
                settings=app.state.settings,
            ).id
            for _ in range(count)
        ]
        db.commit()
        return ids


class CandidateBarrier:
    """Holds every participating transaction at the candidate SELECT until all arrive."""

    def __init__(self, engine, parties: int) -> None:
        self.engine = engine
        self.barrier = threading.Barrier(parties, timeout=15)
        self.arrived = 0
        self._lock = threading.Lock()

    def __enter__(self):
        event.listen(self.engine, "before_cursor_execute", self._hook)
        return self

    def __exit__(self, *exc):
        event.remove(self.engine, "before_cursor_execute", self._hook)

    def _hook(self, conn, cursor, statement, parameters, context, executemany):
        if CANDIDATE_MARK in statement and statement.lstrip().upper().startswith("SELECT"):
            with self._lock:
                self.arrived += 1
            self.barrier.wait()  # BrokenBarrierError if another side never got here


def _race(app, node_ids, request):
    results: dict[uuid.UUID, object] = {}
    errors: list[BaseException] = []

    def run(node_id):
        try:
            results[node_id] = _sync(app, node_id, request)
        except BaseException as exc:  # noqa: BLE001 -- re-raised in the main thread
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(n,)) for n in node_ids]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not any(t.is_alive() for t in threads), "a claimer hung (deadlock?)"
    if errors:
        raise errors[0]
    return results


@pytest.fixture
def setup(app, make_user, enroll, inventory_factory):
    owner = make_user("racer")
    nodes = [
        uuid.UUID(enroll(inventory_factory(hostname=f"race-{i}", gpus=()))[0]["node_id"])
        for i in range(8)
    ]
    return owner.id, nodes


@pytest.mark.parametrize("round_", range(ROUNDS))
def test_two_agents_race_for_one_job_exactly_one_wins(app, setup, tmp_path, round_):
    owner_id, nodes = setup
    [job_id] = _submit(app, owner_id, 1)

    with CandidateBarrier(app.state.engine, parties=2) as gate:
        results = _race(app, nodes[:2], _offer(1))
    assert gate.arrived == 2, "both transactions must reach the claim phase together"

    winners = [n for n, r in results.items() if r.assignments]
    losers = [n for n, r in results.items() if not r.assignments]
    assert len(winners) == 1 and len(losers) == 1  # criteria 1 and 2
    [assignment] = results[winners[0]].assignments
    assert assignment.job_id == job_id and assignment.attempt == 1

    with app.state.sessionmaker() as db:  # criterion 3: one lease, one attempt
        job = db.get(Job, job_id)
        assert job.state == JobState.ASSIGNED and job.node_id == winners[0]
        assert job.attempt == 1 and job.lease_expires_at is not None
        assigned_logs = db.scalar(
            select(func.count())
            .select_from(JobLog)
            .where(JobLog.job_id == job_id, JobLog.message.like("assigned%"))
        )
        assert assigned_logs == 1

    # Criterion 4: each agent applies its own response; exactly one workload is created.
    adds = 0
    for node_id, response in results.items():
        agent_dir = tmp_path / f"agent-{node_id.hex[:8]}"
        sync = JobSync(agent_dir, snapshot=lambda _p: {}, admission=lambda: None, has_gpu=False)
        sync.apply(response)
        adds += len(list((agent_dir / "workloads" / "requests").glob("*.json")))
    assert adds == 1


@pytest.mark.parametrize("round_", range(ROUNDS))
def test_many_agents_many_jobs_every_job_claimed_exactly_once(app, setup, round_):
    owner_id, nodes = setup
    job_ids = _submit(app, owner_id, 6)
    claimed: list[uuid.UUID] = []
    # 8 agents with 2 slots each race for 6 jobs, all released at the same instant.
    with CandidateBarrier(app.state.engine, parties=len(nodes)) as gate:
        results = _race(app, nodes, _offer(2))
    assert gate.arrived == len(nodes)
    held: dict[uuid.UUID, list] = {n: list(r.assignments) for n, r in results.items()}
    for response in results.values():
        claimed += [a.job_id for a in response.assignments]
    assert len(claimed) == len(set(claimed)), "a job was handed to two agents"
    # SKIP LOCKED may leave a job for a later sync; nothing is ever lost or duplicated.
    # Like real agents, each keeps reporting what it holds: an unreported job counts as
    # lost and is (correctly) requeued.
    for _ in range(5):
        if len(claimed) >= len(job_ids):
            break
        for node in nodes:
            request = JobSyncRequest(
                protocol_version=PROTOCOL_VERSION,
                reports=[
                    AgentJobReport(
                        job_id=a.job_id,
                        attempt=a.attempt,
                        state=LocalJobState.WAITING,
                        units_done=0,
                    )
                    for a in held[node]
                ],
                capacity=_offer(2).capacity,
            )
            new = _sync(app, node, request).assignments
            held[node] += new
            claimed += [a.job_id for a in new]
    assert sorted(claimed) == sorted(job_ids)
    with app.state.sessionmaker() as db:
        rows = db.scalars(select(Job).where(Job.id.in_(job_ids))).all()
        assert all(j.attempt == 1 and j.state == JobState.ASSIGNED for j in rows)


@pytest.mark.parametrize("round_", range(ROUNDS))
def test_report_and_reaper_cannot_overwrite_each_other(app, setup, round_):
    """A node reports completion while another node's sync reaps the expired lease.
    The row lock serializes them, so the job ends in one consistent state."""
    owner_id, nodes = setup
    [job_id] = _submit(app, owner_id, 1)
    holder, bystander = nodes[0], nodes[1]
    [assignment] = _sync(app, holder, _offer(1)).assignments
    with app.state.sessionmaker() as db:  # lease expired, controller past its start grace
        db.get(Job, job_id).lease_expires_at = datetime(2000, 1, 1, tzinfo=UTC)
        db.commit()
    app.state.started_at = datetime(2000, 1, 1, tzinfo=UTC)
    done = JobSyncRequest(
        protocol_version=PROTOCOL_VERSION,
        reports=[
            AgentJobReport(
                job_id=job_id,
                attempt=assignment.attempt,
                state=LocalJobState.COMPLETED,
                units_done=10,
                result=JobResult(units=10, checksum=str(expected_checksum(10))),
            )
        ],
        capacity=NodeJobCapacity(accept=False, slots=0, kinds=[], memory_available_mb=0),
    )
    idle = JobSyncRequest(
        protocol_version=PROTOCOL_VERSION,
        reports=[],
        capacity=NodeJobCapacity(accept=False, slots=0, kinds=[], memory_available_mb=0),
    )
    out: dict[uuid.UUID, object] = {}
    errors: list[BaseException] = []
    start = threading.Barrier(2, timeout=15)

    def run(node_id, request):
        try:
            start.wait()
            out[node_id] = _sync(app, node_id, request)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [
        threading.Thread(target=run, args=(holder, done)),
        threading.Thread(target=run, args=(bystander, idle)),  # its sync runs the reaper
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not errors, errors
    with app.state.sessionmaker() as db:
        job = db.get(Job, job_id)
        if out[holder].acknowledged:  # the report won: success is final
            assert job.state == JobState.SUCCEEDED and job.requeues == 0
            assert job.result is not None
        else:  # the reaper won: the late report is fenced, the job is requeued cleanly
            assert out[holder].cancel == [job_id]
            assert job.state == JobState.QUEUED and job.requeues == 1 and job.result is None
