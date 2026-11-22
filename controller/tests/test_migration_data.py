"""Migration 0002 against real Milestone 1 rows, in both directions.

The schema tests only migrate empty databases. This one seeds 0001-era data, then
checks the row-level logic of 0002. That logic copies tokens into keys, backfills
nodes, rewrites state on downgrade, and swaps the CHECK constraint. The test runs
on whichever backend the test database is, so in CI it also runs on PostgreSQL.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from alembic import command

from udcs_controller.database.base import UTCDateTime
from udcs_controller.database.migrate import alembic_config

T0 = datetime(2026, 1, 5, 9, 0, tzinfo=UTC)

users = sa.table(
    "users",
    sa.column("id", sa.Uuid()),
    sa.column("username", sa.String()),
    sa.column("display_name", sa.String()),
    sa.column("password_hash", sa.String()),
    sa.column("role", sa.String()),
    sa.column("is_active", sa.Boolean()),
    sa.column("created_at", UTCDateTime()),
    sa.column("updated_at", UTCDateTime()),
)
NODE_COLUMNS_0001 = (
    sa.column("id", sa.Uuid()),
    sa.column("name", sa.String()),
    sa.column("hostname", sa.String()),
    sa.column("admin_state", sa.String()),
    sa.column("credential_hash", sa.String()),
    sa.column("enrolled_at", UTCDateTime()),
    sa.column("agent_version", sa.String()),
    sa.column("protocol_version", sa.Integer()),
)
nodes_0001 = sa.table("nodes", *NODE_COLUMNS_0001)
nodes_0002 = sa.table(
    "nodes",
    *[sa.column(c.name, c.type) for c in NODE_COLUMNS_0001],
    sa.column("lab", sa.String()),
    sa.column("credential_issued_at", UTCDateTime()),
    sa.column("approved_at", UTCDateTime()),
    sa.column("enrollment_key_id", sa.Uuid()),
)
tokens = sa.table(
    "enrollment_tokens",
    sa.column("id", sa.Uuid()),
    sa.column("token_hash", sa.String()),
    sa.column("created_by_user_id", sa.Uuid()),
    sa.column("note", sa.String()),
    sa.column("created_at", UTCDateTime()),
    sa.column("expires_at", UTCDateTime()),
    sa.column("used_at", UTCDateTime()),
    sa.column("node_id", sa.Uuid()),
)
keys = sa.table(
    "enrollment_keys",
    sa.column("id", sa.Uuid()),
    sa.column("lab", sa.String()),
    sa.column("max_uses", sa.Integer()),
    sa.column("use_count", sa.Integer()),
    sa.column("auto_approve", sa.Boolean()),
    sa.column("last_used_at", UTCDateTime()),
)


def _node(name: str, state: str, enrolled_at: datetime) -> dict:
    return {
        "id": uuid.uuid4(),
        "name": name,
        "hostname": name,
        "admin_state": state,
        "credential_hash": uuid.uuid4().hex * 2,
        "enrolled_at": enrolled_at,
        "agent_version": "0.1.0",
        "protocol_version": 1,
    }


def _insert_rejected(conn: sa.Connection, statement: sa.Executable) -> bool:
    try:
        with conn.begin_nested():  # a savepoint keeps PostgreSQL's transaction usable
            conn.execute(statement)
    except sa.exc.IntegrityError:
        return True
    return False


def test_0002_migrates_milestone_1_rows_up_and_down(app):
    with app.state.engine.begin() as conn:
        cfg = alembic_config()
        cfg.attributes["connection"] = conn
        command.downgrade(cfg, "0001")

        admin = uuid.uuid4()
        conn.execute(
            users.insert().values(
                id=admin,
                username="admin",
                display_name="Admin",
                password_hash="x",
                role="admin",
                is_active=True,
                created_at=T0,
                updated_at=T0,
            )
        )
        enrolled = _node("lab-a-01", "active", T0 + timedelta(hours=1))
        maint = _node("lab-a-02", "maintenance", T0 + timedelta(hours=2))
        conn.execute(nodes_0001.insert(), [enrolled, maint])
        used_token, unused_token = uuid.uuid4(), uuid.uuid4()
        token_common = {"created_by_user_id": admin, "created_at": T0, "note": "m1"}
        conn.execute(
            tokens.insert(),
            [
                {
                    **token_common,
                    "id": used_token,
                    "token_hash": "a" * 64,
                    "expires_at": T0 + timedelta(days=1),
                    "used_at": T0 + timedelta(hours=1),
                    "node_id": enrolled["id"],
                },
                {
                    **token_common,
                    "id": unused_token,
                    "token_hash": "b" * 64,
                    "expires_at": T0 + timedelta(days=1),
                    "used_at": None,
                    "node_id": None,
                },
            ],
        )
        pending_at_0001 = nodes_0001.insert().values(**_node("x", "pending", T0))
        assert _insert_rejected(conn, pending_at_0001), "0001 must reject 'pending'"

        command.upgrade(cfg, "0002")

        rows = {r.id: r for r in conn.execute(sa.select(keys))}
        assert set(rows) == {used_token, unused_token}
        assert all(r.lab == "legacy" and r.max_uses == 1 and r.auto_approve for r in rows.values())
        assert rows[used_token].use_count == 1
        assert rows[used_token].last_used_at == T0 + timedelta(hours=1)
        assert rows[unused_token].use_count == 0 and rows[unused_token].last_used_at is None

        migrated = {r.id: r for r in conn.execute(sa.select(nodes_0002))}
        for original in (enrolled, maint):
            row = migrated[original["id"]]
            assert row.credential_issued_at == original["enrolled_at"]
            assert row.approved_at == original["enrolled_at"]
            assert row.lab == ""
        assert migrated[enrolled["id"]].enrollment_key_id == used_token
        assert migrated[maint["id"]].enrollment_key_id is None
        assert not sa.inspect(conn).has_table("enrollment_tokens")

        pending = {
            **_node("lab-b-01", "pending", T0 + timedelta(hours=3)),
            "lab": "lab-b",
            "credential_issued_at": T0 + timedelta(hours=3),
        }
        conn.execute(nodes_0002.insert().values(**pending))  # head accepts 'pending'

        command.downgrade(cfg, "0001")

        states = dict(conn.execute(sa.select(nodes_0001.c.id, nodes_0001.c.admin_state)).all())
        assert states[pending["id"]] == "maintenance", "pending must not survive a downgrade"
        assert states[enrolled["id"]] == "active" and states[maint["id"]] == "maintenance"
        restored = {r.id: r for r in conn.execute(sa.select(tokens))}
        assert set(restored) == {used_token, unused_token}
        assert restored[used_token].node_id == enrolled["id"]
        assert restored[used_token].used_at == T0 + timedelta(hours=1)
        assert restored[unused_token].node_id is None and restored[unused_token].used_at is None
        assert not sa.inspect(conn).has_table("enrollment_keys")
        again = nodes_0001.insert().values(**_node("y", "pending", T0))
        assert _insert_rejected(conn, again), "downgraded CHECK must reject 'pending' again"

        command.upgrade(cfg, "head")


@pytest.mark.parametrize("revision", ["0001", "0002"])
def test_each_revision_upgrades_from_an_empty_database(app, revision):
    with app.state.engine.begin() as conn:
        cfg = alembic_config()
        cfg.attributes["connection"] = conn
        command.downgrade(cfg, "base")
        assert set(sa.inspect(conn).get_table_names()) <= {"alembic_version"}
        command.upgrade(cfg, revision)
        command.upgrade(cfg, "head")
