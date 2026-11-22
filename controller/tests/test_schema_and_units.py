import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext

from udcs_controller.core.ratelimit import RateLimiter
from udcs_controller.core.security import generate_token, hash_password, hash_token, verify_password
from udcs_controller.database import registry  # noqa: F401
from udcs_controller.database.base import Base
from udcs_controller.database.migrate import alembic_config


def test_migrations_match_models(app):
    with app.state.engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        assert compare_metadata(context, Base.metadata) == []


def test_downgrade_and_upgrade_round_trip(app):
    with app.state.engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.downgrade(cfg, "base")
        command.upgrade(cfg, "head")


def test_rate_limiter_sliding_window():
    now = [0.0]
    limiter = RateLimiter(2, 60, clock=lambda: now[0])
    assert limiter.allow("k") and limiter.allow("k")
    assert not limiter.allow("k")
    assert limiter.allow("other")
    now[0] = 60.1
    assert limiter.allow("k")


def test_rate_limiter_bounds_memory():
    limiter = RateLimiter(1, 60, clock=lambda: 0.0, max_keys=10)
    for i in range(50):
        limiter.allow(f"key-{i}")
    assert len(limiter._hits) <= 10


def test_rate_limiter_rejects_bad_config():
    with pytest.raises(ValueError):
        RateLimiter(0, 60)


def test_passwords_and_tokens():
    hashed = hash_password("s3cret-password")
    assert hashed.startswith("$argon2id$")
    assert verify_password(hashed, "s3cret-password")
    assert not verify_password(hashed, "wrong")
    assert not verify_password("not-a-hash", "s3cret-password")
    token = generate_token("udcs_x_")
    assert token.startswith("udcs_x_") and len(token) > 40
    assert hash_token(token) != token and len(hash_token(token)) == 64
