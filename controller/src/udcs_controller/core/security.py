"""Password hashing and opaque token primitives.

Tokens are 256-bit random secrets with a type prefix. Only their SHA-256 hash is
persisted: a database leak does not yield usable credentials, and because the
secret has full entropy a fast hash (not Argon2) is appropriate here.
"""

from __future__ import annotations

import functools
import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()  # Argon2id with library defaults (RFC 9106 low-memory profile)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except (VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


@functools.cache
def _dummy_hash() -> str:
    return _hasher.hash(secrets.token_urlsafe(16))


def burn_password_check(password: str) -> None:
    """Spend the same time as a real verification (unknown-user login path)."""
    verify_password(_dummy_hash(), password)


def generate_token(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
