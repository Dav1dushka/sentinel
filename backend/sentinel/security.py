"""Password hashing and JWT helpers.

Passwords use scrypt from the standard library (memory-hard, salted, no extra
dependency). Hashes are self-describing so parameters can be raised later
without breaking existing accounts::

    scrypt$16384$8$1$<salt-b64>$<hash-b64>
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

import jwt

ROLES = ("analyst", "admin")
_N, _R, _P, _LEN = 2 ** 14, 8, 1, 32
ALGORITHM = "HS256"
ISSUER = "sentinel"


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def hash_password(password: str) -> str:
    if len(password) < 10:
        raise ValueError("password must be at least 10 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=_LEN)
    return f"scrypt${_N}${_R}${_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, hash_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        expected = base64.b64decode(hash_b64)
        digest = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt_b64),
                                n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, expected)


def create_access_token(user_id: int, role: str, secret: str, ttl_minutes: int = 60) -> str:
    now = datetime.now(UTC)
    payload = {"sub": str(user_id), "role": role, "iss": ISSUER, "iat": now,
               "exp": now + timedelta(minutes=ttl_minutes), "jti": secrets.token_hex(8)}
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


def decode_access_token(token: str, secret: str) -> dict:
    """Raises ``jwt.InvalidTokenError`` (or a subclass) on any problem."""
    claims = jwt.decode(token, secret, algorithms=[ALGORITHM], issuer=ISSUER,
                        options={"require": ["sub", "exp", "iat", "iss", "role"]})
    if claims["role"] not in ROLES:
        raise jwt.InvalidTokenError("unknown role")
    return claims


def tokens_equal(a: str | None, b: str) -> bool:
    """Constant-time comparison for shared secrets such as the ingest token."""
    return a is not None and hmac.compare_digest(a.encode(), b.encode())
