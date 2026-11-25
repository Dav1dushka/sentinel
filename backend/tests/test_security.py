from datetime import UTC, datetime, timedelta

import jwt
import pytest

from sentinel.security import create_access_token, decode_access_token, hash_password, tokens_equal, verify_password

SECRET = "test-secret-that-is-definitely-long-enough-0123"


def test_hash_roundtrip_and_salt():
    h1, h2 = hash_password("correct horse battery"), hash_password("correct horse battery")
    assert h1 != h2 and h1.startswith("scrypt$")
    assert verify_password("correct horse battery", h1)
    assert not verify_password("correct horse batterY", h1)


@pytest.mark.parametrize("stored", ["", "plain", "md5$x$y", "scrypt$1$2$3$not-base64$x"])
def test_verify_rejects_malformed_hashes(stored):
    assert verify_password("whatever-password", stored) is False


def test_short_password_rejected():
    with pytest.raises(ValueError):
        hash_password("short")


def test_token_roundtrip():
    claims = decode_access_token(create_access_token(7, "analyst", SECRET), SECRET)
    assert claims["sub"] == "7" and claims["role"] == "analyst"


def test_token_wrong_secret_expired_or_tampered():
    tok = create_access_token(1, "admin", SECRET)
    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(tok, "another-secret-entirely-and-also-long-0123456")
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(create_access_token(1, "admin", SECRET, ttl_minutes=-1), SECRET)
    now = datetime.now(UTC)
    forged = jwt.encode({"sub": "1", "role": "root", "iss": "sentinel", "iat": now,
                         "exp": now + timedelta(minutes=5)}, SECRET, algorithm="HS256")
    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(forged, SECRET)
    none_alg = jwt.encode({"sub": "1", "role": "admin", "iss": "sentinel", "iat": now,
                           "exp": now + timedelta(minutes=5)}, "", algorithm="none")
    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(none_alg, SECRET)


def test_tokens_equal():
    assert tokens_equal("abc", "abc") and not tokens_equal("abd", "abc") and not tokens_equal(None, "abc")
