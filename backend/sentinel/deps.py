"""FastAPI dependencies: current user, role checks, login rate limiting."""
from __future__ import annotations

import time
from collections import defaultdict, deque

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from .config import get_settings
from .db import User, get_db
from .security import decode_access_token, tokens_equal

oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> User:
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token",
                                 headers={"WWW-Authenticate": "Bearer"})
    try:
        claims = decode_access_token(token, get_settings().jwt_secret)
    except jwt.InvalidTokenError:
        raise unauthorized from None
    user = db.get(User, int(claims["sub"]))
    if not user or not user.is_active:
        raise unauthorized
    return user


def require_admin(user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin role required")
    return user


def ingest_auth(x_ingest_token: str | None = Header(default=None)) -> None:
    if not tokens_equal(x_ingest_token, get_settings().ingest_token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bad ingest token")


class LoginLimiter:
    """Allow at most ``limit`` failed logins per client in ``window`` seconds."""

    def __init__(self, limit: int = 8, window: int = 300):
        self.limit, self.window = limit, window
        self.fails: dict[str, deque] = defaultdict(deque)

    def _trim(self, key: str, now: float) -> deque:
        q = self.fails[key]
        while q and q[0] < now - self.window:
            q.popleft()
        return q

    def blocked(self, key: str) -> bool:
        return len(self._trim(key, time.monotonic())) >= self.limit

    def fail(self, key: str) -> None:
        self._trim(key, time.monotonic()).append(time.monotonic())

    def reset(self, key: str) -> None:
        self.fails.pop(key, None)


login_limiter = LoginLimiter()
