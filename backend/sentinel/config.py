"""Settings come from environment variables (12-factor style).

Only ``SENTINEL_JWT_SECRET`` and ``SENTINEL_INGEST_TOKEN`` matter for
security; both have obviously-unsafe development defaults and the app logs a
warning when they are left unchanged.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DEV_SECRET = "dev-only-change-me"
DEFAULT_RULES = BASE_DIR / "rules" / "default.yml"
log = logging.getLogger("sentinel")


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    return value if value not in (None, "") else default


def _from_env(name: str, default: str | None = None):
    return field(default_factory=lambda: _env(name, default))


def _origins() -> list[str]:
    raw = _env("SENTINEL_CORS_ORIGINS", "http://localhost:5173") or ""
    return [o.strip() for o in raw.split(",") if o.strip()]


@dataclass(frozen=True)
class Settings:
    database_url: str = _from_env("SENTINEL_DATABASE_URL", f"sqlite:///{BASE_DIR / 'sentinel.db'}")
    redis_url: str | None = _from_env("SENTINEL_REDIS_URL")
    jwt_secret: str = _from_env("SENTINEL_JWT_SECRET", DEV_SECRET)
    jwt_ttl_minutes: int = field(default_factory=lambda: int(_env("SENTINEL_JWT_TTL_MINUTES", "60")))
    ingest_token: str = _from_env("SENTINEL_INGEST_TOKEN", DEV_SECRET)
    rules_path: Path = field(default_factory=lambda: Path(_env("SENTINEL_RULES", str(DEFAULT_RULES))))
    cors_origins: list[str] = field(default_factory=_origins)
    telegram_token: str | None = _from_env("SENTINEL_TELEGRAM_TOKEN")
    telegram_chat_id: str | None = _from_env("SENTINEL_TELEGRAM_CHAT_ID")
    notify_min_severity: str = _from_env("SENTINEL_NOTIFY_MIN_SEVERITY", "high")
    admin_email: str = _from_env("SENTINEL_ADMIN_EMAIL", "admin@sentinel.local")
    admin_password: str = _from_env("SENTINEL_ADMIN_PASSWORD", "change-me-please")
    max_lines_per_batch: int = 5000

    def warn_if_insecure(self) -> None:
        if self.jwt_secret == DEV_SECRET or self.ingest_token == DEV_SECRET:
            log.warning("Sentinel is running with development secrets. "
                        "Set SENTINEL_JWT_SECRET and SENTINEL_INGEST_TOKEN.")


@lru_cache
def get_settings() -> Settings:
    return Settings()
