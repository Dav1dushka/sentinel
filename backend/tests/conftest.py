"""Test configuration: an in-memory SQLite database and inline processing (no Redis)."""
import os

os.environ.setdefault("SENTINEL_DATABASE_URL", "sqlite://")
os.environ.setdefault("SENTINEL_JWT_SECRET", "test-jwt-secret-0123456789-abcdefghijklmnop")
os.environ.setdefault("SENTINEL_INGEST_TOKEN", "test-ingest-token-0123456789")
os.environ.setdefault("SENTINEL_ADMIN_EMAIL", "admin@test.local")
os.environ.setdefault("SENTINEL_ADMIN_PASSWORD", "admin-password-123")
os.environ.pop("SENTINEL_REDIS_URL", None)
os.environ.pop("SENTINEL_TELEGRAM_TOKEN", None)
