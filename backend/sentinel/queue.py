"""A tiny job queue on top of a Redis list.

The API pushes raw log batches; the worker pops them. Keeping parsing and
detection out of the request path means a flood of log lines cannot slow the
dashboard down, and the worker can be restarted without losing queued work.
"""
from __future__ import annotations

import json
from typing import Any

QUEUE_KEY = "sentinel:batches"


class RedisQueue:
    def __init__(self, url: str):
        import redis  # imported lazily so local runs without Redis still work

        self.r = redis.Redis.from_url(url, decode_responses=True)

    def push(self, batch: dict[str, Any]) -> None:
        self.r.rpush(QUEUE_KEY, json.dumps(batch))

    def pop(self, timeout: int = 5) -> dict[str, Any] | None:
        item = self.r.blpop([QUEUE_KEY], timeout=timeout)
        return json.loads(item[1]) if item else None

    def size(self) -> int:
        return int(self.r.llen(QUEUE_KEY))

    def ping(self) -> bool:
        try:
            return bool(self.r.ping())
        except Exception:
            return False
