"""Queue worker: pops log batches from Redis and runs the pipeline.

Run:  python -m sentinel.worker
Only one worker should run, because detection windows live in its memory.
"""
from __future__ import annotations

import logging
import signal
import time

from .config import get_settings
from .db import SessionLocal, init_db
from .pipeline import process_batch
from .queue import RedisQueue

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sentinel.worker")
running = True


def _stop(*_):
    global running
    running = False
    log.info("shutting down after the current batch")


def main() -> None:
    url = get_settings().redis_url
    if not url:
        raise SystemExit("SENTINEL_REDIS_URL is not set; the API processes batches inline instead.")
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    init_db()
    queue = RedisQueue(url)
    while not queue.ping():
        log.info("waiting for redis…")
        time.sleep(1)
    log.info("worker started")
    while running:
        batch = queue.pop(timeout=2)
        if not batch:
            continue
        try:
            with SessionLocal() as db:
                process_batch(db, batch["source"], batch["lines"], host=batch.get("host"))
        except Exception:  # keep the worker alive; the batch is logged for replay
            log.exception("batch failed (source=%s, %d lines)", batch.get("source"), len(batch.get("lines", [])))


if __name__ == "__main__":
    main()
