"""Background scheduler: runs every configured collector at a fixed interval.

A single daemon thread inside the web process - no extra service or dependency.
The stop event makes shutdown immediate even while the thread is waiting.
"""
import logging
import threading
from datetime import datetime, timedelta, timezone

from app import config, evidence, scoring

log = logging.getLogger("comply.scheduler")


def run_all() -> dict[str, dict]:
    """Collect from every configured source, then record one score snapshot."""
    results = {}
    collectors = evidence.get_collectors()
    # The internal 'comply' check runs last so it sees the state after this cycle.
    for name in sorted(collectors, key=lambda n: n == "comply"):
        c = collectors[name]
        if c.is_configured():
            results[name] = evidence.run_collection(name, c, snapshot=False)
    scoring.snapshot_all()
    return results


class Scheduler:
    def __init__(self):
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.next_run: datetime | None = None
        self.last_run: datetime | None = None

    @property
    def enabled(self) -> bool:
        return config.COLLECT_INTERVAL_HOURS > 0

    def start(self) -> None:
        if not self.enabled or self._thread:
            return
        self._stop.clear()
        self.next_run = datetime.now(timezone.utc) + timedelta(seconds=config.COLLECT_START_DELAY_SECONDS)
        self._thread = threading.Thread(target=self._loop, name="comply-scheduler", daemon=True)
        self._thread.start()
        log.info("Automatic collection every %sh, first run at %s UTC",
                 config.COLLECT_INTERVAL_HOURS, self.next_run.strftime("%Y-%m-%d %H:%M"))

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            wait = max(0.0, (self.next_run - datetime.now(timezone.utc)).total_seconds())
            if self._stop.wait(wait):
                return
            try:
                summary = run_all()
                log.info("Automatic collection finished: %s",
                         {k: v["message"] for k, v in summary.items()})
            except Exception:  # noqa: BLE001
                log.exception("Automatic collection failed")
            self.last_run = datetime.now(timezone.utc)
            self.next_run = self.last_run + timedelta(hours=config.COLLECT_INTERVAL_HOURS)


scheduler = Scheduler()
