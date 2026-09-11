from __future__ import annotations
from collections import defaultdict, deque
import os
import threading
import time
from typing import Any, Deque, Dict, Tuple


class QuotaService:
    """Dependency-free sliding-window workspace quota guard."""

    def __init__(self) -> None:
        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.RLock()

    @staticmethod
    def _limits() -> Tuple[int, int]:
        per_minute = max(1, int(os.getenv("TRUSTKERNEL_RATE_LIMIT_PER_MINUTE", "120")))
        per_day = max(per_minute, int(os.getenv("TRUSTKERNEL_DAILY_ACTION_QUOTA", "10000")))
        return per_minute, per_day

    def check_and_consume(self, workspace_id: str, now: float | None = None) -> Dict[str, Any]:
        current = time.time() if now is None else now
        per_minute, per_day = self._limits()
        with self._lock:
            bucket = self._events[workspace_id]
            day_cutoff = current - 86400
            while bucket and bucket[0] < day_cutoff:
                bucket.popleft()
            day_count = len(bucket)
            minute_count = sum(1 for t in bucket if t >= current - 60)
            if minute_count >= per_minute:
                return {"allowed": False, "reason": "minute_rate_limit", "minute_used": minute_count, "minute_limit": per_minute, "day_used": day_count, "day_limit": per_day}
            if day_count >= per_day:
                return {"allowed": False, "reason": "daily_quota", "minute_used": minute_count, "minute_limit": per_minute, "day_used": day_count, "day_limit": per_day}
            bucket.append(current)
            return {"allowed": True, "reason": "ok", "minute_used": minute_count + 1, "minute_limit": per_minute, "day_used": day_count + 1, "day_limit": per_day}

    def status(self, workspace_id: str, now: float | None = None) -> Dict[str, Any]:
        current = time.time() if now is None else now
        per_minute, per_day = self._limits()
        with self._lock:
            bucket = self._events[workspace_id]
            day_cutoff = current - 86400
            while bucket and bucket[0] < day_cutoff:
                bucket.popleft()
            day_count = len(bucket)
            minute_count = sum(1 for t in bucket if t >= current - 60)
        return {"minute_used": minute_count, "minute_limit": per_minute, "day_used": day_count, "day_limit": per_day}

    def reset(self, workspace_id: str) -> None:
        with self._lock:
            self._events.pop(workspace_id, None)


quotas = QuotaService()
