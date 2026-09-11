from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import os
import threading
import time
from typing import Any, Callable, Deque, Dict, Protocol, Tuple, runtime_checkable


@dataclass(frozen=True)
class QuotaLimits:
    per_minute: int
    per_day: int


@runtime_checkable
class QuotaBackend(Protocol):
    """Backend contract for atomic workspace quota accounting.

    Distributed implementations MUST make check_and_consume atomic for a
    workspace key. This keeps the policy decision and counter increment in one
    operation and prevents concurrent workers from overspending a quota.
    """

    name: str
    distributed: bool

    def check_and_consume(self, workspace_id: str, limits: QuotaLimits, now: float) -> Dict[str, Any]: ...

    def status(self, workspace_id: str, limits: QuotaLimits, now: float) -> Dict[str, Any]: ...

    def reset(self, workspace_id: str) -> None: ...


class InMemoryQuotaBackend:
    """Thread-safe offline backend used by default and in hackathon demos."""

    name = "memory"
    distributed = False

    def __init__(self) -> None:
        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.RLock()

    @staticmethod
    def _trim(bucket: Deque[float], now: float) -> None:
        day_cutoff = now - 86400
        while bucket and bucket[0] < day_cutoff:
            bucket.popleft()

    def check_and_consume(self, workspace_id: str, limits: QuotaLimits, now: float) -> Dict[str, Any]:
        with self._lock:
            bucket = self._events[workspace_id]
            self._trim(bucket, now)
            day_count = len(bucket)
            minute_count = sum(1 for timestamp in bucket if timestamp >= now - 60)
            if minute_count >= limits.per_minute:
                return _result(False, "minute_rate_limit", minute_count, limits, day_count)
            if day_count >= limits.per_day:
                return _result(False, "daily_quota", minute_count, limits, day_count)
            bucket.append(now)
            return _result(True, "ok", minute_count + 1, limits, day_count + 1)

    def status(self, workspace_id: str, limits: QuotaLimits, now: float) -> Dict[str, Any]:
        with self._lock:
            bucket = self._events[workspace_id]
            self._trim(bucket, now)
            day_count = len(bucket)
            minute_count = sum(1 for timestamp in bucket if timestamp >= now - 60)
        return _status(minute_count, limits, day_count)

    def reset(self, workspace_id: str) -> None:
        with self._lock:
            self._events.pop(workspace_id, None)


class CallbackQuotaBackend:
    """Adapter for Redis/DynamoDB/SQL-backed atomic quota implementations.

    The callbacks are intentionally provider-neutral: production deployments
    can bind an atomic Redis Lua script, a transactional SQL function, or a
    managed rate-limit service without coupling TrustKernel core to one vendor.
    """

    distributed = True

    def __init__(
        self,
        *,
        consume: Callable[[str, QuotaLimits, float], Dict[str, Any]],
        inspect: Callable[[str, QuotaLimits, float], Dict[str, Any]],
        clear: Callable[[str], None],
        name: str = "external",
    ) -> None:
        self._consume = consume
        self._inspect = inspect
        self._clear = clear
        self.name = name.strip() or "external"

    def check_and_consume(self, workspace_id: str, limits: QuotaLimits, now: float) -> Dict[str, Any]:
        return _validate_backend_result(self._consume(workspace_id, limits, now), require_allowed=True)

    def status(self, workspace_id: str, limits: QuotaLimits, now: float) -> Dict[str, Any]:
        return _validate_backend_result(self._inspect(workspace_id, limits, now), require_allowed=False)

    def reset(self, workspace_id: str) -> None:
        self._clear(workspace_id)


def _status(minute_used: int, limits: QuotaLimits, day_used: int) -> Dict[str, Any]:
    return {
        "minute_used": int(minute_used),
        "minute_limit": limits.per_minute,
        "day_used": int(day_used),
        "day_limit": limits.per_day,
    }


def _result(allowed: bool, reason: str, minute_used: int, limits: QuotaLimits, day_used: int) -> Dict[str, Any]:
    return {"allowed": allowed, "reason": reason, **_status(minute_used, limits, day_used)}


def _validate_backend_result(result: Dict[str, Any], *, require_allowed: bool) -> Dict[str, Any]:
    if not isinstance(result, dict):
        raise TypeError("quota backend must return a dictionary")
    required = {"minute_used", "minute_limit", "day_used", "day_limit"}
    if require_allowed:
        required.update({"allowed", "reason"})
    missing = sorted(required.difference(result))
    if missing:
        raise ValueError(f"quota backend result missing fields: {', '.join(missing)}")
    return result


class QuotaService:
    """Workspace quota guard with a swappable atomic accounting backend."""

    def __init__(self, backend: QuotaBackend | None = None) -> None:
        self._backend: QuotaBackend = backend or InMemoryQuotaBackend()
        self._backend_lock = threading.RLock()

    @staticmethod
    def _limits() -> QuotaLimits:
        per_minute = max(1, int(os.getenv("TRUSTKERNEL_RATE_LIMIT_PER_MINUTE", "120")))
        per_day = max(per_minute, int(os.getenv("TRUSTKERNEL_DAILY_ACTION_QUOTA", "10000")))
        return QuotaLimits(per_minute=per_minute, per_day=per_day)

    @property
    def backend_info(self) -> Dict[str, Any]:
        with self._backend_lock:
            return {"name": self._backend.name, "distributed": bool(self._backend.distributed)}

    def set_backend(self, backend: QuotaBackend) -> None:
        if not isinstance(backend, QuotaBackend):
            raise TypeError("backend does not satisfy QuotaBackend")
        with self._backend_lock:
            self._backend = backend

    def use_in_memory_backend(self) -> None:
        self.set_backend(InMemoryQuotaBackend())

    def check_and_consume(self, workspace_id: str, now: float | None = None) -> Dict[str, Any]:
        current = time.time() if now is None else now
        with self._backend_lock:
            backend = self._backend
        result = backend.check_and_consume(workspace_id, self._limits(), current)
        return {**result, "backend": backend.name, "distributed": bool(backend.distributed)}

    def status(self, workspace_id: str, now: float | None = None) -> Dict[str, Any]:
        current = time.time() if now is None else now
        with self._backend_lock:
            backend = self._backend
        result = backend.status(workspace_id, self._limits(), current)
        return {**result, "backend": backend.name, "distributed": bool(backend.distributed)}

    def reset(self, workspace_id: str) -> None:
        with self._backend_lock:
            backend = self._backend
        backend.reset(workspace_id)


quotas = QuotaService()
