from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import hashlib
import os
import threading
import time
from typing import Any, Callable, Deque, Dict, Protocol, runtime_checkable


@dataclass(frozen=True)
class QuotaLimits:
    per_minute: int
    per_day: int


@runtime_checkable
class QuotaBackend(Protocol):
    """Backend contract for atomic workspace quota accounting."""

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
    """Provider-neutral adapter for externally managed atomic quota services."""

    distributed = True

    def __init__(self, *, consume: Callable[[str, QuotaLimits, float], Dict[str, Any]], inspect: Callable[[str, QuotaLimits, float], Dict[str, Any]], clear: Callable[[str], None], name: str = "external") -> None:
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


_REDIS_CONSUME_SCRIPT = r"""
local events = KEYS[1]
local sequence = KEYS[2]
local per_minute = tonumber(ARGV[1])
local per_day = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
local clock = redis.call('TIME')
local now = tonumber(clock[1]) + (tonumber(clock[2]) / 1000000)
redis.call('ZREMRANGEBYSCORE', events, '-inf', now - 86400)
local day_used = redis.call('ZCARD', events)
local minute_used = redis.call('ZCOUNT', events, now - 60, '+inf')
if minute_used >= per_minute then
  return {0, 1, minute_used, day_used}
end
if day_used >= per_day then
  return {0, 2, minute_used, day_used}
end
local seq = redis.call('INCR', sequence)
local member = tostring(clock[1]) .. ':' .. tostring(clock[2]) .. ':' .. tostring(seq)
redis.call('ZADD', events, now, member)
redis.call('EXPIRE', events, ttl)
redis.call('EXPIRE', sequence, ttl)
return {1, 0, minute_used + 1, day_used + 1}
"""

_REDIS_STATUS_SCRIPT = r"""
local events = KEYS[1]
local ttl = tonumber(ARGV[1])
local clock = redis.call('TIME')
local now = tonumber(clock[1]) + (tonumber(clock[2]) / 1000000)
redis.call('ZREMRANGEBYSCORE', events, '-inf', now - 86400)
local day_used = redis.call('ZCARD', events)
local minute_used = redis.call('ZCOUNT', events, now - 60, '+inf')
if day_used > 0 then redis.call('EXPIRE', events, ttl) end
return {minute_used, day_used}
"""


class RedisQuotaBackend:
    """Atomic shared quota backend for multi-replica deployments.

    Redis server time is used inside Lua so application-node clock skew cannot
    create inconsistent windows. Both keys use the same Redis Cluster hash tag.
    The read/decide/write path executes as one short atomic script and failures
    are propagated: production enforcement never silently falls back to memory.
    """

    name = "redis"
    distributed = True

    def __init__(self, url: str, *, key_prefix: str = "trustkernel:quota", socket_timeout: float = 2.0) -> None:
        if not url.strip():
            raise ValueError("Redis quota backend requires TRUSTKERNEL_REDIS_URL")
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - dependency gate covers this
            raise RuntimeError("redis package is required for RedisQuotaBackend") from exc
        self._client = redis.Redis.from_url(
            url,
            decode_responses=False,
            socket_connect_timeout=socket_timeout,
            socket_timeout=socket_timeout,
            health_check_interval=30,
        )
        self._prefix = key_prefix.strip(":") or "trustkernel:quota"
        self._consume = self._client.register_script(_REDIS_CONSUME_SCRIPT)
        self._inspect = self._client.register_script(_REDIS_STATUS_SCRIPT)
        self._ttl_seconds = 86520

    def _keys(self, workspace_id: str) -> tuple[str, str]:
        digest = hashlib.sha256(workspace_id.encode("utf-8")).hexdigest()
        tag = "{" + digest + "}"
        return f"{self._prefix}:{tag}:events", f"{self._prefix}:{tag}:seq"

    def ping(self) -> bool:
        return bool(self._client.ping())

    def check_and_consume(self, workspace_id: str, limits: QuotaLimits, now: float) -> Dict[str, Any]:
        del now  # Redis server time is authoritative for distributed windows.
        raw = self._consume(keys=list(self._keys(workspace_id)), args=[limits.per_minute, limits.per_day, self._ttl_seconds])
        allowed, reason_code, minute_used, day_used = [int(value) for value in raw]
        reason = {0: "ok", 1: "minute_rate_limit", 2: "daily_quota"}.get(reason_code, "backend_error")
        return _result(bool(allowed), reason, minute_used, limits, day_used)

    def status(self, workspace_id: str, limits: QuotaLimits, now: float) -> Dict[str, Any]:
        del now
        events, _ = self._keys(workspace_id)
        raw = self._inspect(keys=[events], args=[self._ttl_seconds])
        minute_used, day_used = [int(value) for value in raw]
        return _status(minute_used, limits, day_used)

    def reset(self, workspace_id: str) -> None:
        self._client.delete(*self._keys(workspace_id))


def _status(minute_used: int, limits: QuotaLimits, day_used: int) -> Dict[str, Any]:
    return {"minute_used": int(minute_used), "minute_limit": limits.per_minute, "day_used": int(day_used), "day_limit": limits.per_day}


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


def configure_quota_backend() -> QuotaBackend:
    backend = os.getenv("TRUSTKERNEL_QUOTA_BACKEND", "memory").strip().lower()
    if backend in {"memory", "inmemory", "in-memory"}:
        quotas.use_in_memory_backend()
        return quotas._backend
    if backend == "redis":
        redis_backend = RedisQuotaBackend(
            os.getenv("TRUSTKERNEL_REDIS_URL", ""),
            key_prefix=os.getenv("TRUSTKERNEL_REDIS_QUOTA_PREFIX", "trustkernel:quota"),
            socket_timeout=max(0.1, float(os.getenv("TRUSTKERNEL_REDIS_TIMEOUT_SECONDS", "2"))),
        )
        if os.getenv("TRUSTKERNEL_REDIS_STARTUP_PING", "1") == "1" and not redis_backend.ping():
            raise RuntimeError("Redis quota backend startup ping failed")
        quotas.set_backend(redis_backend)
        return redis_backend
    raise ValueError(f"Unsupported TRUSTKERNEL_QUOTA_BACKEND: {backend}")
