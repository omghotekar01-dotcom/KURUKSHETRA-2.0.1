from __future__ import annotations

import hashlib
import threading
import time
from typing import Protocol, runtime_checkable


_MAX_NONCE_LENGTH = 256
_DEFAULT_TTL_SECONDS = 300


def _validate_nonce(nonce: str) -> str:
    value = str(nonce)
    if not value.strip():
        raise ValueError("replay nonce must be non-empty")
    if len(value) > _MAX_NONCE_LENGTH:
        raise ValueError(f"replay nonce must be at most {_MAX_NONCE_LENGTH} characters")
    return value


def _nonce_digest(nonce: str) -> str:
    return hashlib.sha256(_validate_nonce(nonce).encode("utf-8")).hexdigest()


@runtime_checkable
class ReplayGuard(Protocol):
    """Single-use nonce contract for replay-sensitive signed envelopes."""

    name: str
    distributed: bool

    def consume(self, nonce: str) -> bool: ...


class InMemoryReplayGuard:
    """Thread-safe offline replay guard for tests, local development, and Judge Mode."""

    name = "memory"
    distributed = False

    def __init__(self, *, ttl_seconds: int = _DEFAULT_TTL_SECONDS) -> None:
        if ttl_seconds <= 0 or ttl_seconds > _DEFAULT_TTL_SECONDS:
            raise ValueError(f"ttl_seconds must be between 1 and {_DEFAULT_TTL_SECONDS}")
        self._ttl_seconds = ttl_seconds
        self._seen: dict[str, float] = {}
        self._lock = threading.RLock()

    def consume(self, nonce: str) -> bool:
        digest = _nonce_digest(nonce)
        now = time.monotonic()
        with self._lock:
            expired = [key for key, expiry in self._seen.items() if expiry <= now]
            for key in expired:
                self._seen.pop(key, None)
            if digest in self._seen:
                return False
            self._seen[digest] = now + self._ttl_seconds
            return True


class RedisReplayGuard:
    """Atomic shared replay guard for multi-replica production deployments.

    Each nonce is SHA-256 hashed before storage and consumed with one atomic
    Redis SET using NX plus an expiry bounded to TrustKernel's maximum signed
    envelope lifetime. Backend failures propagate so callers can fail closed.
    """

    name = "redis"
    distributed = True

    def __init__(
        self,
        url: str,
        *,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        key_prefix: str = "trustkernel:replay",
        socket_timeout: float = 2.0,
    ) -> None:
        if not url.strip():
            raise ValueError("Redis replay guard requires TRUSTKERNEL_REDIS_URL")
        if ttl_seconds <= 0 or ttl_seconds > _DEFAULT_TTL_SECONDS:
            raise ValueError(f"ttl_seconds must be between 1 and {_DEFAULT_TTL_SECONDS}")
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - dependency gate covers this
            raise RuntimeError("redis package is required for RedisReplayGuard") from exc
        self._client = redis.Redis.from_url(
            url,
            decode_responses=False,
            socket_connect_timeout=socket_timeout,
            socket_timeout=socket_timeout,
            health_check_interval=30,
        )
        self._ttl_seconds = ttl_seconds
        self._prefix = key_prefix.strip(":") or "trustkernel:replay"

    def _key(self, nonce: str) -> str:
        return f"{self._prefix}:{_nonce_digest(nonce)}"

    def ping(self) -> bool:
        return bool(self._client.ping())

    def consume(self, nonce: str) -> bool:
        result = self._client.set(self._key(nonce), b"1", nx=True, ex=self._ttl_seconds)
        return bool(result)
