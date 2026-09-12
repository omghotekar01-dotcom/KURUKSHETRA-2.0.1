from __future__ import annotations

import os
import uuid

import pytest

from app.services.quotas import QuotaLimits, RedisQuotaBackend


REDIS_URL = os.getenv("TRUSTKERNEL_REDIS_TEST_URL")
pytestmark = pytest.mark.skipif(not REDIS_URL, reason="TRUSTKERNEL_REDIS_TEST_URL is not configured")


def test_redis_quota_is_shared_atomic_and_resettable():
    workspace_id = f"ci-{uuid.uuid4()}"
    first = RedisQuotaBackend(REDIS_URL)
    second = RedisQuotaBackend(REDIS_URL)
    limits = QuotaLimits(per_minute=2, per_day=5)

    try:
        assert first.ping()
        first.reset(workspace_id)

        one = first.check_and_consume(workspace_id, limits, 0)
        two = second.check_and_consume(workspace_id, limits, 0)
        blocked = first.check_and_consume(workspace_id, limits, 0)
        status = second.status(workspace_id, limits, 0)

        assert one["allowed"] is True
        assert two["allowed"] is True
        assert blocked == {
            "allowed": False,
            "reason": "minute_rate_limit",
            "minute_used": 2,
            "minute_limit": 2,
            "day_used": 2,
            "day_limit": 5,
        }
        assert status == {
            "minute_used": 2,
            "minute_limit": 2,
            "day_used": 2,
            "day_limit": 5,
        }

        events_key, sequence_key = first._keys(workspace_id)
        hash_tag = events_key.split("{", 1)[1].split("}", 1)[0]
        assert "{" + hash_tag + "}" in sequence_key

        second.reset(workspace_id)
        assert first.status(workspace_id, limits, 0)["day_used"] == 0
    finally:
        first.reset(workspace_id)
