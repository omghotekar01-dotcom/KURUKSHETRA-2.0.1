from __future__ import annotations

import os
import uuid

import pytest

from app.services.postgres_storage import MIGRATIONS, PostgresStore


pytestmark = pytest.mark.skipif(
    not os.getenv("TRUSTKERNEL_POSTGRES_TEST_URL"),
    reason="live PostgreSQL integration URL not configured",
)


def test_live_postgres_migrations_and_core_crud(monkeypatch: pytest.MonkeyPatch) -> None:
    dsn = os.environ["TRUSTKERNEL_POSTGRES_TEST_URL"]
    monkeypatch.setenv("TRUSTKERNEL_DATABASE_URL", dsn)
    monkeypatch.setenv("TRUSTKERNEL_MIGRATION_LOCK_TIMEOUT_MS", "10000")

    store = PostgresStore()
    assert store.ping() is True

    applied = store.migration_status()
    assert [row["version"] for row in applied] == [migration.version for migration in MIGRATIONS]
    assert [row["checksum"] for row in applied] == [migration.checksum for migration in MIGRATIONS]

    suffix = uuid.uuid4().hex
    workspace_id = f"ws-ci-{suffix}"
    workspace_name = f"CI Workspace {suffix[:8]}"
    store.create_workspace(workspace_id, workspace_name, f"key-{suffix}", 1.0)
    assert store.workspace(workspace_id) == {
        "id": workspace_id,
        "name": workspace_name,
        "created_at": 1.0,
    }

    agent_id = f"agent-ci-{suffix}"
    agent = {"id": agent_id, "workspace_id": workspace_id, "status": "active"}
    store.upsert_agent(agent_id, agent)
    assert store.get_agent(agent_id) == agent

    approval_id = f"audit-ci-{suffix}"
    store.create_approval(
        {
            "audit_id": approval_id,
            "status": "pending",
            "created_at": 2.0,
            "resolved_at": None,
            "resolution": None,
            "payload": {"workspace_id": workspace_id, "reason": "integration-test"},
        }
    )
    approval = store.get_approval(approval_id)
    assert approval is not None
    assert approval["status"] == "pending"
    assert approval["payload"]["workspace_id"] == workspace_id


def test_two_postgres_store_bootstraps_converge_on_same_migration_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dsn = os.environ["TRUSTKERNEL_POSTGRES_TEST_URL"]
    monkeypatch.setenv("TRUSTKERNEL_DATABASE_URL", dsn)

    first = PostgresStore()
    second = PostgresStore()

    assert first.migration_status() == second.migration_status()
    assert len(second.migration_status()) == len(MIGRATIONS)
