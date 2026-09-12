# ADR-007 — v1.4.1 production persistence

Status: Accepted; migration coordination hardened in v1.4.16.

## Context

TrustKernel's existing `SQLiteStore` is intentionally strong for offline hackathon demos: it is dependency-light, local, durable, and requires no external service. It is not the desired deployment topology for a horizontally scaled production control plane.

For v1.4.1 we add an opt-in PostgreSQL backend while preserving SQLite as the default. The PostgreSQL adapter keeps the existing storage-service contract so the authorization, audit, incident, policy, MCP, session, workload-identity, and telemetry services do not need a simultaneous rewrite.

## Decision

- `TRUSTKERNEL_DB_BACKEND=sqlite` (or unset) keeps the current offline-first store.
- `TRUSTKERNEL_DB_BACKEND=postgres` selects `PostgresStore` before application services are imported.
- PostgreSQL uses Psycopg 3 and a PostgreSQL URL supplied through `TRUSTKERNEL_DATABASE_URL`.
- Schema changes are represented as ordered checksum-pinned migrations recorded in `schema_migrations`.
- A previously applied migration whose checksum changes fails closed rather than silently mutating history.
- SQLite `?` parameter binding is translated to Psycopg `%s` binding only inside the PostgreSQL adapter.
- The small number of SQLite `INSERT OR REPLACE` statements are explicitly translated to PostgreSQL `INSERT ... ON CONFLICT DO UPDATE`; arbitrary SQL rewriting is intentionally avoided.
- PostgreSQL 18 is used by the dedicated Compose profile. SQLite remains the default Compose path for zero-setup demos.

## v1.4.16 migration-coordination hardening

A multi-replica startup path must not allow independent replicas to race on migration ownership. TrustKernel therefore acquires a deterministic PostgreSQL transaction-level advisory lock before reading or applying migration history.

- The lock key is derived from the stable namespace `trustkernel.schema.migrations`.
- `pg_advisory_xact_lock` scopes ownership to the current transaction, so PostgreSQL releases it automatically on commit or rollback.
- The wait is bounded by `TRUSTKERNEL_MIGRATION_LOCK_TIMEOUT_MS` (default 15 seconds, accepted range 1–120 seconds).
- The timeout is applied only while waiting for migration ownership and is reset to unlimited after the lock is acquired, so legitimate migrations are not accidentally capped at the lock-wait duration.
- Failure to acquire ownership fails startup closed instead of allowing uncoordinated schema changes.
- CI now starts a real PostgreSQL service and validates migration state plus representative workspace, agent, and approval CRUD through the production adapter.

## Security and reliability notes

Database credentials must be injected as deployment secrets; the development Compose password is not a production credential. Production deployments should use encrypted connections, database-level backups, least-privilege roles, and externally managed secret rotation.

The advisory lock protects application-owned migration coordination; it is not a replacement for deployment orchestration, backups, connection pooling, replica planning, or explicit database-role design. This milestone also does not claim that PostgreSQL alone makes TrustKernel highly available.

## Authoritative references

Originally reviewed on 2026-09-11, with migration-locking guidance rechecked on 2026-09-12:

- PostgreSQL current documentation: https://www.postgresql.org/docs/
- PostgreSQL explicit/advisory locking: https://www.postgresql.org/docs/16/explicit-locking.html
- PostgreSQL advisory-lock functions: https://www.postgresql.org/docs/current/functions-admin.html
- Psycopg 3 transaction guidance: https://www.psycopg.org/psycopg3/docs/basic/transactions.html
- Psycopg 3 installation guidance: https://www.psycopg.org/psycopg3/docs/basic/install.html
- SQLAlchemy 2.0 engine/dialect documentation was reviewed as an alternative abstraction reference: https://docs.sqlalchemy.org/en/20/core/engines.html and https://docs.sqlalchemy.org/en/20/dialects/postgresql.html

Psycopg 3 was selected for this compatibility milestone because TrustKernel already exposes a DB-API-shaped storage service and a thin adapter minimizes churn. A future repository-layer refactor may adopt SQLAlchemy Core once the storage contract is split by bounded context.
