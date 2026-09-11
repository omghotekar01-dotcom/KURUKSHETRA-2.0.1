# ADR-007 — v1.4.1 production persistence

Status: Accepted for `trustkernel-dev`; merge to `main` only after CI is green.

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

## Security and reliability notes

Database credentials must be injected as deployment secrets; the development Compose password is not a production credential. Production deployments should use encrypted connections, database-level backups, least-privilege roles, and externally managed secret rotation. Schema migrations should run as a controlled deployment step for multi-replica deployments rather than allowing every replica to race on migration ownership.

This milestone does not claim that PostgreSQL alone makes TrustKernel highly available. Connection pooling, backup/restore drills, replica topology, migration locking, and deployment orchestration remain production-operability concerns.

## Authoritative references checked on 2026-09-11

- PostgreSQL current documentation: https://www.postgresql.org/docs/
- Psycopg 3 project and installation guidance: https://www.psycopg.org/ and https://www.psycopg.org/psycopg3/docs/basic/install.html
- SQLAlchemy 2.0 engine/dialect documentation was reviewed as an alternative abstraction reference: https://docs.sqlalchemy.org/en/20/core/engines.html and https://docs.sqlalchemy.org/en/20/dialects/postgresql.html

Psycopg 3 was selected for this compatibility milestone because TrustKernel already exposes a DB-API-shaped storage service and a thin adapter minimizes churn. A future repository-layer refactor may adopt SQLAlchemy Core once the storage contract is split by bounded context.
