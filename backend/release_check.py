from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

import submission_manifest
import supply_chain_check

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_ASSETS = (
    "README.md",
    "VERSION",
    ".env.example",
    "start.bat",
    "start.sh",
    "docker-compose.production.yml",
    ".github/workflows/ci.yml",
    ".github/workflows/supply-chain.yml",
    "frontend/index.html",
    "backend/app/bootstrap.py",
    "backend/app/services/postgres_storage.py",
    "backend/tests/test_v1416_postgres_integration.py",
    "docs/adr/ADR-007-v141-production-persistence.md",
    "docs/JUDGE_RUNBOOK.md",
    "docs/JUDGE_CHEATSHEET.md",
    "docs/JUDGE_ARCHITECTURE.md",
    "docs/HACKATHON_PITCH.md",
    "docs/EVALUATION.md",
    "examples/sdk_guard_quickstart.py",
    "sdk/pyproject.toml",
    "backend/submission_manifest.py",
    "backend/supply_chain_check.py",
)

CLAIMS_DISCIPLINE_FRAGMENT = "not** production security accuracy"
REQUIRED_PRODUCTION_MARKERS = (
    'TRUSTKERNEL_ENV: production',
    'TRUSTKERNEL_REQUIRE_API_KEY: "1"',
    'TRUSTKERNEL_ALLOW_LEGACY_ACTOR_HEADER: "0"',
    'TRUSTKERNEL_REQUIRE_POLICY_APPROVAL: "1"',
    'TRUSTKERNEL_POLICY_FOUR_EYES: "1"',
    'TRUSTKERNEL_OIDC_REQUIRE_HTTPS: "1"',
    'TRUSTKERNEL_DB_BACKEND: postgres',
    'read_only: true',
    '- ALL',
    '- no-new-privileges:true',
)
REQUIRED_SECRET_GUARDS = (
    "TRUSTKERNEL_POSTGRES_PASSWORD:?set TRUSTKERNEL_POSTGRES_PASSWORD",
    "TRUSTKERNEL_SESSION_SIGNING_KEY:?set TRUSTKERNEL_SESSION_SIGNING_KEY",
    "TRUSTKERNEL_A2A_SIGNING_KEY:?set TRUSTKERNEL_A2A_SIGNING_KEY",
    "TRUSTKERNEL_POLICY_SIGNING_KEY:?set TRUSTKERNEL_POLICY_SIGNING_KEY",
    "TRUSTKERNEL_EVIDENCE_SIGNING_KEY:?set TRUSTKERNEL_EVIDENCE_SIGNING_KEY",
    "TRUSTKERNEL_OIDC_ISSUER:?set TRUSTKERNEL_OIDC_ISSUER",
    "TRUSTKERNEL_OIDC_AUDIENCE:?set TRUSTKERNEL_OIDC_AUDIENCE",
)
REQUIRED_ATTESTATION_MARKERS = (
    "id-token: write",
    "attestations: write",
    "python backend/submission_manifest.py > trustkernel-submission-manifest.json",
    "uses: actions/attest@v4",
    "subject-path: trustkernel-submission-manifest.json",
    "sbom-path: backend/trustkernel-sbom.cdx.json",
    "github.event_name == 'push' && github.ref == 'refs/heads/main'",
)
REQUIRED_POSTGRES_MIGRATION_MARKERS = (
    'MIGRATION_LOCK_NAMESPACE = "trustkernel.schema.migrations"',
    "TRUSTKERNEL_MIGRATION_LOCK_TIMEOUT_MS",
    "pg_advisory_xact_lock(?)",
    "schema_migrations",
    "database migration checksum drift",
)
REQUIRED_POSTGRES_CI_MARKERS = (
    "image: postgres:16",
    "pg_isready -U trustkernel -d trustkernel",
    "TRUSTKERNEL_POSTGRES_TEST_URL",
    "pytest -q tests/test_v1416_postgres_integration.py",
)


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def _sdk_version() -> str:
    with (ROOT / "sdk/pyproject.toml").open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def run() -> dict:
    checks: list[dict] = []

    missing = [path for path in REQUIRED_ASSETS if not (ROOT / path).is_file()]
    checks.append({
        "name": "required_submission_assets",
        "passed": not missing,
        "missing": missing,
    })

    version = _read("VERSION").strip() if (ROOT / "VERSION").is_file() else ""
    sdk_version = _sdk_version() if (ROOT / "sdk/pyproject.toml").is_file() else ""
    readme = _read("README.md") if (ROOT / "README.md").is_file() else ""
    readme_match = re.search(r"Startup MVP v(\d+\.\d+\.\d+)", readme)
    readme_version = readme_match.group(1) if readme_match else ""
    versions = {"VERSION": version, "sdk": sdk_version, "README": readme_version}
    checks.append({
        "name": "version_coherence",
        "passed": bool(version) and len(set(versions.values())) == 1,
        "versions": versions,
    })

    bootstrap = _read("backend/app/bootstrap.py") if (ROOT / "backend/app/bootstrap.py").is_file() else ""
    frontend = _read("frontend/index.html") if (ROOT / "frontend/index.html").is_file() else ""
    hardcoded_runtime_versions = re.findall(r'(?:main_module\.VERSION|app\.version)\s*=\s*["\']\d+\.\d+\.\d+["\']', bootstrap)
    hardcoded_ui_versions = re.findall(r"TRUSTKERNEL\s+v\d+\.\d+\.\d+", frontend, flags=re.IGNORECASE)
    runtime_binding_ok = all(marker in bootstrap for marker in (
        'ROOT / "VERSION"',
        "main_module.VERSION = VERSION",
        "app.version = VERSION",
        '@app.get("/api/version"',
    ))
    checks.append({
        "name": "runtime_version_binding",
        "passed": runtime_binding_ok and not hardcoded_runtime_versions and not hardcoded_ui_versions,
        "hardcoded_runtime_versions": hardcoded_runtime_versions,
        "hardcoded_ui_versions": hardcoded_ui_versions,
        "detail": "Runtime release metadata is bound to the canonical VERSION file and the judge UI contains no independent release literal.",
    })

    claims_ok = CLAIMS_DISCIPLINE_FRAGMENT in readme
    checks.append({
        "name": "claims_discipline",
        "passed": claims_ok,
        "detail": "README explicitly distinguishes regression/evaluation evidence from production security accuracy.",
    })

    compose = _read("docker-compose.production.yml") if (ROOT / "docker-compose.production.yml").is_file() else ""
    missing_markers = [marker for marker in REQUIRED_PRODUCTION_MARKERS if marker not in compose]
    missing_secret_guards = [marker for marker in REQUIRED_SECRET_GUARDS if marker not in compose]
    checks.append({
        "name": "production_compose_posture",
        "passed": not missing_markers and not missing_secret_guards,
        "missing_markers": missing_markers,
        "missing_secret_guards": missing_secret_guards,
    })

    postgres_storage = _read("backend/app/services/postgres_storage.py") if (ROOT / "backend/app/services/postgres_storage.py").is_file() else ""
    ci_workflow = _read(".github/workflows/ci.yml") if (ROOT / ".github/workflows/ci.yml").is_file() else ""
    missing_migration_markers = [marker for marker in REQUIRED_POSTGRES_MIGRATION_MARKERS if marker not in postgres_storage]
    missing_postgres_ci_markers = [marker for marker in REQUIRED_POSTGRES_CI_MARKERS if marker not in ci_workflow]
    checks.append({
        "name": "postgres_migration_coordination",
        "passed": not missing_migration_markers and not missing_postgres_ci_markers,
        "missing_migration_markers": missing_migration_markers,
        "missing_ci_markers": missing_postgres_ci_markers,
        "detail": "Production PostgreSQL migrations remain checksum-pinned, transaction-lock coordinated with a bounded wait, and exercised against a live PostgreSQL service in CI.",
    })

    supply_chain = supply_chain_check.run()
    checks.append({
        "name": "supply_chain_declarations",
        "passed": supply_chain["passed"],
        "requirements_sha256": supply_chain["sha256"],
        "direct_component_count": supply_chain["direct_component_count"],
        "violations": supply_chain["violations"],
    })

    workflow = _read(".github/workflows/supply-chain.yml") if (ROOT / ".github/workflows/supply-chain.yml").is_file() else ""
    missing_attestation_markers = [marker for marker in REQUIRED_ATTESTATION_MARKERS if marker not in workflow]
    checks.append({
        "name": "artifact_attestation_workflow",
        "passed": not missing_attestation_markers,
        "missing_markers": missing_attestation_markers,
        "detail": "Main-branch supply-chain evidence is configured for GitHub OIDC-backed artifact provenance and SBOM attestation. This verifies origin/integrity when consumers validate the attestation; it does not certify that the software is secure.",
    })

    manifest = submission_manifest.build_manifest()
    checks.append({
        "name": "submission_manifest",
        "passed": manifest["complete"] and manifest["version"] == version,
        "asset_count": len(manifest["assets"]),
        "missing": manifest["missing"],
        "algorithm": manifest["algorithm"],
    })

    passed = all(check["passed"] for check in checks)
    return {
        "schema": "trustkernel.release-check.v6",
        "version": version or None,
        "passed": passed,
        "status": "release-ready" if passed else "blocked",
        "checks": checks,
        "evidence_note": "This gate checks release consistency, canonical runtime version binding, PostgreSQL migration-coordination declarations and live-database CI coverage, dependency declaration hygiene, configured artifact-attestation posture and submission integrity; known-vulnerability scanning and GitHub's cryptographic attestation issuance/verification are separate CI/platform controls, and none of these checks is a security certification.",
    }


def main() -> int:
    result = run()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
