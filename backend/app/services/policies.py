from __future__ import annotations
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional
import hashlib
import hmac
import json
import os
import time
import uuid
import yaml
from .storage import store

POLICY_DIR = Path(__file__).resolve().parents[2] / "policies"
REQUIRED_SECTIONS = {"identity", "egress", "payments", "database", "github", "memory", "inter_agent", "workflow", "risk", "provenance", "mcp"}


def _safe_profile(profile: str) -> str:
    return "".join(ch for ch in profile if ch.isalnum() or ch in {"-", "_"})


def _policy_path(profile: str) -> Path:
    safe = _safe_profile(profile)
    path = POLICY_DIR / f"{safe}.yaml"
    if not path.exists():
        path = POLICY_DIR / "enterprise-default.yaml"
    return path


@lru_cache(maxsize=32)
def _load_file_policy(profile: str) -> Dict[str, Any]:
    path = _policy_path(profile)
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    data.setdefault("name", _safe_profile(profile) or "enterprise-default")
    return data


def _canonical(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _sha(data: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(data)).hexdigest()


def _sign(profile: str, version: int, sha256: str) -> str:
    key = os.getenv("TRUSTKERNEL_POLICY_SIGNING_KEY", "trustkernel-dev-policy-signing-key").encode("utf-8")
    payload = f"{profile}|{version}|{sha256}".encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def validate_policy_document(data: Dict[str, Any]) -> Dict[str, Any]:
    missing = sorted(REQUIRED_SECTIONS - set(data))
    errors: List[str] = []
    warnings: List[str] = []
    version = data.get("version")
    if not isinstance(version, int) or version < 1:
        errors.append("version must be a positive integer")
    if missing:
        errors.append(f"missing required sections: {', '.join(missing)}")
    if data.get("risk", {}).get("approval_threshold", 70) >= data.get("risk", {}).get("block_threshold", 90):
        errors.append("approval_threshold must be lower than block_threshold")
    if not data.get("identity", {}).get("require_registered_agent", False):
        warnings.append("registered agent identity is not required")
    if not data.get("mcp", {}).get("require_verified_provenance", False):
        warnings.append("MCP tool provenance verification is disabled")
    if not data.get("inter_agent", {}).get("require_valid_signature", False):
        warnings.append("inter-agent signatures are not required")
    return {"valid": not errors, "errors": errors, "warnings": warnings}


def publish_policy_document(profile: str, data: Dict[str, Any], *, created_by: str = "system", source: str = "api") -> Dict[str, Any]:
    profile = _safe_profile(profile) or "enterprise-default"
    doc = json.loads(json.dumps(data))
    doc["name"] = profile
    validation = validate_policy_document(doc)
    if not validation["valid"]:
        raise ValueError("; ".join(validation["errors"]))
    sha256 = _sha(doc)
    version = int(doc["version"])
    existing = next((b for b in store.policy_bundles(profile) if b["version"] == version and b["sha256"] == sha256), None)
    if existing:
        return {**existing, "validation": validation, "signature_valid": verify_policy_bundle(existing)}
    item = {
        "id": f"pol_{uuid.uuid4().hex[:12]}",
        "profile": profile,
        "version": version,
        "sha256": sha256,
        "signature": _sign(profile, version, sha256),
        "policy": doc,
        "source": source,
        "created_by": created_by,
        "created_at": time.time(),
    }
    store.create_policy_bundle(item)
    return {**item, "validation": validation, "signature_valid": True}


def publish_policy_bundle(profile: str, *, created_by: str = "system") -> Dict[str, Any]:
    return publish_policy_document(profile, _load_file_policy(profile), created_by=created_by, source=_policy_path(profile).name)


def verify_policy_bundle(bundle: Dict[str, Any]) -> bool:
    policy = bundle.get("policy") or {}
    actual_sha = _sha(policy)
    if actual_sha != bundle.get("sha256"):
        return False
    expected = _sign(bundle.get("profile", ""), int(bundle.get("version", 0)), actual_sha)
    return hmac.compare_digest(expected, bundle.get("signature", ""))


def list_policy_bundles(profile: Optional[str] = None) -> List[Dict[str, Any]]:
    return [{**b, "signature_valid": verify_policy_bundle(b), "policy": b["policy"]} for b in store.policy_bundles(profile)]


def activate_policy_bundle(workspace_id: str, profile: str, bundle_id: str, *, activated_by: str = "system") -> Dict[str, Any]:
    bundle = store.policy_bundle(bundle_id)
    if not bundle or bundle["profile"] != profile:
        raise KeyError(bundle_id)
    if not verify_policy_bundle(bundle):
        raise ValueError("Policy bundle signature verification failed")
    validation = validate_policy_document(bundle["policy"])
    if not validation["valid"]:
        raise ValueError("Policy bundle is invalid")
    store.bind_policy_bundle(workspace_id, profile, bundle_id, activated_by, time.time())
    return active_policy_bundle(workspace_id, profile) or {}


def active_policy_bundle(workspace_id: str, profile: str) -> Optional[Dict[str, Any]]:
    binding = store.policy_binding(workspace_id, profile)
    if not binding:
        return None
    bundle = store.policy_bundle(binding["bundle_id"])
    if not bundle:
        return None
    return {**bundle, "binding": binding, "signature_valid": verify_policy_bundle(bundle)}


def load_policy(profile: str, workspace_id: Optional[str] = None) -> Dict[str, Any]:
    if workspace_id:
        bundle = active_policy_bundle(workspace_id, profile)
        if bundle and bundle.get("signature_valid"):
            return bundle["policy"]
    return _load_file_policy(profile)


def validate_policy(profile: str, workspace_id: Optional[str] = None) -> Dict[str, Any]:
    return validate_policy_document(load_policy(profile, workspace_id))


def policy_metadata(profile: str, workspace_id: Optional[str] = None) -> Dict[str, Any]:
    data = load_policy(profile, workspace_id)
    validation = validate_policy_document(data)
    active = active_policy_bundle(workspace_id, profile) if workspace_id else None
    return {
        "name": data.get("name", profile),
        "version": data.get("version"),
        "sha256": _sha(data),
        "path": _policy_path(profile).name if not active else None,
        "bundle_id": active["id"] if active else None,
        "signature": active["signature"] if active else None,
        "signature_valid": active["signature_valid"] if active else None,
        "validation": validation,
        "source": "workspace_bundle" if active else "filesystem",
    }


def list_policies() -> List[Dict[str, Any]]:
    result = []
    for path in sorted(POLICY_DIR.glob("*.yaml")):
        result.append(policy_metadata(path.stem))
    return result
