from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict

from .mcp_governance import mcp_governance
from .policy_changes import policy_changes


def _canonical(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class GovernanceEvidenceService:
    """Portable signed evidence for privileged TrustKernel configuration changes.

    Evidence envelopes deliberately contain the complete normalized decision
    record plus a canonical SHA-256 digest and HMAC signature. They can be
    archived in a ticket/SIEM/GRC system without depending on TrustKernel's DB.
    """

    schema = "trustkernel.governance-evidence.v1"

    def __init__(self) -> None:
        self.key = os.getenv(
            "TRUSTKERNEL_EVIDENCE_SIGNING_KEY",
            os.getenv("TRUSTKERNEL_POLICY_SIGNING_KEY", "trustkernel-dev-policy-signing-key"),
        ).encode("utf-8")
        self.key_id = os.getenv("TRUSTKERNEL_EVIDENCE_KEY_ID", "local-hmac-sha256")

    def _envelope(self, *, evidence_type: str, workspace_id: str, subject_id: str, record: Dict[str, Any]) -> Dict[str, Any]:
        body = {
            "schema": self.schema,
            "evidence_type": evidence_type,
            "workspace_id": workspace_id,
            "subject_id": subject_id,
            "record": record,
        }
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        signature = hmac.new(self.key, digest.encode("ascii"), hashlib.sha256).hexdigest()
        return {
            **body,
            "sha256": digest,
            "signature": signature,
            "signature_algorithm": "HMAC-SHA256",
            "key_id": self.key_id,
            "exported_at": time.time(),
        }

    def policy_change(self, request_id: str) -> Dict[str, Any]:
        record = policy_changes.get(request_id)
        if not record:
            raise KeyError(request_id)
        return self._envelope(
            evidence_type="policy_change",
            workspace_id=record["workspace_id"],
            subject_id=request_id,
            record=record,
        )

    def mcp_change(self, request_id: str) -> Dict[str, Any]:
        record = mcp_governance.get(request_id)
        if not record:
            raise KeyError(request_id)
        return self._envelope(
            evidence_type="mcp_registry_change",
            workspace_id=record["workspace_id"],
            subject_id=request_id,
            record=record,
        )

    def verify(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        required = {"schema", "evidence_type", "workspace_id", "subject_id", "record", "sha256", "signature"}
        if not required.issubset(envelope):
            return {"valid": False, "reason": "missing_required_fields"}
        body = {
            "schema": envelope["schema"],
            "evidence_type": envelope["evidence_type"],
            "workspace_id": envelope["workspace_id"],
            "subject_id": envelope["subject_id"],
            "record": envelope["record"],
        }
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        hash_valid = hmac.compare_digest(digest, str(envelope.get("sha256", "")))
        expected = hmac.new(self.key, digest.encode("ascii"), hashlib.sha256).hexdigest()
        signature_valid = hmac.compare_digest(expected, str(envelope.get("signature", "")))
        return {
            "valid": hash_valid and signature_valid,
            "hash_valid": hash_valid,
            "signature_valid": signature_valid,
            "calculated_sha256": digest,
            "key_id": envelope.get("key_id"),
        }


governance_evidence = GovernanceEvidenceService()
