from __future__ import annotations

import json
import sys

from app.services.storage import store
from app.v13_api import judge_demo_v13


def run() -> dict:
    checks: dict[str, object] = {}

    checks["database"] = bool(store.ping())

    judge = judge_demo_v13()
    sequence = judge.get("sequence", [])
    audit_chain = judge.get("audit_chain", {})

    checks["judge_mode"] = judge.get("mode") == "TRUSTKERNEL_V1_3_JUDGE_DEMO"
    checks["six_scenarios"] = len(sequence) == 6
    checks["audit_chain"] = audit_chain.get("valid") is True

    passed = all(bool(value) for value in checks.values())
    return {
        "status": "ready" if passed else "failed",
        "passed": passed,
        "checks": checks,
        "note": "Judge Mode and bundled benchmark evidence are deterministic regression/demo evidence, not production security accuracy.",
    }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2, sort_keys=True))
    sys.exit(0 if result["passed"] else 1)
