from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "backend" / "requirements.txt"
PINNED_REQUIREMENT = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^\s;]+(?:\s*;\s*.+)?$")
DISALLOWED_PREFIXES = ("-e ", "--editable ", "git+", "hg+", "svn+", "bzr+", "file:", "http://", "https://", "../", "./", "/")


def _meaningful_lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def run(requirements_path: Path = REQUIREMENTS) -> dict:
    text = requirements_path.read_text(encoding="utf-8")
    lines = _meaningful_lines(text)
    violations: list[dict[str, str]] = []
    components: list[str] = []

    for line in lines:
        lowered = line.lower()
        if lowered.startswith(DISALLOWED_PREFIXES) or " @ " in line:
            violations.append({"requirement": line, "reason": "remote/local/VCS requirement is not allowed"})
            continue
        if not PINNED_REQUIREMENT.fullmatch(line):
            violations.append({"requirement": line, "reason": "direct dependency must use an exact == pin"})
            continue
        components.append(line.split(";", 1)[0].strip())

    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    passed = bool(lines) and not violations
    return {
        "schema": "trustkernel.supply-chain-check.v1",
        "passed": passed,
        "status": "pinned" if passed else "blocked",
        "requirements": str(requirements_path.relative_to(ROOT)).replace("\\", "/") if requirements_path.is_relative_to(ROOT) else str(requirements_path),
        "sha256": digest,
        "direct_component_count": len(components),
        "direct_components": sorted(components, key=str.lower),
        "violations": violations,
        "evidence_note": "This offline gate validates dependency declaration hygiene only. Known-vulnerability scanning is performed separately in CI with pip-audit.",
    }


def main() -> int:
    result = run()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
