from __future__ import annotations

import json
import os

from app.services.deployment_readiness import assess_production_readiness


def main() -> int:
    report = assess_production_readiness(os.environ)
    print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    return 0 if report.ready else 1


if __name__ == "__main__":
    raise SystemExit(main())
