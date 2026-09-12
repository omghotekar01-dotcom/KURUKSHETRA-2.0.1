from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from benchmark import run as run_benchmark
from diagnostics import run as run_diagnostics
from judge_check import run as run_judge_check

ROOT = Path(__file__).resolve().parent


def _run_tests() -> dict:
    started = time.perf_counter()
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return {
        "passed": proc.returncode == 0,
        "returncode": proc.returncode,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "summary": (proc.stdout or proc.stderr).strip().splitlines()[-1] if (proc.stdout or proc.stderr).strip() else "no pytest output",
    }


def _benchmark_gate(iterations: int) -> dict:
    result = run_benchmark(iterations=iterations)
    passed = (
        result.get("overall_expected_outcome_rate") == 1.0
        and result.get("owasp_agentic_top10_coverage") is True
        and int(result.get("scenario_count", 0)) > 0
    )
    return {
        "passed": passed,
        "scenario_count": result.get("scenario_count"),
        "evaluations": result.get("evaluations"),
        "overall_expected_outcome_rate": result.get("overall_expected_outcome_rate"),
        "owasp_agentic_top10_coverage": result.get("owasp_agentic_top10_coverage"),
        "latency_ms": result.get("latency_ms"),
        "warning": result.get("warning"),
    }


def run(*, iterations: int = 3, include_tests: bool = True) -> dict:
    started = time.perf_counter()
    diagnostics = run_diagnostics()
    tests = _run_tests() if include_tests else {"passed": True, "skipped": True}
    benchmark = _benchmark_gate(iterations)
    judge = run_judge_check()

    gates = {
        "diagnostics": bool(diagnostics.get("passed")),
        "tests": bool(tests.get("passed")),
        "benchmark_regression": bool(benchmark.get("passed")),
        "judge_mode": bool(judge.get("passed")),
    }
    passed = all(gates.values())

    return {
        "schema": "trustkernel.rehearsal.v1",
        "status": "ready" if passed else "failed",
        "passed": passed,
        "gates": gates,
        "diagnostics": diagnostics,
        "tests": tests,
        "benchmark": benchmark,
        "judge": judge,
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        "next_step": "Run start.bat (Windows) or ./start.sh (macOS/Linux) only after this rehearsal is green.",
        "evidence_note": "Judge Mode and bundled synthetic benchmark outputs are deterministic regression/demo evidence, not production security accuracy or certification.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run TrustKernel's judge-laptop rehearsal gates.")
    parser.add_argument("--iterations", type=int, default=3, help="Benchmark iterations per scenario (default: 3).")
    parser.add_argument("--skip-tests", action="store_true", help="Skip pytest for a faster local smoke rehearsal.")
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be at least 1")

    result = run(iterations=args.iterations, include_tests=not args.skip_tests)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
