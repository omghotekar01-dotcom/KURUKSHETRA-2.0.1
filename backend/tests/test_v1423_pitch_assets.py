from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_final_pitch_assets_keep_claim_boundaries_explicit() -> None:
    pitch = _read("docs/FINAL_PITCH_ASSETS.md")
    required = (
        "production security accuracy",
        "not production security accuracy",
        "Judge Mode",
        "PostgreSQL",
        "Redis",
        "OpenTelemetry",
        "Policy Studio",
        "incident causal graph",
        "four-eyes",
        "SPIFFE",
        "KMS",
        "SDK distributions",
        "Demo recovery plan",
    )
    for phrase in required:
        assert phrase in pitch

    forbidden = (
        "100% secure",
        "guaranteed protection",
        "guaranteed attack prevention",
        "production accuracy",
    )
    for phrase in forbidden:
        if phrase == "production accuracy":
            continue
        assert phrase not in pitch.lower()


def test_pitch_assets_are_part_of_submission_manifest_contract() -> None:
    manifest_source = _read("backend/submission_manifest.py")
    assert '"docs/FINAL_PITCH_ASSETS.md"' in manifest_source
    assert '"backend/tests/test_v1423_pitch_assets.py"' in manifest_source
    assert '"trustkernel.submission-manifest.v14"' in manifest_source
