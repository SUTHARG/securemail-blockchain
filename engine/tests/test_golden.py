"""Golden test suite: compares fresh engine execution outputs byte-for-byte against committed golden files (Prompt 5.8)."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"
GOLDEN_DIR = REPO_ROOT / "tests" / "golden"
TRUST_STORE_PATH = REPO_ROOT / "lab" / "ca" / "out" / "client_trust.crt"
ORG_SECRET_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

GOLDEN_SCENARIOS = [
    "S01a",
    "S01b",
    "S02",
    "S03",
    "S04",
    "S05",
    "S06",
    "S07",
    "S08",
    "S09",
    "S10",
    "S11",
    "S12",
    "S13",
    "X01",
    "X02",
    "X03",
]

COMPARED_FILES = [
    "sessions.json",
    "findings.json",
    "host_scores.json",
    "result.json",
]


@pytest.mark.parametrize("scenario", GOLDEN_SCENARIOS)
def test_golden_byte_for_byte(scenario: str, tmp_path: Path):
    """Verify fresh CLI analysis output equals committed golden output byte for byte."""
    pcap_path = CAPTURES_DIR / f"{scenario}.pcap"
    assert pcap_path.exists(), f"Capture file {pcap_path} not found"

    golden_scenario_dir = GOLDEN_DIR / scenario
    assert golden_scenario_dir.exists(), f"Golden directory for {scenario} not found"

    fresh_out_dir = tmp_path / f"fresh_{scenario}"

    cmd = [
        sys.executable,
        "-m",
        "smscope",
        "analyze",
        str(pcap_path),
        "--org-secret-hex",
        ORG_SECRET_HEX,
        "--out",
        str(fresh_out_dir),
        "--case-id",
        f"golden-{scenario}",
    ]
    if TRUST_STORE_PATH.exists():
        cmd.extend(["--trust-store", str(TRUST_STORE_PATH)])

    env = os.environ.copy()
    env["SMSCOPE_LEGACY_SESSIONS"] = "1"
    pythonpath = str(REPO_ROOT / "engine")
    if "PYTHONPATH" in env:
        env["PYTHONPATH"] = f"{pythonpath}{os.pathsep}{env['PYTHONPATH']}"
    else:
        env["PYTHONPATH"] = pythonpath

    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    assert res.returncode == 0, f"Analysis failed on {scenario}: {res.stderr}"

    for fname in COMPARED_FILES:
        golden_file = golden_scenario_dir / fname
        fresh_file = fresh_out_dir / fname

        assert golden_file.exists(), f"Committed golden file {golden_file} does not exist"
        assert fresh_file.exists(), f"Fresh output file {fresh_file} was not generated"

        golden_bytes = golden_file.read_bytes()
        fresh_bytes = fresh_file.read_bytes()

        golden_sha = hashlib.sha256(golden_bytes).hexdigest()
        fresh_sha = hashlib.sha256(fresh_bytes).hexdigest()

        assert fresh_sha == golden_sha, (
            f"Byte mismatch in {scenario}/{fname}!\n"
            f"Expected SHA-256: {golden_sha}\n"
            f"Actual SHA-256:   {fresh_sha}"
        )
        assert fresh_bytes == golden_bytes, f"Raw bytes mismatch in {scenario}/{fname}"
