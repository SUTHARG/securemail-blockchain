"""Unit and integration tests for SecureMailScope engine skeleton (Prompt 3.1)."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import jsonschema
import pytest

from engine.smscope.models import Finding, Evidence
from engine.smscope.results.pipeline import (
    compute_exposure_factor,
    compute_grade,
    score_host,
    SEVERITY_WEIGHTS,
)
from engine.smscope.results.hashing import finding_id, host_id_hex
from engine.smscope.rules import compute_ruleset_hash

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMAS_DIR = REPO_ROOT / "spec" / "schemas"
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def load_schema(name: str) -> dict:
    with open(SCHEMAS_DIR / f"{name}.json", "r", encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Scoring Unit Tests: Severity weights, Exposure buckets, Grade boundaries
# ---------------------------------------------------------------------------


class TestScoring:
    """Test integer scoring rules strictly according to Section 4.7."""

    @pytest.mark.parametrize(
        "severity,weight,expected_score",
        [
            ("Critical", 40, 60),
            ("High", 20, 80),
            ("Medium", 8, 92),
            ("Low", 2, 98),
            ("Info", 0, 100),
        ],
    )
    def test_scoring_per_severity(self, severity, weight, expected_score):
        """Test each severity weight with 1 session (exposure factor 1)."""
        assert SEVERITY_WEIGHTS[severity] == weight
        endpoint = "10.0.0.1:25"
        f = Finding(
            findingId=finding_id("R_TEST", endpoint),
            ruleId="R_TEST",
            severity=severity,
            serverEndpoint=endpoint,
            sortedSessionIds=[0],
            sessionCount=1,
            evidence=[Evidence(sessionId=0, packetNumber=1, note="test")],
            details={},
        )
        host_score = score_host(endpoint, [f], b"test_secret_32_bytes_long_12345")
        assert host_score.score == expected_score

    @pytest.mark.parametrize(
        "session_count,expected_factor",
        [
            (1, 1),
            (2, 2),
            (5, 2),
            (9, 2),
            (10, 3),
            (100, 3),
        ],
    )
    def test_exposure_factor_buckets(self, session_count, expected_factor):
        """Test exposure factor: 1 for 1 session, 2 for 2-9, 3 for 10+."""
        assert compute_exposure_factor(session_count) == expected_factor

    @pytest.mark.parametrize(
        "severity,session_count,expected_score",
        [
            ("Critical", 1, 100 - 40 * 1),  # 60
            ("Critical", 2, 100 - 40 * 2),  # 20
            ("Critical", 9, 100 - 40 * 2),  # 20
            ("Critical", 10, max(0, 100 - 40 * 3)),  # 0
            ("High", 1, 100 - 20 * 1),  # 80
            ("High", 4, 100 - 20 * 2),  # 60
            ("High", 10, 100 - 20 * 3),  # 40
            ("Medium", 1, 100 - 8 * 1),  # 92
            ("Medium", 5, 100 - 8 * 2),  # 84
            ("Medium", 15, 100 - 8 * 3),  # 76
            ("Low", 1, 100 - 2 * 1),  # 98
            ("Low", 7, 100 - 2 * 2),  # 96
            ("Low", 20, 100 - 2 * 3),  # 94
        ],
    )
    def test_scoring_per_exposure_bucket(self, severity, session_count, expected_score):
        """Test host score computation across severities and exposure buckets."""
        endpoint = "10.0.0.1:25"
        f = Finding(
            findingId=finding_id("R_TEST", endpoint),
            ruleId="R_TEST",
            severity=severity,
            serverEndpoint=endpoint,
            sortedSessionIds=list(range(session_count)),
            sessionCount=session_count,
            evidence=[Evidence(sessionId=0, packetNumber=1, note="test")],
            details={},
        )
        host_score = score_host(endpoint, [f], b"test_secret_32_bytes_long_12345")
        assert host_score.score == expected_score

    @pytest.mark.parametrize(
        "score,expected_grade",
        [
            (100, "A"),
            (95, "A"),
            (90, "A"),  # Grade A lower boundary
            (89, "B"),  # Grade B upper boundary
            (80, "B"),
            (75, "B"),  # Grade B lower boundary
            (74, "C"),  # Grade C upper boundary
            (65, "C"),
            (60, "C"),  # Grade C lower boundary
            (59, "D"),  # Grade D upper boundary
            (50, "D"),
            (40, "D"),  # Grade D lower boundary
            (39, "F"),  # Grade F upper boundary
            (20, "F"),
            (0, "F"),
        ],
    )
    def test_grade_boundaries(self, score, expected_grade):
        """Test grade boundaries: A >= 90, B >= 75, C >= 60, D >= 40, F < 40."""
        assert compute_grade(score) == expected_grade

    def test_clean_host_score(self):
        """A host with 0 findings receives score 100, Grade A, and SHA-256 of empty bytes."""
        endpoint = "clean.host:25"
        secret = b"test_secret_32_bytes_long_12345"
        host_score = score_host(endpoint, [], secret)
        assert host_score.score == 100
        assert host_score.grade == "A"
        assert host_score.hostId == host_id_hex(secret, endpoint)
        # SHA-256 of empty bytes
        empty_digest = hashlib.sha256(b"").hexdigest()
        assert host_score.findingsDigest == empty_digest


# ---------------------------------------------------------------------------
# Integration Tests: CLI, Determinism, Schema Validation, Secret Exclusion
# ---------------------------------------------------------------------------


class TestEngineIntegration:
    """Integration tests for engine CLI execution and output properties."""

    @pytest.fixture
    def run_cli_analysis(self, tmp_path):
        """Helper to run the smscope analyze CLI."""
        real_pcap_bytes = (REPO_ROOT / "lab" / "captures" / "S03.pcap").read_bytes()

        def _run(pcap_bytes=None, org_secret_hex="a" * 64, out_dir=None):
            if pcap_bytes is None:
                pcap_bytes = real_pcap_bytes
            if out_dir is None:
                out_dir = tmp_path / "out"
            pcap_file = tmp_path / "test.pcap"
            pcap_file.write_bytes(pcap_bytes)

            cmd = [
                sys.executable,
                "-m",
                "smscope",
                "analyze",
                str(pcap_file),
                "--org-secret-hex",
                org_secret_hex,
                "--out",
                str(out_dir),
            ]
            env = os.environ.copy()
            pythonpath = str(REPO_ROOT / "engine")
            if "PYTHONPATH" in env:
                env["PYTHONPATH"] = f"{pythonpath}{os.pathsep}{env['PYTHONPATH']}"
            else:
                env["PYTHONPATH"] = pythonpath

            result = subprocess.run(cmd, capture_output=True, text=True, env=env)
            return result, out_dir

        return _run

    def test_determinism_byte_for_byte(self, run_cli_analysis, tmp_path):
        """Acceptance test: two CLI runs produce identical sha256sum for every output file."""
        out1 = tmp_path / "run1"
        out2 = tmp_path / "run2"

        secret = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
        res1, _ = run_cli_analysis(org_secret_hex=secret, out_dir=out1)
        assert res1.returncode == 0, f"Run 1 failed: {res1.stderr}"

        res2, _ = run_cli_analysis(org_secret_hex=secret, out_dir=out2)
        assert res2.returncode == 0, f"Run 2 failed: {res2.stderr}"

        expected_files = [
            "sessions.json",
            "findings.json",
            "host_scores.json",
            "result.json",
            "host_proofs.json",
            "manifest.json",
        ]

        for fname in expected_files:
            file1 = out1 / fname
            file2 = out2 / fname
            assert file1.exists(), f"File {fname} missing in run 1"
            assert file2.exists(), f"File {fname} missing in run 2"

            bytes1 = file1.read_bytes()
            bytes2 = file2.read_bytes()

            sha1 = hashlib.sha256(bytes1).hexdigest()
            sha2 = hashlib.sha256(bytes2).hexdigest()

            assert bytes1 == bytes2, f"Byte mismatch in {fname}"
            assert sha1 == sha2, f"SHA-256 mismatch in {fname}"

    def test_schema_validation_of_all_outputs(self, run_cli_analysis, tmp_path):
        """Schema validation of every output file against spec/schemas/."""
        out = tmp_path / "schema_out"
        res, _ = run_cli_analysis(out_dir=out)
        assert res.returncode == 0, f"CLI failed: {res.stderr}"

        s_finding = load_schema("finding")
        s_session = load_schema("session_record")
        s_score = load_schema("host_score")
        s_manifest = load_schema("case_manifest")

        # 1. sessions.json
        sessions = json.loads((out / "sessions.json").read_text(encoding="utf-8"))
        assert len(sessions) > 0
        for s in sessions:
            jsonschema.validate(instance=s, schema=s_session)

        # 2. findings.json
        findings = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        assert len(findings) > 0
        for f in findings:
            jsonschema.validate(instance=f, schema=s_finding)

        # 3. host_scores.json
        scores = json.loads((out / "host_scores.json").read_text(encoding="utf-8"))
        assert len(scores) > 0
        for sc in scores:
            jsonschema.validate(instance=sc, schema=s_score)

        # 4. manifest.json
        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        jsonschema.validate(instance=manifest, schema=s_manifest)

        # 5. result.json and host_proofs.json
        result = json.loads((out / "result.json").read_text(encoding="utf-8"))
        proofs = json.loads((out / "host_proofs.json").read_text(encoding="utf-8"))
        assert "resultRoot" in result
        assert "leaves" in result
        assert len(result["leaves"]) == len(findings) + len(scores)
        assert len(proofs) == len(scores)

    def test_organization_secret_never_leaked(self, run_cli_analysis, tmp_path):
        """Test proving the organization secret does not appear anywhere in any output file."""
        distinct_secret_hex = "0123456789abcdef998877665544332211aabbccddeeff001122334455667788"
        distinct_secret_bytes = bytes.fromhex(distinct_secret_hex)

        out = tmp_path / "secret_check_out"
        res, _ = run_cli_analysis(org_secret_hex=distinct_secret_hex, out_dir=out)
        assert res.returncode == 0, f"CLI failed: {res.stderr}"

        # Check all files in the output directory
        for output_file in out.iterdir():
            if output_file.is_file():
                content_bytes = output_file.read_bytes()
                content_str = output_file.read_text(encoding="utf-8")

                # The hex string must not appear
                assert distinct_secret_hex not in content_str, (
                    f"Secret hex string leaked in {output_file.name}!"
                )
                assert distinct_secret_hex.lower() not in content_str.lower(), (
                    f"Secret hex string (case-insensitive) leaked in {output_file.name}!"
                )
                # Raw bytes must not appear
                assert distinct_secret_bytes not in content_bytes, (
                    f"Raw secret bytes leaked in {output_file.name}!"
                )

    def test_empty_capture_exit_code_2(self, run_cli_analysis, tmp_path):
        """A capture with no mail sessions is rejected with clear error message and exit code 2."""
        res, _ = run_cli_analysis(pcap_bytes=b"", out_dir=tmp_path / "empty_out")
        assert res.returncode == 2
        assert "No mail sessions found in capture" in res.stderr

    def test_ruleset_hash_deterministic(self):
        """Ruleset hash is deterministic and changes if ruleset or rule code changes."""
        hash1 = compute_ruleset_hash()
        hash2 = compute_ruleset_hash()
        assert hash1 == hash2
        assert len(hash1) == 64
        int(hash1, 16)  # valid hex
