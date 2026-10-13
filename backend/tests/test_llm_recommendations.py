"""Tests for Advisory LLM Recommendations (Tier 3 / Prompt T3.2).

Verifies:
1. A hallucinated findingId is rejected.
2. A snippet with an unknown parameter is replaced by the rule's static template.
3. Missing required fields are replaced by static template.
4. The fake provider path works cleanly.
5. The consensus result root is unchanged when the generator runs.
6. Acceptance: the report shows labeled generated recommendations and the verifier still passes.
"""
import json
from pathlib import Path
import pytest

from backend.reports.builder import build_case_report, load_recommendations
from backend.reports.llm_advisor import (
    FakeLLMProvider,
    build_allowed_parameters_set,
    generate_advisory_recommendations,
    validate_and_filter_recommendations,
)
from engine.smscope.results.canonical import canonical_json
from engine.smscope.results.hashing import finding_leaf, host_score_leaf
from engine.smscope.results.merkle import MerkleTree


REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"


SAMPLE_FINDINGS = [
    {
        "findingId": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "ruleId": "R01",
        "severity": "Critical",
        "serverEndpoint": "192.0.2.10:25",
        "sessionCount": 3,
        "sortedSessionIds": [1, 2, 3],
        "evidence": [{"sessionId": 1, "packetNumber": 10, "note": "AUTH before TLS"}],
        "details": {"protocol": "SMTP"},
    },
    {
        "findingId": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "ruleId": "R06",
        "severity": "High",
        "serverEndpoint": "192.0.2.20:25",
        "sessionCount": 2,
        "sortedSessionIds": [4, 5],
        "evidence": [{"sessionId": 4, "packetNumber": 12, "note": "TLS 1.0 negotiated"}],
        "details": {"protocol": "SMTP", "version": "TLS 1.0"},
    },
]

SAMPLE_HOST_SCORES = [
    {
        "hostId": "11" * 32,
        "serverEndpoint": "192.0.2.10:25",
        "score": 40,
        "grade": "F",
        "findingsDigest": "aa" * 32,
    },
    {
        "hostId": "22" * 32,
        "serverEndpoint": "192.0.2.20:25",
        "score": 60,
        "grade": "D",
        "findingsDigest": "bb" * 32,
    },
]


def test_allowed_parameters_set_built_correctly():
    """Verifies allow-list extraction from recommendations.yaml."""
    allowed = build_allowed_parameters_set()
    assert len(allowed) > 0
    # Vetted Postfix / Dovecot parameters must be included
    assert "smtpd_tls_auth_only" in allowed
    assert "disable_plaintext_auth" in allowed
    assert "smtpd_tls_security_level" in allowed
    assert "smtpd_tls_mandatory_protocols" in allowed
    # Malicious or hallucinated parameters must not be present
    assert "malicious_unvetted_param" not in allowed
    assert "allow_any_plaintext" not in allowed


def test_hallucinated_finding_id_rejected():
    """Verifies that an LLM recommendation with a hallucinated findingId is completely rejected."""
    fake_provider = FakeLLMProvider(hallucinate_finding_id=True)
    raw_output = fake_provider.generate(SAMPLE_FINDINGS)

    # Validate output
    validated = validate_and_filter_recommendations(
        raw_output_text=raw_output,
        findings=SAMPLE_FINDINGS,
    )

    validated_ids = [item["findingId"] for item in validated]
    # Hallucinated ID must NOT exist in the validated output
    assert "hallucinated_finding_id_00000000000000000000000000000000" not in validated_ids
    # Exactly the valid findings must remain
    assert set(validated_ids) == {f["findingId"] for f in SAMPLE_FINDINGS}


def test_snippet_with_unknown_parameter_replaced_by_static_template():
    """Verifies that configuration snippets with unknown parameters are replaced by static template."""
    fake_provider = FakeLLMProvider(inject_unknown_parameter=True)
    raw_output = fake_provider.generate(SAMPLE_FINDINGS)

    validated = validate_and_filter_recommendations(
        raw_output_text=raw_output,
        findings=SAMPLE_FINDINGS,
    )

    for item in validated:
        # Unknown parameter must cause fallback to static template
        assert item["source"] == "static_template_fallback"
        assert item["isAdvisory"] is True
        # Malicious parameter text must not appear in any step
        all_steps = " ".join(item["steps"])
        assert "malicious_unvetted_param" not in all_steps


def test_missing_required_fields_replaced():
    """Verifies that an LLM output missing required fields (summary, steps) is replaced by static template."""
    fake_provider = FakeLLMProvider(omit_required_field=True)
    raw_output = fake_provider.generate(SAMPLE_FINDINGS)

    validated = validate_and_filter_recommendations(
        raw_output_text=raw_output,
        findings=SAMPLE_FINDINGS,
    )

    for item in validated:
        assert item["source"] == "static_template_fallback"
        assert "steps" in item and len(item["steps"]) > 0


def test_fake_provider_path_works():
    """Verifies clean execution of fake provider and valid output labeling."""
    fake_provider = FakeLLMProvider()
    results = generate_advisory_recommendations(SAMPLE_FINDINGS, provider=fake_provider)

    assert len(results) == len(SAMPLE_FINDINGS)
    for item in results:
        assert item["isAdvisory"] is True
        assert item["source"] == "advisory_llm"
        assert len(item["steps"]) > 0
        assert item["findingId"] in {f["findingId"] for f in SAMPLE_FINDINGS}


def test_result_root_unchanged_when_generator_runs():
    """
    Verifies that running advisory recommendation generation NEVER alters the consensus Merkle root.
    Specification rule: Result root is computed strictly from findings_leaf and host_score_leaf.
    """
    # 1. Compute original root before generator runs
    leaves_before = [finding_leaf(canonical_json(f)) for f in SAMPLE_FINDINGS]
    leaves_before.extend([
        host_score_leaf(h["hostId"], h["findingsDigest"], int(h["score"]))
        for h in SAMPLE_HOST_SCORES
    ])
    tree_before = MerkleTree(leaves_before)
    root_before = tree_before.root_hex

    # 2. Run advisory LLM recommendation generator
    advisory_recs = generate_advisory_recommendations(SAMPLE_FINDINGS)
    assert len(advisory_recs) == len(SAMPLE_FINDINGS)

    # 3. Compute root after generator runs
    leaves_after = [finding_leaf(canonical_json(f)) for f in SAMPLE_FINDINGS]
    leaves_after.extend([
        host_score_leaf(h["hostId"], h["findingsDigest"], int(h["score"]))
        for h in SAMPLE_HOST_SCORES
    ])
    tree_after = MerkleTree(leaves_after)
    root_after = tree_after.root_hex

    assert root_before == root_after
    assert len(root_before) == 64  # 64 hex chars (32 bytes)


def test_acceptance_report_shows_labeled_recommendations_and_verifier_passes(tmp_path, monkeypatch):
    """
    Acceptance check for Prompt T3.2:
    The generated report displays labeled advisory recommendations and verifier Step 2 passes.
    """
    import backend.config as config
    from backend.database import create_case, init_db
    from backend.storage import get_case_dir

    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "CASES_DIR", tmp_path / "data" / "cases")
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "data" / "cases.db")
    monkeypatch.setattr(config, "REPO_ROOT", tmp_path)

    init_db()
    case_id = "test_case_t32"
    create_case(case_id=case_id, pcap_sha256="aa" * 32, status="analyzed")

    case_dir = get_case_dir(case_id)
    (case_dir / "findings.json").write_text(json.dumps(SAMPLE_FINDINGS), encoding="utf-8")
    (case_dir / "host_scores.json").write_text(json.dumps(SAMPLE_HOST_SCORES), encoding="utf-8")
    (case_dir / "sessions.json").write_text(json.dumps([]), encoding="utf-8")

    # Compute valid result root
    leaves = [finding_leaf(canonical_json(f)) for f in SAMPLE_FINDINGS]
    leaves.extend([
        host_score_leaf(h["hostId"], h["findingsDigest"], int(h["score"]))
        for h in SAMPLE_HOST_SCORES
    ])
    expected_root = MerkleTree(leaves).root_hex

    (case_dir / "result.json").write_text(
        json.dumps({"resultRoot": expected_root}),
        encoding="utf-8",
    )
    (case_dir / "manifest.json").write_text(
        json.dumps({
            "caseId": case_id,
            "resultRoot": expected_root,
            "pcapSha256": "aa" * 32,
            "rulesetHash": "bb" * 32,
            "engineVersion": "0.1.0",
        }),
        encoding="utf-8",
    )

    # Build report
    report_dict, canon_bytes, report_hash, html_content = build_case_report(case_id, save=False)

    # 1. Assert HTML contains advisory label
    assert "Advisory Generated Remediation" in html_content
    assert "ADVISORY (NON-CONSENSUS)" in html_content

    # 2. Assert verifier Step 2 (recomputed root vs resultRoot) passes
    step2 = [s for s in report_dict["verifierSteps"] if s["step"] == 2][0]
    assert step2["status"] == "PASS"

    # 3. Assert report JSON contains advisory recommendations
    assert "advisoryRecommendations" in report_dict
    assert len(report_dict["advisoryRecommendations"]) == len(SAMPLE_FINDINGS)
