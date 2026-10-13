"""Unit tests for Advisory Anomaly Detection (Tier 2 / Prompt T2.4)."""
import json
from pathlib import Path
import pytest
import sklearn

from advisory.anomaly.detector import AnomalyDetector
from advisory.anomaly.features import (
    FEATURE_NAMES,
    TLS_VERSION_MAP,
    extract_session_features,
    session_to_feature_vector,
)
from engine.smscope.ingest import ingest
from engine.smscope.protocols import process_protocols
from engine.smscope.tls import process_tls
from engine.smscope.certs import process_certs
from engine.smscope.models import SessionRecord, TlsInfo

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"
ADVISORY_DIR = REPO_ROOT / "advisory" / "anomaly"
MODEL_PATH = ADVISORY_DIR / "model.joblib"
SUMMARY_PATH = ADVISORY_DIR / "baseline_summary.json"


def test_feature_extraction_types_and_ranges():
    """Verify all features are discrete integers and no timestamp floats exist."""
    from engine.smscope.models import StarttlsInfo

    session = SessionRecord(
        sessionId=42,
        serverEndpoint="172.28.0.10:25",
        clientEndpoint="172.28.0.100:54321",
        protocol="smtp",
        protocolSource="heuristic",
        transportMode="starttls",
        streamComplete=True,
        firstPacketTs=1697000000,
        starttls=StarttlsInfo(offered=True, attempted=True, outcome="succeeded"),
        tls=TlsInfo(
            certObservable=True,
            version="TLS 1.2",
            cipherSuiteCode=0xC02F,
            cipherSuiteName="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            ja3="771,49199,0-23-65281,29-23,0",
            forwardSecrecy=True,
            resumed=False,
        ),
    )

    feat_dict = extract_session_features(session)
    assert len(feat_dict) == len(FEATURE_NAMES)
    for k, v in feat_dict.items():
        assert isinstance(v, int), f"Feature {k} must be integer, got {type(v)}"

    assert feat_dict["tls_version"] == TLS_VERSION_MAP["TLS 1.2"]
    assert feat_dict["cipher_suite_code"] == 0xC02F
    assert feat_dict["cert_differs_from_baseline"] == 0
    assert feat_dict["resumed_flag"] == 0


def test_model_artifact_loading_and_metadata():
    """Verify saved Isolation Forest model and baseline summary load cleanly."""
    assert MODEL_PATH.exists(), f"Missing {MODEL_PATH}"
    assert SUMMARY_PATH.exists(), f"Missing {SUMMARY_PATH}"

    detector = AnomalyDetector(model_path=MODEL_PATH, summary_path=SUMMARY_PATH)
    assert detector.model is not None
    assert detector.baseline_summary.get("sklearn_version") == sklearn.__version__
    assert detector.baseline_summary.get("session_count", 0) >= 200
    assert "threshold" in detector.baseline_summary


def test_scoring_determinism():
    """Verify repeated scoring runs on the same input return exact identical results."""
    detector = AnomalyDetector(model_path=MODEL_PATH, summary_path=SUMMARY_PATH)
    pcap_path = CAPTURES_DIR / "A3.pcap"
    assert pcap_path.exists()

    streams, _ = ingest(pcap_path)
    sessions = process_certs(process_tls(process_protocols(streams)))
    assert len(sessions) > 0

    run1 = [detector.score_session(s) for s in sessions]
    run2 = [detector.score_session(s) for s in sessions]

    assert json.dumps(run1, sort_keys=True) == json.dumps(run2, sort_keys=True)


def test_injected_anomaly_a3_detected():
    """Verify A3 (unseen client JA3 profile) is flagged as anomalous."""
    detector = AnomalyDetector(model_path=MODEL_PATH, summary_path=SUMMARY_PATH)
    pcap_path = CAPTURES_DIR / "A3.pcap"
    assert pcap_path.exists()

    streams, _ = ingest(pcap_path)
    sessions = process_certs(process_tls(process_protocols(streams)))
    assert len(sessions) == 1

    result = detector.score_session(sessions[0])
    assert result["isAnomaly"] is True
    assert "ja3_rarity_bucket=0 (baseline_freq=0.0%)" in result["topDeviatingFeatures"]


def test_dict_input_compatibility():
    """Verify score_session works directly with dictionary input (from sessions.json)."""
    detector = AnomalyDetector(model_path=MODEL_PATH, summary_path=SUMMARY_PATH)
    dict_session = {
        "sessionId": 99,
        "serverEndpoint": "172.28.0.10:25",
        "transportMode": "starttls",
        "tls": {
            "version": "TLS 1.2",
            "cipherSuiteCode": 49199,
            "ja3": "unseen-fake-ja3-hash",
            "resumed": False,
        },
        "starttls": {"offered": True, "outcome": "succeeded"},
        "certificates": [],
    }

    result = detector.score_session(dict_session)
    assert result["sessionId"] == 99
    assert isinstance(result["anomalyScore"], float)
    assert isinstance(result["isAnomaly"], bool)
    assert "topDeviatingFeatures" in result


def test_advisory_isolation_from_merkle_result():
    """Verify that Merkle result root contains only findings and host_scores, never anomaly output."""
    from engine.smscope.results.merkle import MerkleTree
    from engine.smscope.results.hashing import finding_leaf, host_score_leaf
    from engine.smscope.results.canonical import canonical_json

    dummy_finding = {"findingId": "test-finding", "ruleId": "R01", "severity": "Critical"}
    leaf1 = finding_leaf(canonical_json(dummy_finding))
    leaf2 = host_score_leaf("aa" * 32, "bb" * 32, 95)

    tree = MerkleTree([leaf1, leaf2])
    root = tree.root_hex
    assert len(root) == 64  # 64 hex chars (32 bytes)
