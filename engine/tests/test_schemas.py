"""Tests validating schemas against sample documents."""
import json
from pathlib import Path
import pytest
import jsonschema

SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "spec" / "schemas"


def load_schema(name: str) -> dict:
    with open(SCHEMAS_DIR / f"{name}.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_session_record_schema():
    schema = load_schema("session_record")
    valid_record = {
        "sessionId": 1,
        "clientEndpoint": "10.0.0.2:45000",
        "serverEndpoint": "192.168.1.10:25",
        "protocol": "smtp",
        "protocolSource": "content",
        "transportMode": "starttls",
        "streamComplete": True,
        "firstPacketTs": 1700000000,
        "starttls": {
            "offered": True,
            "attempted": True,
            "outcome": "succeeded"
        },
        "cleartextAuth": [],
        "tls": {
            "version": "TLS 1.2",
            "cipherSuiteCode": 49199,
            "cipherSuiteName": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "kxType": "ECDHE",
            "kxGroupOrDhBits": 256,
            "forwardSecrecy": True,
            "resumed": False,
            "ja3": "abc",
            "ja3s": "def",
            "sni": "mail.example.com",
            "certObservable": True,
            "certNotObservableReason": None
        },
        "certificates": [
            {
                "sha256": "a" * 64,
                "subject": "CN=mail.example.com",
                "issuer": "CN=Example CA",
                "notBefore": 1690000000,
                "notAfter": 1720000000,
                "keyAlgorithm": "RSA",
                "keySize": 2048,
                "signatureAlgorithm": "sha256WithRSAEncryption",
                "san": ["mail.example.com"],
                "isCa": False,
                "verdicts": ["valid"]
            }
        ]
    }
    jsonschema.validate(instance=valid_record, schema=schema)

    # Rejection of float for integer field
    invalid_record = dict(valid_record, sessionId=1.5)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=invalid_record, schema=schema)


def test_finding_schema():
    schema = load_schema("finding")
    valid_finding = {
        "findingId": "a" * 64,
        "ruleId": "R01",
        "severity": "Critical",
        "serverEndpoint": "192.168.1.10:25",
        "sortedSessionIds": [1, 2],
        "sessionCount": 2,
        "evidence": [
            {"sessionId": 1, "packetNumber": 4, "note": "cleartext auth"}
        ],
        "details": {"mechanism": "PLAIN"}
    }
    jsonschema.validate(instance=valid_finding, schema=schema)


def test_host_score_schema():
    schema = load_schema("host_score")
    valid_score = {
        "hostId": "b" * 64,
        "serverEndpoint": "192.168.1.10:25",
        "score": 85,
        "grade": "B",
        "findingsDigest": "c" * 64
    }
    jsonschema.validate(instance=valid_score, schema=schema)

    # Score > 100 rejected
    invalid_score = dict(valid_score, score=101)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance=invalid_score, schema=schema)


def test_case_manifest_schema():
    schema = load_schema("case_manifest")
    valid_manifest = {
        "caseId": "0x123",
        "pcapSha256": "d" * 64,
        "engineVersion": "0.1.0",
        "rulesetHash": "e" * 64,
        "resultRoot": "f" * 64,
        "findingCount": 5,
        "hostCount": 2,
        "reportHash": None,
        "txHashes": {"openCase": "0xabc"}
    }
    jsonschema.validate(instance=valid_manifest, schema=schema)
