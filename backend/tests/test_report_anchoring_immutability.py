"""Regression test for anchored report immutability (Issue 6).

Verifies that anchoring a report on-chain does not alter the canonical report
JSON payload or its SHA-256 hash. Mutable live chain status and new transaction
hashes are separated into statusEnvelope and report_status.json.
"""
import hashlib
import json
import uuid
import pytest

import backend.config as config
from backend.database import create_case, init_db, record_chain_tx
from backend.reports.builder import build_case_report
from backend.storage import get_case_dir, read_case_json


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    """Isolate database and cases directories."""
    test_cases_dir = tmp_path / "cases"
    test_cases_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "CASES_DIR", test_cases_dir)
    test_db = tmp_path / "test_report_immutability.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    init_db()


def test_report_sha256_immutable_across_anchoring(monkeypatch):
    """
    Assert that the canonical report payload in report.json and its SHA-256
    remain strictly unchanged before and after anchoring transactions occur.
    """
    case_id = uuid.uuid4().hex
    case_dir = get_case_dir(case_id)

    # Setup case artifacts
    pcap_path = case_dir / "pcap.bin"
    pcap_path.write_bytes(b"dummy pcap traffic")
    pcap_sha = hashlib.sha256(b"dummy pcap traffic").hexdigest()

    create_case(case_id=case_id, pcap_sha256=pcap_sha, status="Finalized")

    manifest = {
        "caseId": case_id,
        "pcapSha256": pcap_sha,
        "engineVersion": "0.1.0",
        "rulesetHash": "11" * 32,
        "resultRoot": "22" * 32,
    }
    (case_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (case_dir / "findings.json").write_text(json.dumps([]), encoding="utf-8")
    (case_dir / "host_scores.json").write_text(json.dumps([]), encoding="utf-8")
    (case_dir / "sessions.json").write_text(json.dumps([]), encoding="utf-8")

    # 1. Build initial report BEFORE anchoring
    report_initial = build_case_report(case_id, save=True)
    report_file = case_dir / "report.json"
    assert report_file.exists()

    report_bytes_before = report_file.read_bytes()
    report_sha_before = hashlib.sha256(report_bytes_before).hexdigest()

    # 2. Simulate anchoring: record new on-chain transaction and update onchain state
    record_chain_tx(
        case_id=case_id,
        step="anchor",
        nonce=1,
        tx_hash="0x" + "aa" * 32,
        status="confirmed",
    )

    class MockGateway:
        def poll_events(self): pass
        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "state": "Finalized",
                "stateName": "Finalized",
                "reportHash": "0x" + report_sha_before,
                "finalRoot": "0x" + "22" * 32,
                "validators": [],
                "transactions": [
                    {"step": "anchor", "txHash": "0x" + "aa" * 32, "blockNumber": 100}
                ],
            }

    # 3. Rebuild report AFTER anchoring transaction exists
    report_after = build_case_report(case_id, save=True, gateway_override=MockGateway())
    report_bytes_after = report_file.read_bytes()
    report_sha_after = hashlib.sha256(report_bytes_after).hexdigest()

    # The canonical report payload and its SHA-256 MUST remain identical
    assert report_sha_after == report_sha_before
    assert report_bytes_after == report_bytes_before

    # Verify that dynamic chain state is captured in statusEnvelope or report_status.json
    status_file = case_dir / "report_status.json"
    assert status_file.exists()
    status_data = json.loads(status_file.read_text(encoding="utf-8"))
    assert "txHashes" in status_data
    assert "onChainState" in status_data
    assert len(status_data["txHashes"]) > 0

    manifest_data = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest_data["reportHash"] == report_sha_before
