"""Comprehensive regression tests for browser Record action and routes (Issue 5).

Verifies:
1. Attempting to record posture for a case without an on-chain ID redirects with an error banner.
2. Attempting to record posture for an unfinalized case redirects with an error banner.
3. Attempting to record posture with an analyst mismatch redirects with an error banner.
4. Attempting to record posture when host scores are missing redirects with an error banner.
5. Attempting to record posture when Merkle proofs are missing redirects with an error banner.
6. Unexpected server exceptions log a traceback and redirect with a sanitized client error without leaking secrets.
7. Successful record action records posture and redirects with success banner; repeated clicks do not duplicate transactions.
8. Direct /cases/{case_id}/record route cleanly serves both HTML redirects and JSON API responses.
"""
import json
import logging
import threading
from unittest.mock import MagicMock
import uuid

import pytest
from fastapi.testclient import TestClient
from web3.datastructures import AttributeDict

from backend.app import app
import backend.config as config
from backend.chain.gateway import ChainGateway, InvalidStateError, GatewayError
from backend.database import create_case, init_db, set_case_onchain_id, update_case_status
from backend.storage import get_case_dir


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    """Isolate database and cases directories."""
    test_cases_dir = tmp_path / "cases"
    test_cases_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "CASES_DIR", test_cases_dir)
    test_db = tmp_path / "test_browser_record.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    init_db()


def get_auth_client() -> TestClient:
    """Helper returning TestClient authenticated as Analyst with CSRF token."""
    client = TestClient(app)
    client.cookies.set("api_key", config.ANALYST_API_KEY)
    client.cookies.set("csrf_token", "test-csrf-token")
    client.headers["X-CSRF-Token"] = "test-csrf-token"
    return client


def _create_mock_gateway():
    """Create a mock ChainGateway with isolated locks and mock contracts."""
    gw = ChainGateway.__new__(ChainGateway)
    gw.w3 = MagicMock()
    gw.w3.eth.get_transaction_count.return_value = 0
    gw.w3.eth.chain_id = 31337
    gw.w3.eth.gas_price = 1000000000
    gw.w3.eth.get_transaction.return_value = None
    gw.w3.eth.get_transaction_receipt.return_value = None
    gw.w3.eth.wait_for_transaction_receipt.return_value = None

    gw.analyst_account = MagicMock()
    gw.analyst_account.address = "0x" + "1" * 40
    gw._analyst_lock = threading.Lock()
    gw._send_tx_retry_delay = 0.01

    gw.case_registry = MagicMock()
    gw.posture_ledger = MagicMock()
    gw.quorum = MagicMock()
    gw.roles = MagicMock()
    return gw


def test_browser_record_without_onchain_id_redirects_with_error():
    """Clicking Record for a case with no on-chain ID must redirect with error banner, NEVER return HTTP 500."""
    client = get_auth_client()
    case_id = uuid.uuid4().hex
    case_dir = get_case_dir(case_id)
    (case_dir / "pcap.bin").write_bytes(b"dummy pcap content")

    create_case(case_id=case_id, pcap_sha256="a" * 64, status="Finalized")

    res = client.post(
        f"/cases/{case_id}/action/record",
        data={"csrf_token": "test-csrf-token"},
        follow_redirects=False,
    )

    assert res.status_code in (302, 303)
    assert f"/cases/{case_id}" in res.headers["location"]
    assert "error=" in res.headers["location"]

    res_followed = client.get(res.headers["location"], headers={"Accept": "text/html"})
    assert res_followed.status_code == 200
    assert "alert alert-error" in res_followed.text
    assert "not been opened on-chain yet" in res_followed.text.lower()


def test_browser_record_unfinalized_case_redirects_with_error(monkeypatch):
    """Attempting to record posture for an unfinalized case must redirect with error banner."""
    client = get_auth_client()
    case_id = uuid.uuid4().hex
    case_dir = get_case_dir(case_id)
    (case_dir / "pcap.bin").write_bytes(b"dummy pcap content")
    create_case(case_id=case_id, pcap_sha256="a" * 64, status="opened")
    onchain_id = "0x" + "c" * 64
    set_case_onchain_id(case_id, onchain_id)

    mock_gw = _create_mock_gateway()
    # State 3 is Committing, not Finalized (5)
    mock_gw.case_registry.functions.caseState.return_value.call.return_value = 3
    monkeypatch.setattr("backend.app.get_gateway", lambda: mock_gw)

    res = client.post(
        f"/cases/{case_id}/action/record",
        data={"csrf_token": "test-csrf-token"},
        follow_redirects=False,
    )

    assert res.status_code in (302, 303)
    assert "error=" in res.headers["location"]
    res_followed = client.get(res.headers["location"], headers={"Accept": "text/html"})
    assert res_followed.status_code == 200
    assert "must be finalized" in res_followed.text.lower()


def test_browser_record_analyst_mismatch_redirects_with_error(monkeypatch):
    """Attempting to record posture when on-chain analyst doesn't match must redirect with error banner."""
    client = get_auth_client()
    case_id = uuid.uuid4().hex
    case_dir = get_case_dir(case_id)
    (case_dir / "pcap.bin").write_bytes(b"dummy pcap content")
    create_case(case_id=case_id, pcap_sha256="a" * 64, status="finalized")
    onchain_id = "0x" + "c" * 64
    set_case_onchain_id(case_id, onchain_id)

    mock_gw = _create_mock_gateway()
    mock_gw.case_registry.functions.caseState.return_value.call.return_value = 5
    # Analyst registered on-chain is different
    mock_gw.case_registry.functions.analyst.return_value.call.return_value = "0x" + "9" * 40
    monkeypatch.setattr("backend.app.get_gateway", lambda: mock_gw)

    res = client.post(
        f"/cases/{case_id}/action/record",
        data={"csrf_token": "test-csrf-token"},
        follow_redirects=False,
    )

    assert res.status_code in (302, 303)
    assert "error=" in res.headers["location"]
    res_followed = client.get(res.headers["location"], headers={"Accept": "text/html"})
    assert res_followed.status_code == 200
    assert "does not match" in res_followed.text.lower()


def test_browser_record_missing_host_scores_redirects_with_error(monkeypatch):
    """Attempting to record posture without host scores must redirect with error banner."""
    client = get_auth_client()
    case_id = uuid.uuid4().hex
    case_dir = get_case_dir(case_id)
    (case_dir / "pcap.bin").write_bytes(b"dummy pcap content")
    create_case(case_id=case_id, pcap_sha256="a" * 64, status="finalized")
    onchain_id = "0x" + "c" * 64
    set_case_onchain_id(case_id, onchain_id)

    mock_gw = _create_mock_gateway()
    mock_gw.case_registry.functions.caseState.return_value.call.return_value = 5
    mock_gw.case_registry.functions.analyst.return_value.call.return_value = mock_gw.analyst_account.address
    monkeypatch.setattr("backend.app.get_gateway", lambda: mock_gw)

    # Empty host_scores.json
    (case_dir / "host_scores.json").write_text("[]", encoding="utf-8")

    res = client.post(
        f"/cases/{case_id}/action/record",
        data={"csrf_token": "test-csrf-token"},
        follow_redirects=False,
    )

    assert res.status_code in (302, 303)
    assert "error=" in res.headers["location"]
    res_followed = client.get(res.headers["location"], headers={"Accept": "text/html"})
    assert res_followed.status_code == 200
    assert "no host scores found" in res_followed.text.lower()


def test_browser_record_missing_proof_redirects_with_error(monkeypatch):
    """Attempting to record posture without Merkle proof for host must redirect with error banner."""
    client = get_auth_client()
    case_id = uuid.uuid4().hex
    case_dir = get_case_dir(case_id)
    (case_dir / "pcap.bin").write_bytes(b"dummy pcap content")
    create_case(case_id=case_id, pcap_sha256="a" * 64, status="finalized")
    onchain_id = "0x" + "c" * 64
    set_case_onchain_id(case_id, onchain_id)

    mock_gw = _create_mock_gateway()
    mock_gw.case_registry.functions.caseState.return_value.call.return_value = 5
    mock_gw.case_registry.functions.analyst.return_value.call.return_value = mock_gw.analyst_account.address
    mock_gw.posture_ledger.functions.hasRecorded.return_value.call.return_value = False
    monkeypatch.setattr("backend.app.get_gateway", lambda: mock_gw)

    host_id = "0x" + "5" * 64
    host_scores = [{
        "hostId": host_id,
        "findingsDigest": "0x" + "6" * 64,
        "score": 95,
    }]
    (case_dir / "host_scores.json").write_text(json.dumps(host_scores), encoding="utf-8")
    # Missing host_id from host_proofs
    (case_dir / "host_proofs.json").write_text("{}", encoding="utf-8")

    res = client.post(
        f"/cases/{case_id}/action/record",
        data={"csrf_token": "test-csrf-token"},
        follow_redirects=False,
    )

    assert res.status_code in (302, 303)
    assert "error=" in res.headers["location"]
    res_followed = client.get(res.headers["location"], headers={"Accept": "text/html"})
    assert res_followed.status_code == 200
    assert "inclusion proof missing" in res_followed.text.lower()


def test_browser_record_unexpected_exception_logs_and_redirects_safely(monkeypatch, caplog):
    """Unexpected exception logs traceback and redirects with sanitized message without leaking secrets."""
    client = get_auth_client()
    case_id = uuid.uuid4().hex
    case_dir = get_case_dir(case_id)
    (case_dir / "pcap.bin").write_bytes(b"dummy pcap content")
    create_case(case_id=case_id, pcap_sha256="a" * 64, status="finalized")
    onchain_id = "0x" + "c" * 64
    set_case_onchain_id(case_id, onchain_id)

    mock_gw = _create_mock_gateway()
    secret_leaked_in_internal_exc = "VERY_CONFIDENTIAL_SECRET_0xdeadbeef"
    mock_gw.record_posture = MagicMock(side_effect=RuntimeError(f"Database crash with {secret_leaked_in_internal_exc}"))
    monkeypatch.setattr("backend.app.get_gateway", lambda: mock_gw)

    with caplog.at_level(logging.ERROR):
        res = client.post(
            f"/cases/{case_id}/action/record",
            data={"csrf_token": "test-csrf-token"},
            follow_redirects=False,
        )

    # Must redirect, not return 500
    assert res.status_code in (302, 303)
    # The secret must NOT appear in the client-visible redirect location
    assert secret_leaked_in_internal_exc not in res.headers["location"]
    assert "error=" in res.headers["location"]

    # Must log traceback in server logs
    assert any("Unexpected error executing browser action" in r.message for r in caplog.records)


def test_browser_record_successful_and_repeated_clicks_idempotent(monkeypatch):
    """Successful record works, and repeated clicks do not send duplicate transactions."""
    client = get_auth_client()
    case_id = uuid.uuid4().hex
    case_dir = get_case_dir(case_id)
    (case_dir / "pcap.bin").write_bytes(b"dummy pcap content")
    create_case(case_id=case_id, pcap_sha256="a" * 64, status="finalized")
    onchain_id = "0x" + "c" * 64
    set_case_onchain_id(case_id, onchain_id)

    host_id = "0x" + "5" * 64
    host_scores = [{
        "hostId": host_id,
        "findingsDigest": "0x" + "6" * 64,
        "score": 88,
    }]
    (case_dir / "host_scores.json").write_text(json.dumps(host_scores), encoding="utf-8")
    (case_dir / "host_proofs.json").write_text(json.dumps({host_id: ["0x" + "7" * 64]}), encoding="utf-8")

    mock_gw = _create_mock_gateway()
    mock_gw.case_registry.functions.caseState.return_value.call.return_value = 5
    mock_gw.case_registry.functions.analyst.return_value.call.return_value = mock_gw.analyst_account.address

    # First run: not yet recorded
    mock_gw.posture_ledger.functions.hasRecorded.return_value.call.return_value = False
    mock_receipt = AttributeDict({
        "transactionHash": bytes.fromhex("8" * 64),
        "status": 1,
        "blockNumber": 12345,
    })
    mock_gw._send_tx = MagicMock(return_value=mock_receipt)
    monkeypatch.setattr("backend.app.get_gateway", lambda: mock_gw)

    # Click 1: Record posture
    res1 = client.post(
        f"/cases/{case_id}/action/record",
        data={"csrf_token": "test-csrf-token"},
        follow_redirects=False,
    )
    assert res1.status_code in (302, 303)
    assert "success=" in res1.headers["location"]
    assert mock_gw._send_tx.call_count == 1

    # Follow redirect: overview renders success banner
    res_followed = client.get(res1.headers["location"], headers={"Accept": "text/html"})
    assert res_followed.status_code == 200
    assert "alert alert-success" in res_followed.text

    # Click 2: Repeated click (now hasRecorded returns True)
    mock_gw.posture_ledger.functions.hasRecorded.return_value.call.return_value = True
    mock_gw._send_tx.reset_mock()

    res2 = client.post(
        f"/cases/{case_id}/action/record",
        data={"csrf_token": "test-csrf-token"},
        follow_redirects=False,
    )
    assert res2.status_code in (302, 303)
    assert "success=" in res2.headers["location"]
    # Re-click did NOT broadcast any new transaction!
    assert mock_gw._send_tx.call_count == 0


def test_direct_record_route_html_and_api(monkeypatch):
    """Direct /cases/{case_id}/record endpoint supports both HTML redirect and JSON API."""
    client = get_auth_client()
    case_id = uuid.uuid4().hex
    case_dir = get_case_dir(case_id)
    (case_dir / "pcap.bin").write_bytes(b"dummy pcap content")
    create_case(case_id=case_id, pcap_sha256="a" * 64, status="finalized")
    onchain_id = "0x" + "c" * 64
    set_case_onchain_id(case_id, onchain_id)

    mock_gw = _create_mock_gateway()
    mock_gw.record_posture = MagicMock(return_value={"status": "recorded", "hosts": []})
    monkeypatch.setattr("backend.app.get_gateway", lambda: mock_gw)

    # 1. HTML request redirects
    res_html = client.post(
        f"/cases/{case_id}/record",
        headers={"Accept": "text/html", "X-CSRF-Token": "test-csrf-token"},
        follow_redirects=False,
    )
    assert res_html.status_code in (302, 303)
    assert f"/cases/{case_id}" in res_html.headers["location"]
    assert "success=" in res_html.headers["location"]

    # 2. JSON API request returns JSON
    res_api = client.post(
        f"/cases/{case_id}/record",
        headers={"Accept": "application/json", "X-CSRF-Token": "test-csrf-token"},
        follow_redirects=False,
    )
    assert res_api.status_code == 200
    data = res_api.json()
    assert data["status"] == "recorded"
