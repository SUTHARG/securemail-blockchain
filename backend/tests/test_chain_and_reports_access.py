"""Regression tests for Chain page and Report access authentication (Prompt Phase 10).

Verifies:
1. GET /cases/{case_id}/chain for a valid case renders correctly without 500 error.
2. Chain page behavior when the blockchain node is unavailable (sanitized 503 error).
3. Chain page behavior when on-chain data is missing (off-chain case renders cleanly with PENDING badges).
4. JSON report access through intended browser navigation and authenticated API workflows.
5. HTML report access through intended browser navigation and authenticated API workflows.
6. Missing or invalid API credentials return HTTP 401 with appropriate details.
7. Unauthorized users and analysts cannot access administrative operations (HTTP 401/403).
8. Existing authentication protections and RBAC on chain-changing endpoints remain strictly enforced.
9. Report content and determinism are preserved across requests.
"""
import hashlib
import io
import json
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from backend.app import app
import backend.config as config
from backend.database import create_case, get_case, init_db
from backend.storage import get_case_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"

TEST_ANALYST_KEY = "test-analyst-secret-key-12345"
TEST_ADMIN_KEY = "test-admin-secret-key-67890"

analyst_headers = {"X-API-Key": TEST_ANALYST_KEY}
admin_headers = {"X-API-Key": TEST_ADMIN_KEY}
browser_headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}


@pytest.fixture
def client():
    """Create test client with isolated database."""
    init_db()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def seeded_case(client):
    """Ensure a completed case exists with report and artifacts."""
    import uuid
    case_id = f"test_reg_{uuid.uuid4().hex[:12]}"
    case_dir = get_case_dir(case_id)
    case_dir.mkdir(parents=True, exist_ok=True)

    pcap_bytes = (CAPTURES_DIR / "S01a.pcap").read_bytes()
    pcap_sha = hashlib.sha256(pcap_bytes).hexdigest()
    (case_dir / "pcap.bin").write_bytes(pcap_bytes)

    create_case(
        case_id=case_id,
        pcap_sha256=pcap_sha,
        status="Finalized",
    )

    manifest = {
        "caseId": case_id,
        "pcapSha256": pcap_sha,
        "engineVersion": "0.1.0",
        "rulesetHash": "a" * 64,
        "resultRoot": "b" * 64,
    }
    (case_dir / "manifest.json").write_text(json.dumps(manifest))
    (case_dir / "findings.json").write_text(json.dumps([]))
    (case_dir / "host_scores.json").write_text(json.dumps([]))
    (case_dir / "sessions.json").write_text(json.dumps([]))
    (case_dir / "result.json").write_text(json.dumps({"resultRoot": "b" * 64, "leaves": []}))

    # Generate report
    from backend.reports.builder import build_case_report
    build_case_report(case_id, save=True)

    return case_id


def test_chain_for_valid_case_with_mock_validators(client, seeded_case, monkeypatch):
    """
    1. GET /cases/{case_id}/chain for a valid on-chain case renders correctly.
    Verifies that validator commitments and revealed roots do NOT trigger UndefinedError.
    """
    case_id = seeded_case
    onchain_id = "0x" + "11" * 32

    # Set on-chain ID on case
    from backend.database import set_case_onchain_id
    set_case_onchain_id(case_id, onchain_id)

    # Mock gateway to return realistic validator submissions
    class MockGateway:
        def poll_events(self):
            pass

        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "status": "report_anchored",
                "onchainCaseId": onchain_id,
                "state": "Finalized",
                "stateName": "Finalized",
                "resultRoot": "0x" + "bb" * 32,
                "claimedRoot": "0x" + "bb" * 32,
                "finalRoot": "0x" + "bb" * 32,
                "reportHash": "0x" + "cc" * 32,
                "round": 1,
                "k": 2,
                "n": 3,
                "validators": [
                    {
                        "address": "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
                        "committed": True,
                        "commitment": "0x" + "aa" * 32,
                        "revealed": True,
                        "resultRoot": "0x" + "bb" * 32,
                        "root": "0x" + "bb" * 32,
                    },
                    {
                        "address": "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
                        "committed": True,
                        "commitment": "0x" + "aa" * 32,
                        "revealed": True,
                        "resultRoot": "0x" + "bb" * 32,
                        "root": "0x" + "bb" * 32,
                    },
                    {
                        "address": "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
                        "committed": False,
                        "commitment": None,
                        "revealed": False,
                        "resultRoot": None,
                        "root": None,
                    },
                ],
                "transactions": [
                    {
                        "step": "claim",
                        "tx_hash": "0x123456",
                        "block_number": 42,
                        "timestamp": 1791896000,
                    }
                ],
            }

    import backend.app as app_module
    monkeypatch.setattr(app_module, "get_gateway", lambda: MockGateway())

    # 1. HTML View
    res_html = client.get(f"/cases/{case_id}/chain", headers=browser_headers)
    assert res_html.status_code == 200
    assert "text/html" in res_html.headers["content-type"]
    assert "Blockchain Ledger &amp; Independent Verification" in res_html.text or "Blockchain Ledger & Independent Verification" in res_html.text
    assert "Validator Commit-Reveal Consensus" in res_html.text
    # Verify the revealed validator roots are rendered without UndefinedError
    assert "0xbbbbbbbbbbbbbb" in res_html.text

    # 2. JSON API View
    res_json = client.get(f"/cases/{case_id}/chain", headers=analyst_headers)
    assert res_json.status_code == 200
    data = res_json.json()
    assert data["state"] == "Finalized"
    assert len(data["validators"]) == 3
    assert data["validators"][0]["revealed"] is True


def test_chain_behavior_when_blockchain_node_unavailable(client, seeded_case, monkeypatch):
    """
    2. Chain page behavior when the blockchain node is unavailable.
    Returns HTTP 503 with a sanitized error message instead of 500 or fake data.
    """
    case_id = seeded_case
    onchain_id = "0x" + "22" * 32
    from backend.database import set_case_onchain_id
    set_case_onchain_id(case_id, onchain_id)

    class BrokenGateway:
        def poll_events(self):
            raise ConnectionError("Failed to establish a new connection: [WinError 10061] Connection refused")

        def get_chain_status(self, cid):
            raise ConnectionError("Failed to establish a new connection: [WinError 10061] Connection refused")

    import backend.app as app_module
    monkeypatch.setattr(app_module, "get_gateway", lambda: BrokenGateway())

    # HTML request
    res_html = client.get(f"/cases/{case_id}/chain", headers=browser_headers)
    assert res_html.status_code == 503
    assert "Blockchain RPC endpoint is unavailable" in res_html.text

    # JSON request
    res_json = client.get(f"/cases/{case_id}/chain", headers=analyst_headers)
    assert res_json.status_code == 503
    assert res_json.json()["detail"] == "Blockchain RPC endpoint is unavailable"


def test_chain_behavior_when_onchain_data_missing(client, seeded_case):
    """
    3. Chain page behavior when on-chain data is missing (off-chain case).
    Renders cleanly with 'Not Opened' state and PENDING steps without exceptions.
    """
    case_id = seeded_case
    # Ensure onchain_case_id is None
    from backend.database import get_case
    c = get_case(case_id)
    assert c.get("onchain_case_id") is None

    # HTML request
    res_html = client.get(f"/cases/{case_id}/chain", headers=browser_headers)
    assert res_html.status_code == 200
    assert "Not Opened" in res_html.text
    assert "No validator consensus round active yet." in res_html.text

    # JSON request
    res_json = client.get(f"/cases/{case_id}/chain", headers=analyst_headers)
    assert res_json.status_code == 200
    data = res_json.json()
    assert data["onchainCaseId"] is None
    assert data["state"] == "None"


def test_json_report_access_intended_workflow(client, seeded_case):
    """
    4. JSON report access through the intended authenticated and browser workflows.
    """
    case_id = seeded_case

    # 4a. Browser navigation workflow (Accept: text/html)
    res_browser = client.get(f"/cases/{case_id}/report?format=json", headers=browser_headers)
    assert res_browser.status_code == 200
    assert res_browser.headers["content-type"] == "application/json"
    data = res_browser.json()
    assert data["caseId"] == case_id
    assert "findings" in data
    assert "verifierSteps" in data

    # 4b. Authenticated API client workflow
    res_api = client.get(f"/cases/{case_id}/report?format=json", headers=analyst_headers)
    assert res_api.status_code == 200
    assert res_api.headers["content-type"] == "application/json"
    assert res_api.json()["caseId"] == case_id


def test_html_report_access_intended_workflow(client, seeded_case):
    """
    5. HTML report access through the intended authenticated and browser workflows.
    """
    case_id = seeded_case

    # 5a. Browser navigation workflow
    res_browser = client.get(f"/cases/{case_id}/report?format=html", headers=browser_headers)
    assert res_browser.status_code == 200
    assert "text/html" in res_browser.headers["content-type"]
    assert "SecureMailScope Posture Assessment Report" in res_browser.text

    # 5b. Authenticated API client workflow
    res_api = client.get(f"/cases/{case_id}/report?format=html", headers=analyst_headers)
    assert res_api.status_code == 200
    assert "text/html" in res_api.headers["content-type"]
    assert "SecureMailScope Posture Assessment Report" in res_api.text


def test_missing_or_invalid_api_credentials(client, seeded_case, monkeypatch):
    """
    6. Missing or invalid API credentials are appropriately rejected.
    """
    case_id = seeded_case

    # Missing API credentials on API request (non-browser Accept)
    res_unauth = client.get(f"/cases/{case_id}/report?format=json")
    assert res_unauth.status_code == 401
    assert res_unauth.json()["detail"] == "Missing API key"

    # Invalid API credentials
    res_bad = client.get(f"/cases/{case_id}/report?format=json", headers={"X-API-Key": "completely-invalid"})
    assert res_bad.status_code == 401
    assert res_bad.json()["detail"] == "Invalid analyst API key"

    # Server configuration error when API key not set in environment
    monkeypatch.setattr(config, "ANALYST_API_KEY", "")
    res_misconf = client.get(f"/cases/{case_id}/report?format=json", headers={"X-API-Key": "some-key"})
    assert res_misconf.status_code == 500
    assert "ANALYST_API_KEY is not configured" in res_misconf.json()["detail"]


def test_unauthorized_users_cannot_access_administrative_operations(client, seeded_case):
    """
    7. Unauthorized users and analysts cannot access administrative operations.
    """
    case_id = seeded_case

    # Unauthenticated rejected with 401
    res_unauth = client.post(f"/cases/{case_id}/resolve")
    assert res_unauth.status_code == 401

    # Analyst key rejected on admin endpoint with 403
    res_analyst = client.post(f"/cases/{case_id}/resolve", headers=analyst_headers)
    assert res_analyst.status_code == 403
    assert "Analyst key cannot access admin endpoints" in res_analyst.json()["detail"]

    # Admin key rejected on analyst endpoint with 403
    res_admin = client.get(f"/cases/{case_id}/report?format=json", headers=admin_headers)
    assert res_admin.status_code == 403
    assert "Admin key cannot access analyst endpoints" in res_admin.json()["detail"]


def test_existing_authentication_protections_remain_in_place(client):
    """
    8. Existing authentication protections and RBAC on chain-changing endpoints remain strictly in place.
    """
    # Chain-changing POST endpoints MUST reject unauthenticated requests regardless of Accept headers
    for endpoint in ["open", "claim", "finalize", "record", "anchor"]:
        res_unauth = client.post(
            f"/cases/dummy/{endpoint}",
            headers={"Accept": "text/html"},
        )
        assert res_unauth.status_code == 401, f"{endpoint} allowed unauthenticated access"

        res_admin = client.post(
            f"/cases/dummy/{endpoint}",
            headers=admin_headers,
        )
        assert res_admin.status_code == 403, f"{endpoint} allowed admin access to analyst endpoint"


def test_report_content_and_determinism_preserved(client, seeded_case):
    """
    9. Existing report content and determinism are strictly preserved.
    """
    case_id = seeded_case

    res1 = client.get(f"/cases/{case_id}/report?format=json", headers=analyst_headers)
    assert res1.status_code == 200
    bytes1 = res1.content

    res2 = client.get(f"/cases/{case_id}/report?format=json", headers=browser_headers)
    assert res2.status_code == 200
    bytes2 = res2.content

    # Byte-identical outputs across requests and access channels
    assert bytes1 == bytes2
    sha1 = hashlib.sha256(bytes1).hexdigest()
    sha2 = hashlib.sha256(bytes2).hexdigest()
    assert sha1 == sha2
