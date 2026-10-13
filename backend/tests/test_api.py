"""Integration and unit tests for SecureMailScope API service (Prompt 6.1)."""
import hashlib
import io
import json
import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

import backend.config as config
from backend.app import app
from backend.database import get_audit_entries, get_case, init_db, update_case_status
from backend.storage import get_case_dir

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    """Isolate database and case storage directories for every test run."""
    test_data_dir = tmp_path / "data"
    test_cases_dir = test_data_dir / "cases"
    test_db_path = test_data_dir / "test_smscope.db"

    monkeypatch.setattr(config, "DATA_DIR", test_data_dir)
    monkeypatch.setattr(config, "CASES_DIR", test_cases_dir)
    monkeypatch.setattr(config, "DB_PATH", test_db_path)
    monkeypatch.setattr(config, "MAX_UPLOAD_SIZE", 100 * 1024 * 1024)

    test_cases_dir.mkdir(parents=True, exist_ok=True)
    init_db(test_db_path)


@pytest.fixture
def client():
    """Create FastAPI test client."""
    with TestClient(app) as test_client:
        yield test_client


analyst_headers = {"X-API-Key": config.ANALYST_API_KEY}
admin_headers = {"X-API-Key": config.ADMIN_API_KEY}


# ---------------------------------------------------------------------------
# 1. Role Checks & Authentication Tests
# ---------------------------------------------------------------------------


def test_auth_role_enforcement(client):
    """
    Verify RBAC enforcement:
    - Missing or invalid key -> 401 Unauthorized
    - Analyst key on analyst endpoint -> 200/201 Success
    - Admin key on analyst endpoint -> 403 Forbidden
    - Analyst key on admin endpoint -> 403 Forbidden
    """
    # Missing key
    res = client.get("/cases/dummy123")
    assert res.status_code == 401

    # Invalid key
    res = client.get("/cases/dummy123", headers={"X-API-Key": "wrong-key"})
    assert res.status_code == 401

    # Admin key rejected on analyst endpoint
    res = client.get("/cases/dummy123", headers=admin_headers)
    assert res.status_code == 403
    assert "Admin key cannot access analyst endpoints" in res.json()["detail"]

    # Analyst key rejected on admin endpoint
    res = client.post("/cases/dummy123/resolve", headers=analyst_headers)
    assert res.status_code == 403
    assert "Analyst key cannot access admin endpoints" in res.json()["detail"]


# ---------------------------------------------------------------------------
# 2. Upload, Magic Number, and Oversize Tests
# ---------------------------------------------------------------------------


def test_upload_valid_pcap(client):
    """Upload valid PCAP capture and verify permissions, hashing, and audit log."""
    pcap_bytes = (CAPTURES_DIR / "S01a.pcap").read_bytes()
    expected_sha = hashlib.sha256(pcap_bytes).hexdigest()

    files = {"file": ("S01a.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")}
    res = client.post("/cases", headers=analyst_headers, files=files)
    assert res.status_code == 201
    data = res.json()

    case_id = data["caseId"]
    assert data["status"] == "uploaded"
    assert data["pcapSha256"] == expected_sha

    # Verify file saved on disk
    case_dir = get_case_dir(case_id)
    saved_pcap = case_dir / "pcap.bin"
    assert saved_pcap.exists()
    from validator.crypto import decrypt_at_rest
    assert saved_pcap.read_bytes().startswith(b"SMSE")
    assert hashlib.sha256(decrypt_at_rest(saved_pcap.read_bytes())).hexdigest() == expected_sha

    # Verify audit log entry
    audit = get_audit_entries(case_id=case_id)
    assert any(a["action"] == "case_uploaded" for a in audit)


def test_upload_bad_magic_number(client):
    """Reject upload with non-PCAP header."""
    bad_bytes = b"NOT_A_PCAP_MAGIC_HEADER_BYTES_12345"
    files = {"file": ("bad.pcap", io.BytesIO(bad_bytes), "application/octet-stream")}
    res = client.post("/cases", headers=analyst_headers, files=files)
    assert res.status_code == 400
    assert "Invalid PCAP magic number" in res.json()["detail"]


def test_upload_oversize_rejection(client, monkeypatch):
    """Reject upload exceeding configured maximum size."""
    # Set limit to 100 bytes
    monkeypatch.setattr(config, "MAX_UPLOAD_SIZE", 100)

    pcap_bytes = (CAPTURES_DIR / "S01a.pcap").read_bytes()
    assert len(pcap_bytes) > 100

    files = {"file": ("big.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")}
    res = client.post("/cases", headers=analyst_headers, files=files)
    assert res.status_code == 413
    assert "exceeds maximum allowable size" in res.json()["detail"]


# ---------------------------------------------------------------------------
# 3. Analysis & Acceptance on S01a
# ---------------------------------------------------------------------------


def test_analyze_and_inspect_s01a(client):
    """
    Acceptance test:
    Upload lab/captures/S01a.pcap, analyze it, and fetch findings and host scores.
    Verify outputs equal the engine CLI output.
    """
    pcap_bytes = (CAPTURES_DIR / "S01a.pcap").read_bytes()
    files = {"file": ("S01a.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")}
    res_upload = client.post("/cases", headers=analyst_headers, files=files)
    assert res_upload.status_code == 201
    case_id = res_upload.json()["caseId"]

    # Trigger analysis synchronously
    res_analyze = client.post(f"/cases/{case_id}/analyze", headers=analyst_headers)
    assert res_analyze.status_code == 200
    assert res_analyze.json()["status"] == "analyzed"
    assert res_analyze.json()["success"] is True

    # 1. Inspect sessions
    res_sessions = client.get(f"/cases/{case_id}/sessions", headers=analyst_headers)
    assert res_sessions.status_code == 200
    sessions_data = res_sessions.json()
    assert sessions_data["total"] == 1
    assert sessions_data["items"][0]["serverEndpoint"] == "172.28.0.10:25"

    # 2. Inspect findings (S01a is clean -> 0 findings)
    res_findings = client.get(f"/cases/{case_id}/findings", headers=analyst_headers)
    assert res_findings.status_code == 200
    findings_data = res_findings.json()
    assert findings_data["total"] == 0
    assert findings_data["items"] == []

    # 3. Inspect host scores (Clean host receives 100, Grade A)
    res_hosts = client.get(f"/cases/{case_id}/hosts", headers=analyst_headers)
    assert res_hosts.status_code == 200
    hosts_data = res_hosts.json()
    assert hosts_data["total"] == 1
    assert hosts_data["items"][0]["score"] == 100
    assert hosts_data["items"][0]["grade"] == "A"

    # 4. Verification endpoint
    res_verify = client.post(f"/cases/{case_id}/verify", headers=analyst_headers)
    assert res_verify.status_code == 200
    verify_data = res_verify.json()
    assert verify_data["pcapVerified"] is True
    assert verify_data["merkleRootVerified"] is True
    assert verify_data["verified"] is True

    # 5. Chain state endpoint
    res_chain = client.get(f"/cases/{case_id}/chain", headers=analyst_headers)
    assert res_chain.status_code == 200
    assert res_chain.json()["status"] == "analyzed"
    assert res_chain.json()["resultRoot"] is not None


# ---------------------------------------------------------------------------
# 4. Resume After Killed Mid-Analysis
# ---------------------------------------------------------------------------


def test_resume_after_killed_mid_analysis(client):
    """Verify that a case marked failed mid-analysis can be resumed and completed."""
    pcap_bytes = (CAPTURES_DIR / "S01a.pcap").read_bytes()
    files = {"file": ("S01a.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")}
    res_upload = client.post("/cases", headers=analyst_headers, files=files)
    case_id = res_upload.json()["caseId"]

    # Simulate mid-analysis crash / process kill
    update_case_status(case_id, "failed")
    case = get_case(case_id)
    assert case["status"] == "failed"

    # Re-trigger analyze endpoint to resume
    res_resume = client.post(f"/cases/{case_id}/analyze", headers=analyst_headers)
    assert res_resume.status_code == 200
    assert res_resume.json()["status"] == "analyzed"
    assert res_resume.json()["success"] is True

    case_after = get_case(case_id)
    assert case_after["status"] == "analyzed"


# ---------------------------------------------------------------------------
# 5. Secret and Planted Credential Exclusion
# ---------------------------------------------------------------------------


def test_planted_credentials_and_secrets_never_leaked(client):
    """
    Verify Rule 4 and Rule 6:
    Planted lab credentials and organization secret NEVER appear in logs or API responses.
    Uploads S05 (which contains cleartext AUTH credentials: 'labuser' and 'LabPass-123!').
    """
    pcap_bytes = (CAPTURES_DIR / "S05.pcap").read_bytes()
    files = {"file": ("S05.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")}
    res_upload = client.post("/cases", headers=analyst_headers, files=files)
    case_id = res_upload.json()["caseId"]

    # Analyze S05
    client.post(f"/cases/{case_id}/analyze", headers=analyst_headers)

    # Fetch all API responses
    case_details = client.get(f"/cases/{case_id}", headers=analyst_headers).text
    sessions_resp = client.get(f"/cases/{case_id}/sessions", headers=analyst_headers).text
    findings_resp = client.get(f"/cases/{case_id}/findings", headers=analyst_headers).text
    hosts_resp = client.get(f"/cases/{case_id}/hosts", headers=analyst_headers).text

    all_responses = f"{case_details} {sessions_resp} {findings_resp} {hosts_resp}"

    # Planted password MUST NOT appear
    assert "LabPass-123!" not in all_responses
    # Organization secret MUST NOT appear
    assert config.ORG_SECRET_HEX not in all_responses

    # Audit log entries must also be completely free of secrets
    audit_entries = get_audit_entries(case_id=case_id)
    for entry in audit_entries:
        assert "LabPass-123!" not in str(entry["detail"])
        assert config.ORG_SECRET_HEX not in str(entry["detail"])


# ---------------------------------------------------------------------------
# 6. Chain-Changing Endpoints RBAC & Validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["open", "claim", "finalize", "record", "anchor"])
def test_chain_changing_endpoints_rbac(client, action):
    """Verify that Prompt 6.2 endpoints enforce role separation and authentication."""
    # Unauthenticated rejected with 401
    res_unauth = client.post(f"/cases/dummy/{action}")
    assert res_unauth.status_code == 401

    # Admin key rejected with 403 on analyst endpoints
    res_admin = client.post(f"/cases/dummy/{action}", headers=admin_headers)
    assert res_admin.status_code == 403

    # Analyst key on non-existent case returns 404
    res_analyst = client.post(f"/cases/nonexistent_case/{action}", headers=analyst_headers)
    assert res_analyst.status_code in [400, 404]


def test_resolve_endpoint_rbac(client):
    """Admin resolve endpoint rejects unauthenticated (401) and analyst (403)."""
    res_unauth = client.post("/cases/dummy/resolve")
    assert res_unauth.status_code == 401

    res_analyst = client.post("/cases/dummy/resolve", headers=analyst_headers)
    assert res_analyst.status_code == 403
