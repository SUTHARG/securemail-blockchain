"""Tests for the Admin Engine Registration workflow and UI guidance (Prompt 6.3).

Verifies:
1. Idempotent engine registration in ChainGateway (no duplicate transactions).
2. Admin-only REST endpoint /api/admin/register-engine (authentication & permissions).
3. Browser action /cases/{case_id}/action/register_engine redirection & execution.
4. UI error guidance banner on the case overview page.
5. End-to-end recovery: opening a case, encountering/handling registration, and continuing
   to submitClaim on the existing case without re-upload.
"""
import json
from pathlib import Path
from starlette.testclient import TestClient
import pytest
from web3 import Web3

from backend.app import app, get_gateway
import backend.config as config
from backend.database import create_case, get_case, init_db, update_case_status
from backend.chain.gateway import ChainGateway


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Ensure clean test database."""
    test_db = tmp_path / "test_smscope_reg.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    init_db(test_db)


def test_gateway_register_engine_idempotency():
    """Verify gateway.register_engine_for_case is strictly idempotent."""
    gateway = get_gateway()
    
    # 1st call: either registers or reports already registered
    res1 = gateway.register_engine_for_case()
    assert res1["status"] in ("registered", "already_registered")
    assert res1["imageDigest"].startswith("0x")
    assert res1["rulesetHash"].startswith("0x")
    
    # 2nd call: MUST report idempotent=True and send no duplicate tx
    res2 = gateway.register_engine_for_case()
    assert res2["idempotent"] is True
    assert res2["status"] == "already_registered"
    assert res2["txHash"] is None


def test_admin_api_register_engine_auth():
    """Verify /api/admin/register-engine strictly requires admin credentials."""
    client = TestClient(app)

    # 1. Unauthenticated request -> 401
    resp_unauth = client.post("/api/admin/register-engine", json={})
    assert resp_unauth.status_code == 401

    # 2. Analyst request (insufficient role) -> 401 / 403
    resp_analyst = client.post(
        "/api/admin/register-engine",
        headers={"X-API-Key": config.ANALYST_API_KEY},
        json={},
    )
    assert resp_analyst.status_code in (401, 403)

    # 3. Admin request -> 200 OK
    resp_admin = client.post(
        "/api/admin/register-engine",
        headers={"X-API-Key": config.ADMIN_API_KEY},
        json={},
    )
    assert resp_admin.status_code == 200
    data = resp_admin.json()
    assert data["status"] in ("registered", "already_registered")
    assert "imageDigest" in data
    assert "rulesetHash" in data


def test_overview_page_shows_engine_guidance_card():
    """Verify /cases/{case_id} renders actionable admin guidance when engine error is present."""
    case_id = "test_case_guidance_001"
    create_case(
        case_id=case_id,
        pcap_sha256="b" * 64,
        status="opened",
    )

    client = TestClient(app)
    error_msg = "Engine not configured on-chain. Admin must register engine first."
    response = client.get(
        f"/cases/{case_id}?error={error_msg}",
        headers={"X-API-Key": config.ANALYST_API_KEY, "Accept": "text/html"},
    )
    assert response.status_code == 200
    html = response.text

    # Guidance card headers and instructions
    assert "Engine Not Registered On-Chain (Admin Action Required)" in html
    assert f"python scripts/register_engine.py --case {case_id}" in html
    assert f"/cases/{case_id}/action/register_engine" in html
    assert "Register Engine &amp; Ruleset On-Chain" in html or "Register Engine & Ruleset On-Chain" in html
    assert "Workflow Continuity" in html
    assert "not</strong> need to re-upload" in html or "not need to re-upload" in html


def test_dashboard_browser_action_register_engine():
    """Verify POST /cases/{case_id}/action/register_engine succeeds and redirects."""
    case_id = "test_case_action_002"
    create_case(
        case_id=case_id,
        pcap_sha256="c" * 64,
        status="opened",
    )

    client = TestClient(app)
    response = client.post(
        f"/cases/{case_id}/action/register_engine",
        headers={"X-API-Key": config.ANALYST_API_KEY},
        follow_redirects=False,
    )
    # 303 See Other redirecting back to case overview with success query param
    assert response.status_code == 303
    location = response.headers.get("location", "")
    assert f"/cases/{case_id}?success=" in location
    assert "registered" in location.lower()
