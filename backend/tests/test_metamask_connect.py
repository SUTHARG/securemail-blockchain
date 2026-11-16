"""Tests for MetaMask client-side connection, contract inspector, and wrong-network handling."""
import json
from pathlib import Path
from starlette.testclient import TestClient

import pytest

from backend.app import app
from backend.chain.deployment import get_client_deployment_config, REQUIRED_CONTRACTS
import backend.config as config
from backend.database import create_case, init_db


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Ensure clean test database and dummy case."""
    test_db = tmp_path / "test_smscope.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    init_db(test_db)


def test_client_deployment_config_loader():
    """Verify get_client_deployment_config returns correct chain ID and contract ABIs."""
    cfg = get_client_deployment_config()

    assert cfg["chainId"] == 31337
    assert cfg["network"] == "localhost"
    assert "contracts" in cfg

    for cname in REQUIRED_CONTRACTS:
        assert cname in cfg["contracts"], f"Missing contract {cname}"
        cdata = cfg["contracts"][cname]
        assert "address" in cdata
        assert cdata["address"].startswith("0x")
        assert len(cdata["address"]) == 42
        assert "abi" in cdata
        assert isinstance(cdata["abi"], list)
        assert len(cdata["abi"]) > 0, f"ABI for {cname} is empty"


def test_client_deployment_config_missing_file(tmp_path):
    """Verify graceful fallback when deployment file does not exist."""
    missing_file = tmp_path / "nonexistent.json"
    cfg = get_client_deployment_config(deployment_file=missing_file)

    assert cfg["chainId"] == 31337
    assert cfg["network"] == "localhost"
    for cname in REQUIRED_CONTRACTS:
        assert cname in cfg["contracts"]
        assert cfg["contracts"][cname]["address"] == ""


def test_chain_page_renders_metamask_section():
    """Verify /cases/{case_id}/chain HTML includes MetaMask inspector and contract addresses."""
    case_id = "test_meta_case_001"
    create_case(
        case_id=case_id,
        pcap_sha256="a" * 64,
        status="analyzed",
    )

    client = TestClient(app)
    response = client.get(
        f"/cases/{case_id}/chain",
        headers={"X-API-Key": config.ANALYST_API_KEY, "Accept": "text/html"},
    )

    assert response.status_code == 200
    html = response.text

    # Section 9 Card & UI elements
    assert 'id="metamask-card"' in html
    assert 'id="mm-connect-btn"' in html
    assert 'id="mm-disconnect-btn"' in html
    assert 'id="mm-switch-network-btn"' in html
    assert 'id="mm-status-badge"' in html
    assert 'id="mm-address-display"' in html
    assert 'id="mm-network-display"' in html
    assert 'id="mm-provider-display"' in html
    assert 'id="mm-contracts-table"' in html
    assert 'id="mm-case-table"' in html

    # Configured Contract Addresses
    dep_cfg = get_client_deployment_config()
    for cname, cdata in dep_cfg["contracts"].items():
        assert cname in html
        assert cdata["address"] in html

    # Expected Chain & Read-Only Notice
    assert "31337" in html
    assert "Read-Only Safety Guarantee" in html

    # Client-side configuration payload
    assert 'id="chain-client-config"' in html

    # Local JS scripts only (zero external CDNs)
    assert '<script src="/static/js/ethers.umd.min.js"></script>' in html
    assert '<script src="/static/js/metamask.js"></script>' in html
    assert "cdn.jsdelivr.net" not in html
    assert "cdnjs.cloudflare.com" not in html
    assert "unpkg.com" not in html


def test_chain_config_api_endpoint():
    """Verify /cases/{case_id}/chain/config returns deployment JSON and case details."""
    case_id = "test_meta_case_002"
    create_case(
        case_id=case_id,
        pcap_sha256="b" * 64,
        status="uploaded",
    )

    client = TestClient(app)
    response = client.get(
        f"/cases/{case_id}/chain/config",
        headers={"X-API-Key": config.ANALYST_API_KEY},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["chainId"] == 31337
    assert data["network"] == "localhost"
    assert "contracts" in data
    assert "CaseRegistry" in data["contracts"]
    assert "ValidationQuorum" in data["contracts"]
    assert "PostureLedger" in data["contracts"]
    assert "Roles" in data["contracts"]

    assert "case" in data
    assert data["case"]["caseId"] == case_id
    assert data["case"]["pcapHash"] == "b" * 64


def test_static_dependencies_served_locally():
    """Verify local static assets are served properly via FastAPI with correct content."""
    client = TestClient(app)

    # ethers.umd.min.js
    r_ethers = client.get("/static/js/ethers.umd.min.js")
    assert r_ethers.status_code == 200
    assert len(r_ethers.content) > 100_000
    assert "javascript" in r_ethers.headers.get("content-type", "").lower()

    # metamask.js
    r_mm = client.get("/static/js/metamask.js")
    assert r_mm.status_code == 200
    assert len(r_mm.content) > 1_000
    assert "javascript" in r_mm.headers.get("content-type", "").lower()
    assert b"MetaMaskInspector" in r_mm.content
    assert b"read-only" in r_mm.content.lower()
