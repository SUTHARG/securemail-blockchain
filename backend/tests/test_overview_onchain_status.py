"""Regression tests for overview page on-chain status and Record button conditions (Requirement 2).

Verifies:
1. No on-chain ID -> onchain_status is "Not Opened", Record button is NOT rendered.
2. Opened but not finalized -> onchain_status is "Opened", Record button is NOT rendered.
3. Finalized -> onchain_status is "Finalized", Record button IS rendered.
4. RPC unavailable -> displays "Unavailable", does not crash, Record button is NOT rendered.
"""
import uuid
import pytest
from fastapi.testclient import TestClient
from backend.app import app
import backend.config as config
from backend.database import create_case, init_db, update_case_status, set_case_onchain_id
from backend.storage import get_case_dir, write_case_json


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    test_cases_dir = tmp_path / "cases"
    test_cases_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "CASES_DIR", test_cases_dir)
    test_db = tmp_path / "test_overview_status.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    init_db()


def _get_auth_client() -> TestClient:
    client = TestClient(app)
    client.cookies.set("api_key", config.ANALYST_API_KEY)
    client.cookies.set("csrf_token", "test-csrf-token")
    client.headers["X-CSRF-Token"] = "test-csrf-token"
    return client


def _create_analyzed_case(case_id: str):
    create_case(case_id=case_id, pcap_sha256="c" * 64, status="analyzed")
    case_dir = get_case_dir(case_id)
    (case_dir / "pcap.bin").write_bytes(b"dummy")
    write_case_json(case_id, "manifest.json", {"rulesetHash": "0x1", "resultRoot": "0x2"})
    write_case_json(case_id, "result.json", {"resultRoot": "0x2", "score": 95})


def test_overview_no_onchain_id():
    """Case without onchain ID displays 'Not Opened' and no Record button."""
    client = _get_auth_client()
    case_id = uuid.uuid4().hex
    _create_analyzed_case(case_id)

    res = client.get(f"/cases/{case_id}", headers={"Accept": "text/html"})
    assert res.status_code == 200
    assert "Not Opened" in res.text
    # Action form for record must NOT be rendered
    assert f"/cases/{case_id}/action/record" not in res.text


def test_overview_opened_not_finalized(monkeypatch):
    """Case opened but not finalized displays 'Opened' and no Record button."""
    client = _get_auth_client()
    case_id = uuid.uuid4().hex
    _create_analyzed_case(case_id)
    update_case_status(case_id, "opened")
    set_case_onchain_id(case_id, "0x" + "1" * 64)

    class MockGateway:
        def get_chain_status(self, cid):
            return {"caseId": cid, "state": "Opened", "stateName": "Opened"}

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())

    res = client.get(f"/cases/{case_id}", headers={"Accept": "text/html"})
    assert res.status_code == 200
    assert "Opened" in res.text
    assert f"/cases/{case_id}/action/record" not in res.text


def test_overview_finalized_shows_record_button(monkeypatch):
    """Case finalized on-chain displays 'Finalized' and renders the Record button."""
    client = _get_auth_client()
    case_id = uuid.uuid4().hex
    _create_analyzed_case(case_id)
    update_case_status(case_id, "finalized")
    set_case_onchain_id(case_id, "0x" + "2" * 64)

    class MockGateway:
        def get_chain_status(self, cid):
            return {"caseId": cid, "state": "Finalized", "stateName": "Finalized"}

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())

    res = client.get(f"/cases/{case_id}", headers={"Accept": "text/html"})
    assert res.status_code == 200
    assert "Finalized" in res.text
    # Record button must be rendered
    assert f"/cases/{case_id}/action/record" in res.text


def test_overview_rpc_unavailable(monkeypatch):
    """When RPC is unavailable, overview gracefully displays 'Unavailable' and no Record button."""
    client = _get_auth_client()
    case_id = uuid.uuid4().hex
    _create_analyzed_case(case_id)
    update_case_status(case_id, "opened")
    set_case_onchain_id(case_id, "0x" + "3" * 64)

    class FailingGateway:
        def get_chain_status(self, cid):
            raise ConnectionError("RPC unreachable")

    monkeypatch.setattr("backend.app.get_gateway", lambda: FailingGateway())

    res = client.get(f"/cases/{case_id}", headers={"Accept": "text/html"})
    assert res.status_code == 200
    assert "Unavailable" in res.text
    assert f"/cases/{case_id}/action/record" not in res.text


def test_overview_committing_shows_validate_not_finalize(monkeypatch):
    """When on-chain status is Committing, Finalize button is NOT rendered; Validator Consensus IS rendered."""
    client = _get_auth_client()
    case_id = uuid.uuid4().hex
    _create_analyzed_case(case_id)
    update_case_status(case_id, "distributed")
    set_case_onchain_id(case_id, "0x" + "4" * 64)

    class CommittingGateway:
        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "state": "Committing",
                "stateName": "Committing",
                "canFinalize": False,
                "quorumReached": False,
                "matchingReveals": 0,
                "k": 2,
                "validators": [],
            }

    monkeypatch.setattr("backend.app.get_gateway", lambda: CommittingGateway())

    res = client.get(f"/cases/{case_id}", headers={"Accept": "text/html"})
    assert res.status_code == 200
    assert "Committing" in res.text
    # Finalize form must NOT be rendered
    assert f"/cases/{case_id}/action/finalize" not in res.text
    # Validator consensus button MUST be rendered
    assert f"/cases/{case_id}/action/validate" in res.text
    assert "Finalize Round On-Chain is locked until validator quorum is reached" in res.text


def test_overview_revealing_with_quorum_shows_finalize(monkeypatch):
    """When on-chain status is Revealing and quorum reached, Finalize button IS rendered."""
    client = _get_auth_client()
    case_id = uuid.uuid4().hex
    _create_analyzed_case(case_id)
    update_case_status(case_id, "revealing")
    set_case_onchain_id(case_id, "0x" + "5" * 64)

    class RevealingGateway:
        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "state": "Revealing",
                "stateName": "Revealing",
                "canFinalize": True,
                "quorumReached": True,
                "matchingReveals": 2,
                "k": 2,
                "validators": [],
            }

    monkeypatch.setattr("backend.app.get_gateway", lambda: RevealingGateway())

    res = client.get(f"/cases/{case_id}", headers={"Accept": "text/html"})
    assert res.status_code == 200
    assert "Revealing" in res.text
    # Finalize button MUST be rendered
    assert f"/cases/{case_id}/action/finalize" in res.text
    assert "Quorum Achieved" in res.text


def test_action_finalize_premature_rejection(monkeypatch):
    """Calling finalize prematurely returns an informative error and does not corrupt case status."""
    client = _get_auth_client()
    case_id = uuid.uuid4().hex
    _create_analyzed_case(case_id)
    update_case_status(case_id, "distributed")
    set_case_onchain_id(case_id, "0x" + "6" * 64)

    from backend.chain.gateway import InvalidStateError

    class MockGateway:
        def finalize(self, cid):
            raise InvalidStateError("Cannot finalize round: case is currently in 'committing' state on-chain.")

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())

    res = client.post(
        f"/cases/{case_id}/action/finalize",
        headers={"X-CSRF-Token": "test-csrf-token"},
        follow_redirects=False,
    )
    assert res.status_code == 303
    assert "error=" in res.headers["location"]
    assert "Cannot%20finalize%20round" in res.headers["location"]

    # Verify that local case status was NOT corrupted
    from backend.database import get_case
    c = get_case(case_id)
    assert c["status"] == "distributed"
    assert "reverted:" not in c["status"]


def test_action_validate_consensus(monkeypatch):
    """Calling /action/validate executes validator consensus and redirects with success."""
    client = _get_auth_client()
    case_id = uuid.uuid4().hex
    _create_analyzed_case(case_id)
    update_case_status(case_id, "distributed")
    set_case_onchain_id(case_id, "0x" + "7" * 64)

    class MockGateway:
        def run_validator_round(self, cid):
            return {
                "caseId": cid,
                "round": 1,
                "commits": 3,
                "reveals": 2,
                "quorum": 2,
                "quorumReached": True,
                "status": "revealing",
            }

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())

    res = client.post(
        f"/cases/{case_id}/action/validate",
        headers={"X-CSRF-Token": "test-csrf-token"},
        follow_redirects=False,
    )
    assert res.status_code == 303
    assert "success=" in res.headers["location"]
    assert "Validator%20consensus%20completed" in res.headers["location"]
