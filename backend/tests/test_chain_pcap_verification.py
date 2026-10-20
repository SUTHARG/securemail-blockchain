"""Regression tests for on-chain PCAP hash reporting and verification (Requirement 1 & 10).

Verifies:
1. Matching PCAP SHA-256 vs on-chain pcapHash -> Step 1 PASS.
2. Mismatching on-chain pcapHash -> Step 1 FAIL.
3. Zero on-chain pcapHash (0x00...00) -> Step 1 FAIL for opened case.
4. Missing / None on-chain pcapHash -> Step 1 PENDING if unopened, FAIL if opened.
5. Report builder reflects correct PASS/FAIL/PENDING statuses.
"""
import hashlib
import uuid
import pytest
from backend.storage import get_case_dir, write_case_json
from backend.database import create_case, init_db, update_case_status, set_case_onchain_id
import backend.config as config
from backend.app import _compute_verifier_steps_and_state
from backend.reports.builder import build_case_report


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path, monkeypatch):
    test_cases_dir = tmp_path / "cases"
    test_cases_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "CASES_DIR", test_cases_dir)
    test_db = tmp_path / "test_chain_pcap.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    init_db()


def _setup_case_with_pcap(case_id: str, pcap_content: bytes = b"test-pcap-data"):
    pcap_sha = hashlib.sha256(pcap_content).hexdigest()
    create_case(case_id=case_id, pcap_sha256=pcap_sha, status="analyzed")
    case_dir = get_case_dir(case_id)
    # Write encrypted at rest PCAP
    from validator.crypto import encrypt_at_rest
    (case_dir / "pcap.bin").write_bytes(encrypt_at_rest(pcap_content))
    write_case_json(case_id, "manifest.json", {"rulesetHash": "0x1111", "resultRoot": "0x2222"})
    write_case_json(case_id, "result.json", {"resultRoot": "0x2222", "score": 90})
    write_case_json(case_id, "findings.json", [])
    write_case_json(case_id, "host_scores.json", [])
    return pcap_sha


def test_unopened_case_pcap_hash_reporting(monkeypatch):
    """Unopened case has None onchain_case_id; reports PENDING, not FAIL."""
    case_id = uuid.uuid4().hex
    _setup_case_with_pcap(case_id)

    steps, chain_info, validators, txs, passed = _compute_verifier_steps_and_state(case_id)
    step1 = steps[0]
    assert step1["step"] == 1
    assert step1["status"] == "PENDING"
    assert "not yet opened" in step1["details"].lower()
    assert passed is False

    rep, _, _, _ = build_case_report(case_id)
    assert rep["verifierSteps"][0]["status"] == "PENDING"


def test_opened_case_matching_pcap_hash(monkeypatch):
    """Opened case with matching on-chain pcapHash passes Step 1."""
    case_id = uuid.uuid4().hex
    pcap_sha = _setup_case_with_pcap(case_id)
    onchain_id = "0x" + "a" * 64
    update_case_status(case_id=case_id, status="opened")
    set_case_onchain_id(case_id=case_id, onchain_case_id=onchain_id)

    class MockGateway:
        def poll_events(self):
            pass
        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "state": "Opened",
                "stateName": "Opened",
                "pcapHash": "0x" + pcap_sha,
                "finalRoot": "0x" + "0" * 64,
                "reportHash": None,
                "validators": [],
            }
        posture_ledger = None

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())

    steps, chain_info, validators, txs, passed = _compute_verifier_steps_and_state(case_id)
    step1 = steps[0]
    assert step1["step"] == 1
    assert step1["status"] == "PASS"
    assert "matches on-chain" in step1["details"].lower()

    rep, _, _, _ = build_case_report(case_id)
    assert rep["verifierSteps"][0]["status"] == "PASS"


def test_opened_case_mismatching_pcap_hash(monkeypatch):
    """Opened case with mismatching on-chain pcapHash fails Step 1."""
    case_id = uuid.uuid4().hex
    pcap_sha = _setup_case_with_pcap(case_id)
    onchain_id = "0x" + "a" * 64
    update_case_status(case_id=case_id, status="opened")
    set_case_onchain_id(case_id=case_id, onchain_case_id=onchain_id)

    different_hash = "0x" + "f" * 64

    class MockGateway:
        def poll_events(self):
            pass
        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "state": "Opened",
                "stateName": "Opened",
                "pcapHash": different_hash,
                "finalRoot": "0x" + "0" * 64,
                "reportHash": None,
                "validators": [],
            }
        posture_ledger = None

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())

    steps, chain_info, validators, txs, passed = _compute_verifier_steps_and_state(case_id)
    step1 = steps[0]
    assert step1["step"] == 1
    assert step1["status"] == "FAIL"
    assert "does not match" in step1["details"].lower()

    rep, _, _, _ = build_case_report(case_id)
    assert rep["verifierSteps"][0]["status"] == "FAIL"


def test_opened_case_zero_pcap_hash(monkeypatch):
    """Opened case with zero on-chain pcapHash (0x00...00) must FAIL Step 1, never PASS."""
    case_id = uuid.uuid4().hex
    _setup_case_with_pcap(case_id)
    onchain_id = "0x" + "a" * 64
    update_case_status(case_id=case_id, status="opened")
    set_case_onchain_id(case_id=case_id, onchain_case_id=onchain_id)

    zero_hash = "0x" + "0" * 64

    class MockGateway:
        def poll_events(self):
            pass
        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "state": "Opened",
                "stateName": "Opened",
                "pcapHash": zero_hash,
                "finalRoot": "0x" + "0" * 64,
                "reportHash": None,
                "validators": [],
            }
        posture_ledger = None

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())

    steps, chain_info, validators, txs, passed = _compute_verifier_steps_and_state(case_id)
    step1 = steps[0]
    assert step1["step"] == 1
    assert step1["status"] == "FAIL"
    assert "missing or zero" in step1["details"].lower()

    rep, _, _, _ = build_case_report(case_id)
    assert rep["verifierSteps"][0]["status"] == "FAIL"


def test_opened_case_missing_pcap_hash(monkeypatch):
    """Opened case with missing (None/empty) on-chain pcapHash must FAIL Step 1."""
    case_id = uuid.uuid4().hex
    _setup_case_with_pcap(case_id)
    onchain_id = "0x" + "a" * 64
    update_case_status(case_id=case_id, status="opened")
    set_case_onchain_id(case_id=case_id, onchain_case_id=onchain_id)

    class MockGateway:
        def poll_events(self):
            pass
        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "state": "Opened",
                "stateName": "Opened",
                "pcapHash": None,
                "finalRoot": "0x" + "0" * 64,
                "reportHash": None,
                "validators": [],
            }
        posture_ledger = None

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())

    steps, chain_info, validators, txs, passed = _compute_verifier_steps_and_state(case_id)
    step1 = steps[0]
    assert step1["step"] == 1
    assert step1["status"] == "FAIL"
    assert "missing or zero" in step1["details"].lower()


def test_decryption_failure_never_accepts_encrypted_bytes_as_pcap_hash(monkeypatch):
    """Encrypted bytes must never be accepted as the PCAP hash when decryption fails."""
    case_id = uuid.uuid4().hex
    ciphertext = b"malformed-or-corrupted-ciphertext-12345"
    cipher_sha = hashlib.sha256(ciphertext).hexdigest()

    create_case(case_id=case_id, pcap_sha256=cipher_sha, status="opened")
    onchain_id = "0x" + "a" * 64
    set_case_onchain_id(case_id=case_id, onchain_case_id=onchain_id)

    case_dir = get_case_dir(case_id)
    # Write raw bytes that will fail decryption with InvalidSignature / InvalidTag
    (case_dir / "pcap.bin").write_bytes(ciphertext)
    write_case_json(case_id, "manifest.json", {"rulesetHash": "0x1111", "resultRoot": "0x2222", "pcapSha256": cipher_sha})
    write_case_json(case_id, "result.json", {"resultRoot": "0x2222", "score": 90})
    write_case_json(case_id, "findings.json", [])
    write_case_json(case_id, "host_scores.json", [])

    class MockGateway:
        def poll_events(self):
            pass
        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "state": "Opened",
                "stateName": "Opened",
                "pcapHash": "0x" + cipher_sha,
                "finalRoot": "0x" + "0" * 64,
                "reportHash": None,
                "validators": [],
            }
        posture_ledger = None

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())

    # In _compute_verifier_steps_and_state: must FAIL, never PASS
    steps, _, _, _, passed = _compute_verifier_steps_and_state(case_id)
    step1 = steps[0]
    assert step1["step"] == 1
    assert step1["status"] == "FAIL"
    assert "decryption failed" in step1["details"].lower()
    assert passed is False

    # In report builder: must FAIL, and report payload must not treat ciphertext hash as actual_pcap_sha
    rep, _, _, _ = build_case_report(case_id)
    assert rep["verifierSteps"][0]["status"] == "FAIL"
    assert "decryption failed" in rep["verifierSteps"][0]["details"].lower()


def test_missing_pcap_file_fails_closed(monkeypatch):
    """Missing pcap.bin on disk must FAIL step 1 with clear reason."""
    case_id = uuid.uuid4().hex
    pcap_sha = "abcd" * 16
    create_case(case_id=case_id, pcap_sha256=pcap_sha, status="opened")
    onchain_id = "0x" + "a" * 64
    set_case_onchain_id(case_id=case_id, onchain_case_id=onchain_id)

    case_dir = get_case_dir(case_id)
    pcap_file = case_dir / "pcap.bin"
    if pcap_file.exists():
        pcap_file.unlink()

    write_case_json(case_id, "manifest.json", {"rulesetHash": "0x1111", "resultRoot": "0x2222", "pcapSha256": pcap_sha})
    write_case_json(case_id, "result.json", {"resultRoot": "0x2222", "score": 90})
    write_case_json(case_id, "findings.json", [])
    write_case_json(case_id, "host_scores.json", [])

    class MockGateway:
        def poll_events(self):
            pass
        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "state": "Opened",
                "stateName": "Opened",
                "pcapHash": "0x" + pcap_sha,
                "finalRoot": "0x" + "0" * 64,
                "reportHash": None,
                "validators": [],
            }
        posture_ledger = None

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())

    steps, _, _, _, _ = _compute_verifier_steps_and_state(case_id)
    assert steps[0]["status"] == "FAIL"
    assert "missing on disk" in steps[0]["details"].lower()

    rep, _, _, _ = build_case_report(case_id)
    assert rep["verifierSteps"][0]["status"] == "FAIL"
    assert "missing on disk" in rep["verifierSteps"][0]["details"].lower()


def test_corrupted_pcap_bytes_fails_step1(monkeypatch):
    """If PCAP ciphertext/bytes are corrupted on disk, step 1 must FAIL."""
    case_id = uuid.uuid4().hex
    pcap_sha = _setup_case_with_pcap(case_id, b"original-content")
    onchain_id = "0x" + "a" * 64
    update_case_status(case_id=case_id, status="opened")
    set_case_onchain_id(case_id=case_id, onchain_case_id=onchain_id)

    # Corrupt the pcap.bin by overwriting with invalid bytes
    case_dir = get_case_dir(case_id)
    (case_dir / "pcap.bin").write_bytes(b"corrupted-invalid-bytes")

    class MockGateway:
        def poll_events(self):
            pass
        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "state": "Opened",
                "stateName": "Opened",
                "pcapHash": "0x" + pcap_sha,
                "finalRoot": "0x" + "0" * 64,
                "reportHash": None,
                "validators": [],
            }
        posture_ledger = None

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())

    steps, _, _, _, passed = _compute_verifier_steps_and_state(case_id)
    assert steps[0]["status"] == "FAIL"
    assert passed is False


def test_database_hash_mismatch_fails_step1(monkeypatch):
    """If DB pcap_sha256 was altered and does not match decrypted bytes, step 1 must FAIL."""
    case_id = uuid.uuid4().hex
    actual_sha = _setup_case_with_pcap(case_id, b"real-content")
    # Tamper database with a different hash
    from backend.database import get_connection
    with get_connection() as conn:
        conn.execute("UPDATE cases SET pcap_sha256 = ? WHERE id = ?", ("e" * 64, case_id))

    onchain_id = "0x" + "a" * 64
    update_case_status(case_id=case_id, status="opened")
    set_case_onchain_id(case_id=case_id, onchain_case_id=onchain_id)

    class MockGateway:
        def poll_events(self):
            pass
        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "state": "Opened",
                "stateName": "Opened",
                "pcapHash": "0x" + actual_sha,
                "finalRoot": "0x" + "0" * 64,
                "reportHash": None,
                "validators": [],
            }
        posture_ledger = None

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())

    steps, _, _, _, passed = _compute_verifier_steps_and_state(case_id)
    assert steps[0]["status"] == "FAIL"
    assert "does not match stored case record" in steps[0]["details"].lower()
    assert passed is False


def test_missing_report_file_when_anchored_fails_step5(monkeypatch):
    """When report is anchored on chain but report.json is missing locally, step 5 must FAIL."""
    case_id = uuid.uuid4().hex
    pcap_sha = _setup_case_with_pcap(case_id)
    onchain_id = "0x" + "a" * 64
    update_case_status(case_id=case_id, status="Finalized")
    set_case_onchain_id(case_id=case_id, onchain_case_id=onchain_id)

    case_dir = get_case_dir(case_id)
    rep_file = case_dir / "report.json"
    if rep_file.exists():
        rep_file.unlink()

    class MockGateway:
        def poll_events(self):
            pass
        def get_chain_status(self, cid):
            return {
                "caseId": cid,
                "state": "Finalized",
                "stateName": "Finalized",
                "pcapHash": "0x" + pcap_sha,
                "finalRoot": "0x2222",
                "reportHash": "0x" + "c" * 64,
                "validators": [],
            }
        posture_ledger = None

    monkeypatch.setattr("backend.app.get_gateway", lambda: MockGateway())

    steps, _, _, _, passed = _compute_verifier_steps_and_state(case_id)
    assert steps[4]["step"] == 5
    assert steps[4]["status"] == "FAIL"
    assert "missing locally" in steps[4]["details"].lower()
    assert passed is False


def test_unavailable_chain_raises_503(monkeypatch):
    """When blockchain gateway raises connection error, get_case_chain_state raises HTTP 503."""
    from fastapi import HTTPException
    from backend.app import get_case_chain_state
    from unittest.mock import AsyncMock

    case_id = uuid.uuid4().hex
    _setup_case_with_pcap(case_id)
    set_case_onchain_id(case_id, "0x" + "a" * 64)

    def mock_get_gw():
        raise ConnectionError("Failed to establish a new connection: [WinError 10061] No connection could be made")

    monkeypatch.setattr("backend.app.get_gateway", mock_get_gw)

    mock_req = AsyncMock()
    mock_req.headers = {"accept": "application/json"}

    import asyncio
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(get_case_chain_state(case_id, mock_req, actor="analyst"))

    assert exc_info.value.status_code == 503
    assert "unavailable" in exc_info.value.detail.lower()
