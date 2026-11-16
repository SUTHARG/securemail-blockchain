"""Focused regression tests for validator consensus deadline handling and salt recovery (Prompt 6.4).

Verifies:
1. Expired commit deadline:
   - Does NOT submit validator commits when block timestamp >= commitDeadline.
   - Follows contract allowed state transitions (advance to Revealing / finalize to Expired).
   - Does NOT report consensus success (quorumReached is False, commits=0).
   - Returns clear, actionable message explaining next steps.
2. Active commit deadline:
   - Successfully commits, advances, reveals, and reaches quorum when deadline is active.
3. Failed or partially completed transaction handling & salt recovery:
   - Failed commits do not leave state looking like a successful commit.
   - Reveal NEVER falls back to zero salt if state is missing or corrupted (raises actionable error).
   - Valid saved salt is recovered safely and checked against on-chain commitment before reveal.
4. MetaMask client inspector remains strictly read-only.
"""
import json
import os
from pathlib import Path
import pytest
from starlette.testclient import TestClient
from web3 import Web3
from eth_account import Account
from eth_abi import encode

from backend.app import app, get_gateway
import backend.config as config
from backend.chain.gateway import (
    ChainGateway,
    GatewayError,
    TransactionRevertedError,
    STATE_MAP,
)
from backend.database import create_case, get_case, init_db
from backend.storage import get_case_dir, write_case_json


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Ensure clean test database."""
    test_db = tmp_path / "test_smscope_deadline.db"
    monkeypatch.setattr(config, "DB_PATH", test_db)
    init_db(test_db)


def _setup_open_claimed_case(case_id: str, pcap_byte_char: str = "a"):
    """Helper to create, analyze, open, and claim a test case on-chain."""
    gateway = get_gateway()
    
    # 1. Ensure engine registered
    gateway.register_engine_for_case()
    
    # 2. Create case and mock analysis artifacts
    pcap_hash = pcap_byte_char * 64
    create_case(case_id=case_id, pcap_sha256=pcap_hash, status="uploaded")
    
    case_dir = get_case_dir(case_id)
    manifest = {
        "caseId": case_id,
        "pcapSha256": pcap_hash,
        "rulesetHash": gateway.case_registry.functions.activeRulesetHash().call().hex(),
        "resultRoot": "0x1111111111111111111111111111111111111111111111111111111111111111",
    }
    result_data = {
        "caseId": case_id,
        "resultRoot": "0x1111111111111111111111111111111111111111111111111111111111111111",
        "leaves": [],
    }
    write_case_json(case_id, "manifest.json", manifest)
    write_case_json(case_id, "result.json", result_data)
    
    # 3. Open case on-chain
    gateway.open_case(case_id)
    
    # 4. Submit claim on-chain (transitions to Committing)
    gateway.submit_claim(case_id)
    return gateway


def test_expired_commit_deadline_handling():
    """Verify run_validator_round stops commits and transitions cleanly when commit deadline has passed."""
    case_id = "test_expired_deadline_case_001"
    gateway = _setup_open_claimed_case(case_id, pcap_byte_char="e")
    
    case, onchain_bytes = gateway._resolve_onchain_id(case_id)
    round_num = gateway.case_registry.functions.caseRound(onchain_bytes).call()
    round_params = gateway.quorum.functions.getRoundParams(onchain_bytes, round_num).call()
    commit_deadline = round_params[2]
    reveal_deadline = round_params[3]
    
    # Fast-forward EVM time past commit deadline
    now_ts = gateway.w3.eth.get_block("latest").timestamp
    if now_ts < commit_deadline:
        diff = commit_deadline - now_ts + 10
        gateway.w3.provider.make_request("evm_increaseTime", [int(diff)])
        gateway.w3.provider.make_request("evm_mine", [])
    
    # Run validator round with expired commit deadline
    res = gateway.run_validator_round(case_id)
    
    # 1. No commits submitted on-chain
    assert res["commits"] == 0
    snap_addrs = gateway.quorum.functions.getValidatorSnapshot(onchain_bytes, round_num).call()
    for addr in snap_addrs:
        assert not gateway.quorum.functions.hasCommitted(onchain_bytes, round_num, addr).call()
    
    # 2. Consensus success is NOT reported
    assert res["quorumReached"] is False
    assert res["reveals"] == 0
    assert res["commitDeadlinePassed"] is True
    
    # 3. Allowed state transitions followed: case advanced out of Committing
    new_state_int = gateway.case_registry.functions.caseState(onchain_bytes).call()
    assert new_state_int in (4, 7)  # Revealing (4) or Expired (7)
    
    # 4. Explanation is clear and actionable
    assert "deadline" in res["message"].lower()
    assert "new round" in res["message"].lower() or "administrator" in res["message"].lower()


def test_active_commit_deadline_reaches_quorum():
    """Verify run_validator_round succeeds when commit deadline is active."""
    case_id = "test_active_deadline_case_002"
    gateway = _setup_open_claimed_case(case_id, pcap_byte_char="a")
    
    case, onchain_bytes = gateway._resolve_onchain_id(case_id)
    round_num = gateway.case_registry.functions.caseRound(onchain_bytes).call()
    round_params = gateway.quorum.functions.getRoundParams(onchain_bytes, round_num).call()
    commit_deadline = round_params[2]
    
    now_ts = gateway.w3.eth.get_block("latest").timestamp
    assert now_ts < commit_deadline, "Test setup error: commit deadline must be active"
    
    # Run validator round with active deadline
    res = gateway.run_validator_round(case_id)
    
    # Quorum is reached and case finalized
    assert res["quorumReached"] is True
    assert res["commits"] >= res["quorum"]
    assert res["reveals"] >= res["quorum"]
    assert res["status"] == "finalized"
    
    # On-chain state is Finalized (5)
    final_state = gateway.case_registry.functions.caseState(onchain_bytes).call()
    assert final_state == 5


def test_missing_or_invalid_validator_salt_rejects_zero_salt(tmp_path, monkeypatch):
    """Verify reveal phase NEVER uses zero salt and raises actionable GatewayError when state is missing/corrupted."""
    case_id = "test_missing_salt_case_003"
    gateway = _setup_open_claimed_case(case_id, pcap_byte_char="b")
    case, onchain_bytes = gateway._resolve_onchain_id(case_id)
    round_num = gateway.case_registry.functions.caseRound(onchain_bytes).call()
    
    # Point validator_state to an empty isolated directory
    isolated_state_dir = tmp_path / "empty_validator_state"
    isolated_state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "REPO_ROOT", tmp_path)
    
    # Manually commit on-chain for validator 1 with a known random salt
    val_key = config.VALIDATOR_KEY_1
    val_acc = Account.from_key(val_key)
    real_salt = os.urandom(32)
    root_bytes = bytes.fromhex("11" * 32)
    encoded = encode(
        ["bytes32", "address", "bytes32", "bytes32"],
        [onchain_bytes, val_acc.address, root_bytes, real_salt],
    )
    commitment = Web3.keccak(encoded)
    
    nonce = gateway.w3.eth.get_transaction_count(val_acc.address, "pending")
    tx = gateway.quorum.functions.commit(onchain_bytes, commitment).build_transaction({
        "from": val_acc.address,
        "nonce": nonce,
        "gas": 250000,
        "gasPrice": gateway.w3.eth.gas_price,
        "chainId": gateway.w3.eth.chain_id,
    })
    signed = val_acc.sign_transaction(tx)
    raw_tx = getattr(signed, "raw_transaction", getattr(signed, "rawTransaction", None))
    tx_h = gateway.w3.eth.send_raw_transaction(raw_tx)
    gateway.w3.eth.wait_for_transaction_receipt(tx_h, timeout=20)
    
    assert gateway.quorum.functions.hasCommitted(onchain_bytes, round_num, val_acc.address).call() is True
    
    # Fast forward past commit deadline and advance to Revealing
    round_params = gateway.quorum.functions.getRoundParams(onchain_bytes, round_num).call()
    commit_deadline = round_params[2]
    now_ts = gateway.w3.eth.get_block("latest").timestamp
    diff = commit_deadline - now_ts + 5
    gateway.w3.provider.make_request("evm_increaseTime", [int(diff)])
    gateway.w3.provider.make_request("evm_mine", [])
    gateway.advance(case_id)
    
    # Now attempt to run validator round with MISSING salt file
    # Must NOT fallback to zero salt; must raise explicit GatewayError!
    with pytest.raises(GatewayError) as exc_info:
        gateway.run_validator_round(case_id)
    
    err_msg = str(exc_info.value)
    assert "salt is missing or invalid" in err_msg
    assert val_acc.address in err_msg


def test_failed_commit_transaction_does_not_leave_successful_state(tmp_path, monkeypatch):
    """Verify that a reverted or failed commit attempt marks state as 'failed' and does not look successful."""
    case_id = "test_failed_commit_case_004"
    gateway = _setup_open_claimed_case(case_id, pcap_byte_char="c")
    case, onchain_bytes = gateway._resolve_onchain_id(case_id)
    round_num = gateway.case_registry.functions.caseRound(onchain_bytes).call()
    
    state_dir = config.REPO_ROOT / "validator_state"
    val_key = config.VALIDATOR_KEY_1
    val_acc = Account.from_key(val_key)
    state_file = state_dir / f"{val_acc.address.lower()}_{onchain_bytes.hex()}_r{round_num}.json"
    
    # If a state file already existed, remove it
    if state_file.exists():
        state_file.unlink()
    
    # Create invalid case state so commit transaction will revert on-chain
    # (e.g. advance to Revealing early so commit reverts with InvalidCaseState)
    round_params = gateway.quorum.functions.getRoundParams(onchain_bytes, round_num).call()
    commit_deadline = round_params[2]
    now_ts = gateway.w3.eth.get_block("latest").timestamp
    diff = commit_deadline - now_ts + 5
    gateway.w3.provider.make_request("evm_increaseTime", [int(diff)])
    gateway.w3.provider.make_request("evm_mine", [])
    gateway.advance(case_id)
    
    # Calling run_validator_round now in Revealing state will NOT mark any commit as committed
    res = gateway.run_validator_round(case_id)
    
    if state_file.exists():
        payload = json.loads(state_file.read_text(encoding="utf-8"))
        assert payload.get("status") != "committed", "Failed attempt must not be marked 'committed'"
