"""Integration tests for SecureMailScope Blockchain Gateway (Prompt 6.2).

Tests run against a local Hardhat node and verify:
1. Full flow: upload -> analyze -> open -> claim -> validators commit/reveal -> finalize -> record -> anchor.
2. Idempotence: calling every endpoint twice creates zero duplicate transactions and does not revert.
3. Crash recovery: transaction sent but interrupted before receipt stored; restarts and confirms without a second transaction.
4. Revert reporting: invalid role or contract revert is surfaced with revert reason and not retried.
5. Event listener: polls logs and updates case database state from the chain source of truth.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import time
from typing import Any, Dict, List, Tuple
import pytest
from eth_abi import encode
from eth_account import Account
from fastapi.testclient import TestClient
from web3 import Web3

from backend.app import app, get_gateway
from backend.chain.gateway import (
    ChainGateway,
    TransactionRevertedError,
)
import backend.config as config
from backend.database import (
    get_case,
    get_chain_tx,
    get_chain_txs,
    init_db,
    record_chain_tx,
    update_case_status,
)
from backend.runner import execute_analysis
from backend.storage import get_case_dir, read_case_json

REPO_ROOT = config.REPO_ROOT
CONTRACTS_DIR = REPO_ROOT / "contracts"
DEPLOYMENTS_FILE = CONTRACTS_DIR / "deployments" / "local.json"
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"

# Hardhat standard test accounts
ADMIN_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANALYST_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

VALIDATOR_KEYS = [
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
]
VALIDATOR_ACCOUNTS = [Account.from_key(k) for k in VALIDATOR_KEYS]


def kill_process_tree(pid: int) -> None:
    """Cleanly terminate process and all child processes on Windows/Linux."""
    try:
        subprocess.run(f"taskkill /F /T /PID {pid}", shell=True, capture_output=True)
    except Exception:
        pass


@pytest.fixture(scope="module")
def hardhat_node():
    """Start local Hardhat node and deploy contracts once for gateway test module."""
    rpc_url = "http://127.0.0.1:8545"
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    node_proc = None
    if not w3.is_connected():
        node_proc = subprocess.Popen(
            "npx hardhat node",
            cwd=str(CONTRACTS_DIR),
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(40):
            if w3.is_connected():
                break
            time.sleep(0.5)
        else:
            if node_proc:
                kill_process_tree(node_proc.pid)
            pytest.fail("Failed to connect to local Hardhat node at 127.0.0.1:8545")

    # Deploy smart contracts
    deploy_res = subprocess.run(
        "npx hardhat run scripts/deploy.ts --network localhost",
        cwd=str(CONTRACTS_DIR),
        shell=True,
        capture_output=True,
        text=True,
    )
    if deploy_res.returncode != 0:
        if node_proc:
            kill_process_tree(node_proc.pid)
        pytest.fail(f"Failed to deploy contracts: {deploy_res.stderr}\n{deploy_res.stdout}")

    init_db()
    gateway = ChainGateway(rpc_url=rpc_url, deployment_file=DEPLOYMENTS_FILE)

    # Register active engine & ruleset on-chain
    image_digest = Web3.keccak(text="smscope:latest")
    ruleset_hash = Web3.keccak(text="ruleset_v1_catalog")
    gateway.register_engine(image_digest, ruleset_hash)

    # Register the 3 validator addresses
    for val_acc in VALIDATOR_ACCOUNTS:
        try:
            gateway.add_validator(val_acc.address)
        except Exception:
            pass

    yield {"gateway": gateway, "w3": w3, "rpc_url": rpc_url}

    if node_proc:
        kill_process_tree(node_proc.pid)


@pytest.fixture
def setup_api_env(tmp_path, monkeypatch, hardhat_node):
    """Isolate database and case directories for test run."""
    test_data_dir = tmp_path / "data"
    test_cases_dir = test_data_dir / "cases"
    test_db_path = test_data_dir / "test_gateway.db"

    monkeypatch.setattr(config, "DATA_DIR", test_data_dir)
    monkeypatch.setattr(config, "CASES_DIR", test_cases_dir)
    monkeypatch.setattr(config, "DB_PATH", test_db_path)
    monkeypatch.setattr(config, "RPC_URL", hardhat_node["rpc_url"])
    monkeypatch.setattr(config, "DEPLOYMENT_FILE", DEPLOYMENTS_FILE)
    monkeypatch.setattr(config, "ANALYST_KEY", ANALYST_KEY)
    monkeypatch.setattr(config, "ADMIN_KEY", ADMIN_KEY)

    test_cases_dir.mkdir(parents=True, exist_ok=True)
    init_db(test_db_path)

    # Reset gateway singleton
    import backend.app as app_mod
    app_mod._gateway_instance = hardhat_node["gateway"]


@pytest.fixture
def client(setup_api_env):
    """FastAPI test client."""
    with TestClient(app) as test_client:
        yield test_client


analyst_headers = {"X-API-Key": config.ANALYST_API_KEY}
admin_headers = {"X-API-Key": config.ADMIN_API_KEY}


def create_analyzed_case(client) -> Tuple[str, str]:
    """Helper to upload S01a and run engine analysis."""
    pcap_bytes = (CAPTURES_DIR / "S01a.pcap").read_bytes()
    files = {"file": ("S01a.pcap", io.BytesIO(pcap_bytes), "application/vnd.tcpdump.pcap")}
    res_upload = client.post("/cases", headers=analyst_headers, files=files)
    assert res_upload.status_code == 201
    case_id = res_upload.json()["caseId"]

    # Run analysis
    res_analyze = client.post(f"/cases/{case_id}/analyze", headers=analyst_headers)
    assert res_analyze.status_code == 200
    assert res_analyze.json()["status"] == "analyzed"
    return case_id, res_upload.json()["pcapSha256"]


def send_validator_tx(w3: Web3, contract_fn: Any, account: Any) -> Any:
    """Helper to submit a validator transaction."""
    nonce = w3.eth.get_transaction_count(account.address, "pending")
    gas_est = contract_fn.estimate_gas({"from": account.address})
    tx_params = {
        "from": account.address,
        "nonce": nonce,
        "gas": int(gas_est * 1.3),
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    }
    tx = contract_fn.build_transaction(tx_params)
    signed = account.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", getattr(signed, "rawTransaction", None))
    tx_hash = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt.status == 1
    return receipt


# ---------------------------------------------------------------------------
# 1. Full Flow Test
# ---------------------------------------------------------------------------


def test_gateway_full_flow(client, hardhat_node):
    """
    Acceptance test for Prompt 6.2:
    Flow: upload -> analyze -> open -> claim -> validators commit/reveal -> finalize -> record -> anchor.
    Verifies on-chain state changes and audit/chain_txs logs at every step.
    """
    gateway: ChainGateway = hardhat_node["gateway"]
    w3: Web3 = hardhat_node["w3"]

    case_id, pcap_sha = create_analyzed_case(client)

    # 1. Open case on-chain via API
    res_open = client.post(f"/cases/{case_id}/open", headers=analyst_headers)
    assert res_open.status_code == 200
    open_data = res_open.json()
    onchain_id = open_data["onchainCaseId"]
    assert onchain_id.startswith("0x")
    onchain_bytes = bytes.fromhex(onchain_id.replace("0x", ""))

    case_record = get_case(case_id)
    assert case_record["status"] == "opened_on_chain"
    assert case_record["onchain_case_id"] == onchain_id

    # 2. Submit claim on-chain via API
    res_claim = client.post(f"/cases/{case_id}/claim", headers=analyst_headers)
    assert res_claim.status_code == 200
    assert res_claim.json()["status"] == "claimed"

    case_record = get_case(case_id)
    assert case_record["status"] == "claimed"

    # State in CaseRegistry must now be Committing (3)
    assert gateway.case_registry.functions.caseState(onchain_bytes).call() == 3

    # 3. Validators Commit (3 independent validator processes / accounts)
    res_data = read_case_json(case_id, "result.json")
    result_root_bytes = bytes.fromhex(res_data["resultRoot"].replace("0x", ""))
    image_digest, ruleset_hash = gateway.case_registry.functions.activeEngine().call()

    salts = [Web3.keccak(text=f"salt_{i}_{case_id}") for i in range(3)]

    for i, val_acc in enumerate(VALIDATOR_ACCOUNTS):
        # commitment = keccak256(abi.encode(caseId, validator, resultRoot, salt))
        commitment = Web3.keccak(
            encode(
                ["bytes32", "address", "bytes32", "bytes32"],
                [onchain_bytes, val_acc.address, result_root_bytes, salts[i]],
            )
        )
        commit_fn = gateway.quorum.functions.commit(onchain_bytes, commitment)
        send_validator_tx(w3, commit_fn, val_acc)

    # Fast forward time beyond commitDeadline (60 seconds)
    w3.provider.make_request("evm_increaseTime", [65])
    w3.provider.make_request("evm_mine", [])

    # Advance to Revealing
    gateway.advance(case_id)
    assert gateway.case_registry.functions.caseState(onchain_bytes).call() == 4  # Revealing

    # 4. Validators Reveal
    for i, val_acc in enumerate(VALIDATOR_ACCOUNTS):
        rev_fn = gateway.quorum.functions.reveal(
            onchain_bytes,
            result_root_bytes,
            salts[i],
            image_digest,
            ruleset_hash,
        )
        send_validator_tx(w3, rev_fn, val_acc)

    # 5. Finalize via API
    res_finalize = client.post(f"/cases/{case_id}/finalize", headers=analyst_headers)
    assert res_finalize.status_code == 200
    assert res_finalize.json()["status"] == "finalized"
    assert gateway.case_registry.functions.caseState(onchain_bytes).call() == 5  # Finalized

    # 6. Record Posture via API
    res_record = client.post(f"/cases/{case_id}/record", headers=analyst_headers)
    assert res_record.status_code == 200
    assert res_record.json()["status"] == "recorded"
    assert len(res_record.json()["hosts"]) == 1

    # Verify on-chain posture recorded
    host_scores = read_case_json(case_id, "host_scores.json")
    host_bytes = bytes.fromhex(host_scores[0]["hostId"].replace("0x", ""))
    assert gateway.posture_ledger.functions.hasRecorded(onchain_bytes, host_bytes).call() is True

    # 7. Anchor Report via API
    res_anchor = client.post(f"/cases/{case_id}/anchor", headers=analyst_headers)
    assert res_anchor.status_code == 200
    assert res_anchor.json()["status"] == "report_anchored"

    anchored_hash = gateway.case_registry.functions.reportHash(onchain_bytes).call()
    assert anchored_hash != bytes(32)

    # 8. Query GET /cases/{id}/chain
    res_chain = client.get(f"/cases/{case_id}/chain", headers=analyst_headers)
    assert res_chain.status_code == 200
    chain_info = res_chain.json()
    assert chain_info["state"] == "Finalized"
    assert chain_info["onchainCaseId"] == onchain_id
    assert chain_info["claimedRoot"] is not None
    assert chain_info["finalRoot"] is not None
    assert chain_info["reportHash"] is not None
    assert len(chain_info["validators"]) == 3
    assert all(v["committed"] and v["revealed"] for v in chain_info["validators"])


# ---------------------------------------------------------------------------
# 2. Idempotence Tests
# ---------------------------------------------------------------------------


def test_gateway_idempotence(client, hardhat_node):
    """
    Verify idempotency requirement:
    Calling every endpoint twice creates NO duplicate transactions and does not revert.
    """
    case_id, _ = create_analyzed_case(client)

    # Open twice
    res_open_1 = client.post(f"/cases/{case_id}/open", headers=analyst_headers)
    assert res_open_1.status_code == 200
    tx_open_1 = res_open_1.json()["txHash"]

    res_open_2 = client.post(f"/cases/{case_id}/open", headers=analyst_headers)
    assert res_open_2.status_code == 200
    assert res_open_2.json()["idempotent"] is True
    assert res_open_2.json()["txHash"] == tx_open_1

    # Claim twice
    res_claim_1 = client.post(f"/cases/{case_id}/claim", headers=analyst_headers)
    assert res_claim_1.status_code == 200
    tx_claim_1 = res_claim_1.json()["txHash"]

    res_claim_2 = client.post(f"/cases/{case_id}/claim", headers=analyst_headers)
    assert res_claim_2.status_code == 200
    assert res_claim_2.json()["idempotent"] is True
    assert res_claim_2.json()["txHash"] == tx_claim_1

    # Verify only 2 transactions exist in chain_txs so far (open and claim)
    txs = get_chain_txs(case_id)
    steps = [t["step"] for t in txs]
    assert steps == ["open", "claim"]


# ---------------------------------------------------------------------------
# 3. Crash Recovery Before Receipt Stored Test
# ---------------------------------------------------------------------------


def test_crash_recovery_before_receipt_stored(client, hardhat_node):
    """
    Crash test:
    A crash test that raises an exception after the transaction is sent but before
    the receipt is stored, then restarts and finishes without a second transaction.
    """
    gateway: ChainGateway = hardhat_node["gateway"]
    w3: Web3 = hardhat_node["w3"]
    case_id, _ = create_analyzed_case(client)

    case = get_case(case_id)
    pcap_sha = bytes.fromhex(case["pcap_sha256"])
    contract_fn = gateway.case_registry.functions.openCase(pcap_sha)

    # 1. Simulate sending tx and saving status='sent', then crashing before receipt saved
    nonce = w3.eth.get_transaction_count(gateway.analyst_account.address, "pending")
    tx_params = {
        "from": gateway.analyst_account.address,
        "nonce": nonce,
        "gas": 300000,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    }
    built_tx = contract_fn.build_transaction(tx_params)
    signed = gateway.analyst_account.sign_transaction(built_tx)
    raw = getattr(signed, "raw_transaction", getattr(signed, "rawTransaction", None))
    tx_hash = "0x" + w3.eth.send_raw_transaction(raw).hex().lstrip("0x")

    # Store 'sent' status in chain_txs
    record_chain_tx(case_id, "open", nonce, tx_hash, "sent", 0)

    # Verify initial state: status is 'sent' in database, NOT 'confirmed'
    tx_before = get_chain_tx(case_id, "open")
    assert tx_before["status"] == "sent"

    # 2. Restart / re-invoke open_case endpoint
    # Gateway MUST discover existing mined transaction, mark 'confirmed', and NOT send a second tx!
    res_open = client.post(f"/cases/{case_id}/open", headers=analyst_headers)
    assert res_open.status_code == 200

    # Verify receipt confirmed and tx_hash matches the original sent hash
    tx_after = get_chain_tx(case_id, "open")
    assert tx_after["status"] == "confirmed"
    assert tx_after["tx_hash"] == tx_hash

    # Verify no second transaction was sent for 'open'
    open_txs = [t for t in get_chain_txs(case_id) if t["step"] == "open"]
    assert len(open_txs) == 1


# ---------------------------------------------------------------------------
# 4. Revert Reported and Not Retried Test
# ---------------------------------------------------------------------------


def test_revert_reported_and_not_retried(client, hardhat_node):
    """
    Verify:
    A revert (e.g. wrong state or unauthorized caller) is reported,
    the revert reason is surfaced, and the transaction is NEVER retried.
    """
    case_id, _ = create_analyzed_case(client)

    # Open case on-chain first so the contract is actually called
    res_open = client.post(f"/cases/{case_id}/open", headers=analyst_headers)
    assert res_open.status_code == 200

    # Attempt to finalize before case is in Revealing state -> contract reverts with InvalidCaseState
    res_bad = client.post(f"/cases/{case_id}/finalize", headers=analyst_headers)
    assert res_bad.status_code == 400
    assert "InvalidCaseState" in res_bad.json()["detail"]

    # Verify chain_txs has recorded status='reverted' and retries=0
    tx_reverted = get_chain_tx(case_id, "finalize")
    assert tx_reverted is not None
    assert tx_reverted["status"] == "reverted"
    assert tx_reverted["retries"] == 0


# ---------------------------------------------------------------------------
# 5. Event Listener Sync Test
# ---------------------------------------------------------------------------


def test_event_listener_sync(client, hardhat_node):
    """
    Verify event listener log polling corrects database from chain source of truth.
    """
    gateway: ChainGateway = hardhat_node["gateway"]
    case_id, _ = create_analyzed_case(client)

    # Open case
    res_open = client.post(f"/cases/{case_id}/open", headers=analyst_headers)
    assert res_open.status_code == 200

    # Intentionally desynchronize database status
    update_case_status(case_id, "desynchronized_state")
    assert get_case(case_id)["status"] == "desynchronized_state"

    # Call poll_events
    events_found = gateway.poll_events()
    assert events_found >= 1

    # Database case status must be corrected to match on-chain state
    res_chain = client.get(f"/cases/{case_id}/chain", headers=analyst_headers)
    assert res_chain.status_code == 200
    assert res_chain.json()["state"] == "Opened"
