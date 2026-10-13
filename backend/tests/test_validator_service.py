"""Tests for SecureMailScope Validator Service (Phase 6 - Prompt 6.3).

Verifies:
1. Restart safety: Restart between commit and reveal still reveals using stored salt.
2. Snapshot filtering: Inbox bundle for a case the validator is not in is ignored.
3. Strict mode pinning: A wrong engine digest aborts before commit.
4. Quorum consensus & outvoting: A faulty validator is outvoted by honest quorum.
5. Acceptance (Milestone M3): End-to-end API upload -> analyze -> open -> claim -> distribute
   -> three validator services finalize -> record & anchor complete; killing one validator service
   after commit and restarting it still ends in Finalized.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Any, Dict, List, Tuple
import uuid

from eth_account import Account
from fastapi.testclient import TestClient
import pytest
from web3 import Web3

from backend.app import app
import backend.config as config
from backend.chain.gateway import ChainGateway
from backend.database import get_case, init_db
from engine.smscope.rules.ruleset_hash import compute_ruleset_hash
from validator.service import ValidatorService, StrictModeError

REPO_ROOT = config.REPO_ROOT
CONTRACTS_DIR = REPO_ROOT / "contracts"
DEPLOYMENTS_FILE = CONTRACTS_DIR / "deployments" / "local.json"
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"

# Hardhat accounts
ADMIN_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANALYST_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

VALIDATOR_KEYS = [
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
]
VALIDATOR_ACCOUNTS = [Account.from_key(k) for k in VALIDATOR_KEYS]

NON_SNAPSHOT_KEY = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
NON_SNAPSHOT_ACCOUNT = Account.from_key(NON_SNAPSHOT_KEY)


def kill_process_tree(pid: int) -> None:
    try:
        subprocess.run(f"taskkill /F /T /PID {pid}", shell=True, capture_output=True)
    except Exception:
        pass


@pytest.fixture(scope="module")
def hardhat_node():
    """Start local Hardhat node and deploy contracts once for validator tests."""
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

    # Register active engine & real ruleset on-chain
    image_digest = Web3.keccak(text="smscope:latest")
    real_ruleset_hex = compute_ruleset_hash()
    ruleset_hash = bytes.fromhex(real_ruleset_hex)
    gateway.register_engine(image_digest, ruleset_hash)

    # Register the 3 validator addresses
    for val_acc in VALIDATOR_ACCOUNTS:
        try:
            gateway.add_validator(val_acc.address)
        except Exception:
            pass

    # Ensure engine digest is set in environment for strict mode
    os.environ["ENGINE_IMAGE_DIGEST"] = "0x" + image_digest.hex()

    yield {
        "gateway": gateway,
        "w3": w3,
        "rpc_url": rpc_url,
        "image_digest": image_digest,
        "ruleset_hash": ruleset_hash,
    }

    if node_proc:
        kill_process_tree(node_proc.pid)


@pytest.fixture
def setup_env(tmp_path, monkeypatch, hardhat_node):
    """Isolate DB, inboxes, and state dirs for each test."""
    test_data_dir = tmp_path / "data"
    test_cases_dir = test_data_dir / "cases"
    test_db_path = test_data_dir / "test_validator.db"

    test_inbox_dir = tmp_path / "validator_inbox"
    test_state_dir = tmp_path / "validator_state"

    monkeypatch.setattr(config, "DATA_DIR", test_data_dir)
    monkeypatch.setattr(config, "CASES_DIR", test_cases_dir)
    monkeypatch.setattr(config, "DB_PATH", test_db_path)
    monkeypatch.setattr(config, "RPC_URL", hardhat_node["rpc_url"])
    monkeypatch.setattr(config, "DEPLOYMENT_FILE", DEPLOYMENTS_FILE)
    monkeypatch.setattr(config, "ANALYST_KEY", ANALYST_KEY)
    monkeypatch.setattr(config, "ADMIN_KEY", ADMIN_KEY)

    test_cases_dir.mkdir(parents=True, exist_ok=True)
    test_inbox_dir.mkdir(parents=True, exist_ok=True)
    test_state_dir.mkdir(parents=True, exist_ok=True)

    init_db(test_db_path)

    import backend.app as app_mod
    app_mod._gateway_instance = hardhat_node["gateway"]

    return {
        "inbox_dir": test_inbox_dir,
        "state_dir": test_state_dir,
        "cases_dir": test_cases_dir,
    }


@pytest.fixture
def client(setup_env):
    with TestClient(app) as test_client:
        yield test_client


def prepare_claimed_case(client: TestClient, hardhat_node: Dict[str, Any], setup_env: Dict[str, Any]) -> Tuple[str, str, bytes]:
    """Helper to upload, analyze, open, and claim a case on-chain."""
    analyst_headers = {"X-API-Key": config.ANALYST_API_KEY}
    pcap_path = CAPTURES_DIR / "S01a.pcap"

    with open(pcap_path, "rb") as f:
        res_upload = client.post(
            "/cases/upload",
            files={"file": ("S01a.pcap", f, "application/vnd.tcpdump.pcap")},
            headers=analyst_headers,
        )
    assert res_upload.status_code in (200, 201)
    case_id = res_upload.json()["caseId"]

    res_an = client.post(f"/cases/{case_id}/analyze?sync=true", headers=analyst_headers)
    assert res_an.status_code == 200
    assert res_an.json()["status"] == "analyzed"

    res_open = client.post(f"/cases/{case_id}/open", headers=analyst_headers)
    assert res_open.status_code == 200
    onchain_case_id = res_open.json()["onchainCaseId"]
    onchain_bytes = bytes.fromhex(onchain_case_id.replace("0x", ""))

    res_claim = client.post(f"/cases/{case_id}/claim", headers=analyst_headers)
    assert res_claim.status_code == 200

    return case_id, onchain_case_id, onchain_bytes


# ---------------------------------------------------------------------------
# Test 1: Restart between commit and reveal still reveals with stored salt
# ---------------------------------------------------------------------------

def test_restart_between_commit_and_reveal(client, hardhat_node, setup_env):
    case_id, onchain_case_id, onchain_bytes = prepare_claimed_case(client, hardhat_node, setup_env)
    w3 = hardhat_node["w3"]
    gateway = hardhat_node["gateway"]

    # Prepare bundle in inbox for validator 1
    val1_inbox = setup_env["inbox_dir"] / "1" / onchain_case_id.replace("0x", "")
    val1_inbox.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(CAPTURES_DIR / "S01a.pcap", val1_inbox / "pcap.bin")
    (val1_inbox / "org_secret.hex").write_text(config.ORG_SECRET_HEX.strip())
    (val1_inbox / "onchain_case_id.txt").write_text(onchain_case_id.strip())

    service1 = ValidatorService(
        validator_id="1",
        private_key=VALIDATOR_KEYS[0],
        inbox_dir=setup_env["inbox_dir"] / "1",
        state_dir=setup_env["state_dir"],
        rpc_url=hardhat_node["rpc_url"],
        deployment_file=DEPLOYMENTS_FILE,
        strict=True,
    )

    # 1. First run: commits and saves salt atomically, then simulate interrupt/stop
    # Mocking wait/advance to simulate crash right after commit
    original_save = service1.save_state
    saved_state_capture = {}

    def spy_save(payload):
        saved_state_capture.update(payload)
        original_save(payload)

    service1.save_state = spy_save

    # Run one pass up to commit
    pcap_path = val1_inbox / "pcap.bin"
    root_bytes, res_data, man_data = service1.run_engine_analysis(
        val1_inbox, pcap_path, config.ORG_SECRET_HEX, onchain_bytes.hex()
    )
    service1.verify_strict_mode(onchain_bytes, man_data)

    salt_bytes = os.urandom(32)
    from eth_abi import encode
    encoded_payload = encode(
        ["bytes32", "address", "bytes32", "bytes32"],
        [onchain_bytes, service1.account.address, root_bytes, salt_bytes],
    )
    commitment_bytes = Web3.keccak(encoded_payload)

    state_payload = {
        "validatorId": "1",
        "validatorAddress": service1.account.address,
        "caseId": onchain_case_id,
        "round": 1,
        "salt": "0x" + salt_bytes.hex(),
        "resultRoot": "0x" + root_bytes.hex(),
        "commitment": "0x" + commitment_bytes.hex(),
        "committedAt": int(time.time()),
        "revealed": False,
    }
    service1.save_state(state_payload)

    commit_fn = service1.quorum.functions.commit(onchain_bytes, commitment_bytes)
    from validator.service import send_validator_tx
    send_validator_tx(w3, commit_fn, service1.account, service1.private_key)

    assert gateway.quorum.functions.hasCommitted(onchain_bytes, 1, service1.account.address).call() is True
    assert gateway.quorum.functions.hasRevealed(onchain_bytes, 1, service1.account.address).call() is False

    # Simulate crash / process termination: service1 is discarded!
    del service1

    # Fast forward past commit deadline
    w3.provider.make_request("evm_increaseTime", [65])
    w3.provider.make_request("evm_mine", [])

    # Advance to Revealing
    gateway.advance(case_id)

    # 2. Restarted service instance resumes from state file
    restarted_service = ValidatorService(
        validator_id="1",
        private_key=VALIDATOR_KEYS[0],
        inbox_dir=setup_env["inbox_dir"] / "1",
        state_dir=setup_env["state_dir"],
        rpc_url=hardhat_node["rpc_url"],
        deployment_file=DEPLOYMENTS_FILE,
        strict=True,
    )

    # Resume from state must pick up stored salt and reveal
    resumed = restarted_service.resume_from_state()
    assert resumed is True
    assert gateway.quorum.functions.hasRevealed(onchain_bytes, 1, restarted_service.account.address).call() is True

    # Calling resume again must be a no-op (no double-submission)
    assert restarted_service.resume_from_state() is False


# ---------------------------------------------------------------------------
# Test 2: An inbox bundle for a case the validator is not in is ignored
# ---------------------------------------------------------------------------

def test_inbox_bundle_not_in_snapshot_ignored(client, hardhat_node, setup_env):
    case_id, onchain_case_id, onchain_bytes = prepare_claimed_case(client, hardhat_node, setup_env)
    gateway = hardhat_node["gateway"]

    # Validator 4 is NOT in the snapshot of 3 validators
    val_out_inbox = setup_env["inbox_dir"] / "non_snapshot" / onchain_case_id.replace("0x", "")
    val_out_inbox.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(CAPTURES_DIR / "S01a.pcap", val_out_inbox / "pcap.bin")
    (val_out_inbox / "org_secret.hex").write_text(config.ORG_SECRET_HEX.strip())
    (val_out_inbox / "onchain_case_id.txt").write_text(onchain_case_id.strip())

    service_out = ValidatorService(
        validator_id="non_snapshot",
        private_key=NON_SNAPSHOT_KEY,
        inbox_dir=setup_env["inbox_dir"] / "non_snapshot",
        state_dir=setup_env["state_dir"],
        rpc_url=hardhat_node["rpc_url"],
        deployment_file=DEPLOYMENTS_FILE,
        strict=True,
    )

    actions = service_out.poll_and_process()
    assert actions == 0
    # Must not have committed on-chain
    assert gateway.quorum.functions.hasCommitted(onchain_bytes, 1, service_out.account.address).call() is False


# ---------------------------------------------------------------------------
# Test 3: A wrong engine digest aborts before commit
# ---------------------------------------------------------------------------

def test_wrong_engine_digest_aborts_before_commit(client, hardhat_node, setup_env, monkeypatch):
    case_id, onchain_case_id, onchain_bytes = prepare_claimed_case(client, hardhat_node, setup_env)
    gateway = hardhat_node["gateway"]

    # Set incorrect engine digest in environment
    bad_engine_digest = "0x" + ("ff" * 32)
    monkeypatch.setenv("ENGINE_IMAGE_DIGEST", bad_engine_digest)

    val1_inbox = setup_env["inbox_dir"] / "1" / onchain_case_id.replace("0x", "")
    val1_inbox.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(CAPTURES_DIR / "S01a.pcap", val1_inbox / "pcap.bin")
    (val1_inbox / "org_secret.hex").write_text(config.ORG_SECRET_HEX.strip())
    (val1_inbox / "onchain_case_id.txt").write_text(onchain_case_id.strip())

    service1 = ValidatorService(
        validator_id="1",
        private_key=VALIDATOR_KEYS[0],
        inbox_dir=setup_env["inbox_dir"] / "1",
        state_dir=setup_env["state_dir"],
        rpc_url=hardhat_node["rpc_url"],
        deployment_file=DEPLOYMENTS_FILE,
        strict=True,
    )

    # Process bundle directly: must raise StrictModeError and never commit
    pcap_path = val1_inbox / "pcap.bin"
    root_bytes, res_data, man_data = service1.run_engine_analysis(
        val1_inbox, pcap_path, config.ORG_SECRET_HEX, onchain_bytes.hex()
    )

    with pytest.raises(StrictModeError):
        service1.verify_strict_mode(onchain_bytes, man_data)

    assert gateway.quorum.functions.hasCommitted(onchain_bytes, 1, service1.account.address).call() is False


# ---------------------------------------------------------------------------
# Test 4: A faulty validator is outvoted
# ---------------------------------------------------------------------------

def test_faulty_validator_outvoted(client, hardhat_node, setup_env):
    case_id, onchain_case_id, onchain_bytes = prepare_claimed_case(client, hardhat_node, setup_env)
    w3 = hardhat_node["w3"]
    gateway = hardhat_node["gateway"]

    # Distribute bundles to validators 1, 2, and 3
    for vid in ["1", "2", "3"]:
        inbox = setup_env["inbox_dir"] / vid / onchain_case_id.replace("0x", "")
        inbox.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(CAPTURES_DIR / "S01a.pcap", inbox / "pcap.bin")
        (inbox / "org_secret.hex").write_text(config.ORG_SECRET_HEX.strip())
        (inbox / "onchain_case_id.txt").write_text(onchain_case_id.strip())

    # Validators 1 & 2 are honest; Validator 3 is faulty
    s1 = ValidatorService(
        validator_id="1",
        private_key=VALIDATOR_KEYS[0],
        inbox_dir=setup_env["inbox_dir"] / "1",
        state_dir=setup_env["state_dir"],
        rpc_url=hardhat_node["rpc_url"],
        deployment_file=DEPLOYMENTS_FILE,
        strict=True,
        faulty=False,
    )
    s2 = ValidatorService(
        validator_id="2",
        private_key=VALIDATOR_KEYS[1],
        inbox_dir=setup_env["inbox_dir"] / "2",
        state_dir=setup_env["state_dir"],
        rpc_url=hardhat_node["rpc_url"],
        deployment_file=DEPLOYMENTS_FILE,
        strict=True,
        faulty=False,
    )
    s3_faulty = ValidatorService(
        validator_id="3",
        private_key=VALIDATOR_KEYS[2],
        inbox_dir=setup_env["inbox_dir"] / "3",
        state_dir=setup_env["state_dir"],
        rpc_url=hardhat_node["rpc_url"],
        deployment_file=DEPLOYMENTS_FILE,
        strict=True,
        faulty=True,
    )

    # 1. All three commit
    from eth_abi import encode
    from validator.service import send_validator_tx

    salts = []
    roots = []
    for s in [s1, s2, s3_faulty]:
        pcap = setup_env["inbox_dir"] / s.validator_id / onchain_case_id.replace("0x", "") / "pcap.bin"
        root, _, _ = s.run_engine_analysis(pcap.parent, pcap, config.ORG_SECRET_HEX, onchain_bytes.hex())
        salt = os.urandom(32)
        salts.append(salt)
        roots.append(root)

        enc = encode(["bytes32", "address", "bytes32", "bytes32"], [onchain_bytes, s.account.address, root, salt])
        comm = Web3.keccak(enc)
        s.save_state({
            "validatorId": s.validator_id,
            "validatorAddress": s.account.address,
            "caseId": onchain_case_id,
            "round": 1,
            "salt": "0x" + salt.hex(),
            "resultRoot": "0x" + root.hex(),
            "commitment": "0x" + comm.hex(),
            "revealed": False,
        })
        commit_fn = s.quorum.functions.commit(onchain_bytes, comm)
        send_validator_tx(w3, commit_fn, s.account, s.private_key)

    # Verify roots: s1 and s2 match honest claimedRoot; s3_faulty is tampered
    claimed_root = gateway.case_registry.functions.claimedRoot(onchain_bytes).call()
    assert roots[0] == claimed_root
    assert roots[1] == claimed_root
    assert roots[2] != claimed_root  # Faulty!

    # Fast forward beyond commit deadline
    w3.provider.make_request("evm_increaseTime", [65])
    w3.provider.make_request("evm_mine", [])

    # Advance to Revealing
    gateway.advance(case_id)

    # 2. All three reveal
    onchain_engine = gateway.case_registry.functions.engineHash(onchain_bytes).call()
    onchain_ruleset = gateway.case_registry.functions.rulesetHash(onchain_bytes).call()
    for i, s in enumerate([s1, s2, s3_faulty]):
        rev_fn = s.quorum.functions.reveal(onchain_bytes, roots[i], salts[i], onchain_engine, onchain_ruleset)
        send_validator_tx(w3, rev_fn, s.account, s.private_key)

    # 3. Finalize: quorum (2 of 3) agreed on claimed_root
    fin_fn = gateway.quorum.functions.finalize(onchain_bytes)
    send_validator_tx(w3, fin_fn, s1.account, s1.private_key)

    # Case must finalize on the honest root without contradiction
    final_root = gateway.case_registry.functions.finalRoot(onchain_bytes).call()
    assert final_root == claimed_root
    assert gateway.case_registry.functions.isContradicted(onchain_bytes).call() is False
    assert gateway.case_registry.functions.caseState(onchain_bytes).call() == 5  # Finalized


# ---------------------------------------------------------------------------
# Test 5: Acceptance (Milestone M3) Full API Flow with Restart Safety
# ---------------------------------------------------------------------------

def test_acceptance_full_flow_with_restart(client, hardhat_node, setup_env, monkeypatch):
    """
    Acceptance (milestone M3): API upload, analyze, open, claim, distribute;
    three validator services finalize; record and anchor complete;
    killing one validator service after its commit and restarting it still ends in Finalized.
    """
    analyst_headers = {"X-API-Key": config.ANALYST_API_KEY}
    w3 = hardhat_node["w3"]
    gateway = hardhat_node["gateway"]

    # Set up global repo inbox & state locations for distribute endpoint
    monkeypatch.setattr(config, "REPO_ROOT", setup_env["cases_dir"].parent)

    pcap_path = CAPTURES_DIR / "S01a.pcap"

    # 1. Upload
    with open(pcap_path, "rb") as f:
        res_up = client.post(
            "/cases/upload",
            files={"file": ("S01a.pcap", f, "application/vnd.tcpdump.pcap")},
            headers=analyst_headers,
        )
    assert res_up.status_code in (200, 201)
    case_id = res_up.json()["caseId"]

    # 2. Analyze
    res_an = client.post(f"/cases/{case_id}/analyze?sync=true", headers=analyst_headers)
    assert res_an.status_code == 200

    # 3. Open
    res_open = client.post(f"/cases/{case_id}/open", headers=analyst_headers)
    assert res_open.status_code == 200
    onchain_case_id = res_open.json()["onchainCaseId"]
    onchain_bytes = bytes.fromhex(onchain_case_id.replace("0x", ""))

    # 4. Claim
    res_claim = client.post(f"/cases/{case_id}/claim", headers=analyst_headers)
    assert res_claim.status_code == 200

    # 5. Distribute
    res_dist = client.post(f"/cases/{case_id}/distribute", headers=analyst_headers)
    assert res_dist.status_code == 200
    assert res_dist.json()["status"] == "distributed"

    # Verify bundles in validator inboxes
    repo_root = config.REPO_ROOT
    for vid in ["1", "2", "3"]:
        assert (repo_root / "validator_inbox" / vid / case_id / "pcap.bin").exists()
        assert (repo_root / "validator_inbox" / vid / case_id / "org_secret.hex").exists()

    # 6. Initialize Validator 1, 2, 3 services
    state_dir = repo_root / "validator_state"
    s1 = ValidatorService(
        validator_id="1",
        private_key=VALIDATOR_KEYS[0],
        inbox_dir=repo_root / "validator_inbox" / "1",
        state_dir=state_dir,
        rpc_url=hardhat_node["rpc_url"],
        deployment_file=DEPLOYMENTS_FILE,
        strict=True,
    )
    s2 = ValidatorService(
        validator_id="2",
        private_key=VALIDATOR_KEYS[1],
        inbox_dir=repo_root / "validator_inbox" / "2",
        state_dir=state_dir,
        rpc_url=hardhat_node["rpc_url"],
        deployment_file=DEPLOYMENTS_FILE,
        strict=True,
    )
    s3 = ValidatorService(
        validator_id="3",
        private_key=VALIDATOR_KEYS[2],
        inbox_dir=repo_root / "validator_inbox" / "3",
        state_dir=state_dir,
        rpc_url=hardhat_node["rpc_url"],
        deployment_file=DEPLOYMENTS_FILE,
        strict=True,
    )

    # 7. Validator 1 processes bundle up to commit, then gets "killed"
    from eth_abi import encode
    from validator.service import send_validator_tx

    bundle_1 = repo_root / "validator_inbox" / "1" / case_id
    root_1, _, man_1 = s1.run_engine_analysis(
        bundle_1, bundle_1 / "pcap.bin", config.ORG_SECRET_HEX, onchain_bytes.hex()
    )
    s1.verify_strict_mode(onchain_bytes, man_1)
    salt_1 = os.urandom(32)
    enc_1 = encode(["bytes32", "address", "bytes32", "bytes32"], [onchain_bytes, s1.account.address, root_1, salt_1])
    comm_1 = Web3.keccak(enc_1)

    s1.save_state({
        "validatorId": "1",
        "validatorAddress": s1.account.address,
        "caseId": onchain_case_id,
        "round": 1,
        "salt": "0x" + salt_1.hex(),
        "resultRoot": "0x" + root_1.hex(),
        "commitment": "0x" + comm_1.hex(),
        "revealed": False,
    })
    commit_1 = s1.quorum.functions.commit(onchain_bytes, comm_1)
    send_validator_tx(w3, commit_1, s1.account, s1.private_key)

    # Kill s1
    del s1

    # 8. Validators 2 and 3 commit
    for s in [s2, s3]:
        bundle = repo_root / "validator_inbox" / s.validator_id / case_id
        root, _, man = s.run_engine_analysis(
            bundle, bundle / "pcap.bin", config.ORG_SECRET_HEX, onchain_bytes.hex()
        )
        s.verify_strict_mode(onchain_bytes, man)
        salt = os.urandom(32)
        enc = encode(["bytes32", "address", "bytes32", "bytes32"], [onchain_bytes, s.account.address, root, salt])
        comm = Web3.keccak(enc)
        s.save_state({
            "validatorId": s.validator_id,
            "validatorAddress": s.account.address,
            "caseId": onchain_case_id,
            "round": 1,
            "salt": "0x" + salt.hex(),
            "resultRoot": "0x" + root.hex(),
            "commitment": "0x" + comm.hex(),
            "revealed": False,
        })
        commit_fn = s.quorum.functions.commit(onchain_bytes, comm)
        send_validator_tx(w3, commit_fn, s.account, s.private_key)

    # 9. Fast forward past commit deadline
    w3.provider.make_request("evm_increaseTime", [65])
    w3.provider.make_request("evm_mine", [])

    # Advance to Revealing
    gateway.advance(case_id)

    # 10. Restart Validator 1: resumes from state and reveals
    restarted_s1 = ValidatorService(
        validator_id="1",
        private_key=VALIDATOR_KEYS[0],
        inbox_dir=repo_root / "validator_inbox" / "1",
        state_dir=state_dir,
        rpc_url=hardhat_node["rpc_url"],
        deployment_file=DEPLOYMENTS_FILE,
        strict=True,
    )
    restarted_s1.resume_from_state()

    # Validators 2 and 3 reveal
    s2.resume_from_state()
    s3.resume_from_state()

    # Finalize
    gateway.finalize(case_id)
    assert gateway.case_registry.functions.caseState(onchain_bytes).call() == 5  # Finalized

    # 11. Record posture and Anchor report
    res_rec = client.post(f"/cases/{case_id}/record", headers=analyst_headers)
    assert res_rec.status_code == 200

    res_anc = client.post(f"/cases/{case_id}/anchor", headers=analyst_headers)
    assert res_anc.status_code == 200

    # 12. Verify state on chain
    chain_info = client.get(f"/cases/{case_id}/chain", headers=analyst_headers).json()
    assert chain_info["state"] in ("Finalized", "finalized")
    assert chain_info["contradicted"] is False
    assert len(chain_info["validators"]) == 3
    assert all(v["committed"] and v["revealed"] for v in chain_info["validators"])
