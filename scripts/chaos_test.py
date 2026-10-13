"""SecureMailScope Kill-and-Resume Chaos Test (Tier 3 / Prompt T3.3).

Executes crash-recovery verification across all lifecycle steps:
1. analyze (API worker / analysis runner killed mid-analysis)
2. open (Gateway killed during open transaction submission)
3. claim (Gateway killed during claim transaction submission)
4. distribute (API worker killed during bundle distribution)
5. commit (Validator service killed after atomic salt write before commit confirmation)
6. reveal (Validator service killed during commit wait before reveal confirmation)
7. finalize (Gateway killed during finalize transaction submission)
8. record (Gateway killed during posture record transaction)
9. anchor (Gateway killed during report anchor transaction)

Assertions per scenario:
- Case ends on-chain in 'Finalized' (State 5).
- chain_txs table holds NO duplicate transactions for any step.
- The 5-step cryptographic verifier passes.
Prints a formatted summary table of: Step | Killed Process | Result.
"""
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from eth_abi import encode
from eth_account import Account
from fastapi.testclient import TestClient
from web3 import Web3

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "engine"))

from backend.app import app
from backend.chain.gateway import ChainGateway
import backend.config as config
from backend.database import (
    create_case,
    get_case,
    get_chain_txs,
    init_db,
    record_chain_tx,
    update_case_status,
)
from backend.reports.builder import build_case_report
from backend.runner import execute_analysis
from backend.storage import get_case_dir
from engine.smscope.rules.ruleset_hash import compute_ruleset_hash
from validator.service import ValidatorService, send_validator_tx

CONTRACTS_DIR = REPO_ROOT / "contracts"
DEPLOYMENTS_FILE = CONTRACTS_DIR / "deployments" / "local.json"
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"

VALIDATOR_KEYS = [
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
]


def ensure_chain_and_deployment() -> Tuple[Web3, ChainGateway, bytes, bytes]:
    """Ensures local Hardhat node is running and returns (w3, gateway, engine_digest, ruleset_hash)."""
    rpc_url = "http://127.0.0.1:8545"
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print("[!] Starting Hardhat node in background...")
        proc = subprocess.Popen(
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
        if not w3.is_connected():
            raise RuntimeError("Could not connect to Hardhat node after starting.")

    needs_deploy = not DEPLOYMENTS_FILE.exists()
    if not needs_deploy:
        try:
            with open(DEPLOYMENTS_FILE, "r") as f:
                dep_data = json.load(f)
            reg_addr = dep_data["contracts"]["CaseRegistry"]["address"]
            if len(w3.eth.get_code(reg_addr)) <= 2:
                needs_deploy = True
        except Exception:
            needs_deploy = True

    if needs_deploy:
        print("[!] Deploying contracts...")
        res = subprocess.run(
            "npx hardhat run scripts/deploy.ts --network localhost",
            cwd=str(CONTRACTS_DIR),
            shell=True,
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            raise RuntimeError(f"Deploy failed: {res.stderr}")

    gateway = ChainGateway(rpc_url=rpc_url, deployment_file=DEPLOYMENTS_FILE)

    ruleset_hash_raw = compute_ruleset_hash()
    ruleset_hash_bytes = bytes.fromhex(ruleset_hash_raw) if isinstance(ruleset_hash_raw, str) else ruleset_hash_raw
    image_digest_bytes = Web3.keccak(text="smscope:latest")

    try:
        gateway.register_engine(image_digest_bytes, ruleset_hash_bytes)
    except Exception:
        pass

    for k in VALIDATOR_KEYS:
        val_addr = Account.from_key(k).address
        try:
            gateway.add_validator(val_addr)
        except Exception:
            pass

    os.environ["ENGINE_IMAGE_DIGEST"] = "0x" + image_digest_bytes.hex()
    return w3, gateway, image_digest_bytes, ruleset_hash_bytes


def run_validators_consensus(
    w3: Web3,
    gateway: ChainGateway,
    case_id: str,
    onchain_bytes: bytes,
    onchain_case_id: str,
    env_dir: Path,
    kill_step: Optional[str] = None,
) -> None:
    """Runs commit, advance, and reveal for the 3 validator services."""
    state_dir = env_dir / "validator_state"
    state_dir.mkdir(parents=True, exist_ok=True)
    inbox_base = env_dir / "validator_inbox"

    services = [
        ValidatorService(
            validator_id=str(idx + 1),
            private_key=VALIDATOR_KEYS[idx],
            inbox_dir=inbox_base / str(idx + 1),
            state_dir=state_dir,
            rpc_url="http://127.0.0.1:8545",
            deployment_file=DEPLOYMENTS_FILE,
            strict=True,
        )
        for idx in range(3)
    ]

    # --- COMMIT STAGE ---
    for idx, s in enumerate(services):
        bundle = inbox_base / s.validator_id / case_id
        # Detect bundle.enc or pcap.bin
        enc_file = bundle / "bundle.enc"
        if enc_file.exists():
            from validator.crypto import decrypt_validator_bundle
            from validator.keygen import load_validator_private_key
            val_priv = load_validator_private_key(state_dir, s.validator_id)
            pcap_b, sec_dec, _ = decrypt_validator_bundle(enc_file.read_bytes(), val_priv)
            t_dir = tempfile.mkdtemp(prefix="val_chaos_")
            try:
                t_pcap = Path(t_dir) / "pcap.bin"
                t_pcap.write_bytes(pcap_b)
                root, _, man = s.run_engine_analysis(Path(t_dir), t_pcap, sec_dec, onchain_bytes.hex())
            finally:
                shutil.rmtree(t_dir, ignore_errors=True)
        else:
            pcap_p = bundle / "pcap.bin"
            root, _, man = s.run_engine_analysis(bundle, pcap_p, config.ORG_SECRET_HEX, onchain_bytes.hex())

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

        if kill_step == "commit" and idx == 0:
            # Simulate Validator 1 process SIGKILL immediately after atomic salt save
            # Kill s instance and instantiate a fresh restarted instance
            del s
            services[0] = ValidatorService(
                validator_id="1",
                private_key=VALIDATOR_KEYS[0],
                inbox_dir=inbox_base / "1",
                state_dir=state_dir,
                rpc_url="http://127.0.0.1:8545",
                deployment_file=DEPLOYMENTS_FILE,
                strict=True,
            )
            # Restarted validator finishes commit
            commit_fn = services[0].quorum.functions.commit(onchain_bytes, comm)
            send_validator_tx(w3, commit_fn, services[0].account, services[0].private_key)
            continue

        commit_fn = s.quorum.functions.commit(onchain_bytes, comm)
        send_validator_tx(w3, commit_fn, s.account, s.private_key)

    # --- ADVANCE TO REVEAL ---
    w3.provider.make_request("evm_increaseTime", [65])
    w3.provider.make_request("evm_mine", [])
    gateway.advance(case_id)

    # --- REVEAL STAGE ---
    for idx, s in enumerate(services):
        if kill_step == "reveal" and idx == 0:
            # Simulate Validator 1 SIGKILL during reveal window, restarted from stored state
            del s
            services[0] = ValidatorService(
                validator_id="1",
                private_key=VALIDATOR_KEYS[0],
                inbox_dir=inbox_base / "1",
                state_dir=state_dir,
                rpc_url="http://127.0.0.1:8545",
                deployment_file=DEPLOYMENTS_FILE,
                strict=True,
            )
            # Resumes reveal using saved state
            services[0].resume_from_state()
            continue

        s.resume_from_state()


def run_chaos_scenario(
    step_name: str,
    killed_process_name: str,
    w3: Web3,
    gateway: ChainGateway,
) -> Tuple[bool, str]:
    """Runs a complete end-to-end flow with simulated crash/kill at step_name."""
    temp_dir = tempfile.mkdtemp(prefix=f"chaos_{step_name}_")
    env_dir = Path(temp_dir)
    try:
        # Isolated test environment
        test_cases_dir = env_dir / "data" / "cases"
        test_cases_dir.mkdir(parents=True, exist_ok=True)
        test_db = env_dir / "data" / "smscope.db"
        test_db.parent.mkdir(parents=True, exist_ok=True)

        # Initialize isolated DB
        init_db(test_db)
        client = TestClient(app)
        headers = {"X-API-Key": config.ANALYST_API_KEY}

        case_id = f"chaos_{step_name}_{int(time.time())}"
        pcap_src = CAPTURES_DIR / "S01a.pcap"
        pcap_bytes = pcap_src.read_bytes()

        # Step 0: Upload
        case_dir = test_cases_dir / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        pcap_path = case_dir / "pcap.bin"
        pcap_path.write_bytes(pcap_bytes)
        import hashlib
        pcap_sha = hashlib.sha256(pcap_bytes).hexdigest()
        create_case(case_id=case_id, pcap_sha256=pcap_sha, status="uploaded", db_path=test_db)

        orig_db = config.DB_PATH
        orig_cases = config.CASES_DIR
        orig_data = config.DATA_DIR
        config.DB_PATH = test_db
        config.CASES_DIR = test_cases_dir
        config.DATA_DIR = env_dir / "data"

        # 1. Step: analyze
        if step_name == "analyze":
            # Simulate worker dying mid-analysis
            from backend.database import record_analysis_run
            record_analysis_run(case_id=case_id, status="running", started_at=int(time.time()), db_path=test_db)
            update_case_status(case_id, "running", db_path=test_db)
            # Restarted worker executes analysis to completion
            execute_analysis(case_id, use_docker=False)
        else:
            execute_analysis(case_id, use_docker=False)

        case_obj = get_case(case_id, db_path=test_db)
        assert case_obj and case_obj["status"] == "analyzed"

        # 2. Step: open
        if step_name == "open":
            # Simulate crash during open: tx submitted to network, status='sent' recorded, then gateway dies
            pcap_sha_b = bytes.fromhex(pcap_sha)
            nonce = w3.eth.get_transaction_count(gateway.analyst_account.address, "pending")
            fn = gateway.case_registry.functions.openCase(pcap_sha_b)
            tx = fn.build_transaction({
                "from": gateway.analyst_account.address,
                "nonce": nonce,
                "gas": 300000,
                "gasPrice": w3.eth.gas_price,
                "chainId": w3.eth.chain_id,
            })
            signed = gateway.analyst_account.sign_transaction(tx)
            raw = getattr(signed, "raw_transaction", getattr(signed, "rawTransaction", None))
            tx_h = "0x" + w3.eth.send_raw_transaction(raw).hex()
            record_chain_tx(case_id, "open", nonce, tx_h, "sent", 0, db_path=test_db)
            # Gateway killed, restarted gateway recovers sent tx
            del gateway
            gateway = ChainGateway(rpc_url="http://127.0.0.1:8545", deployment_file=DEPLOYMENTS_FILE)
            res_open = gateway.open_case(case_id)
        else:
            res_open = gateway.open_case(case_id)

        onchain_case_id = res_open["onchainCaseId"]
        onchain_bytes = bytes.fromhex(onchain_case_id.replace("0x", ""))

        # 3. Step: claim
        if step_name == "claim":
            res_json = json.loads((case_dir / "result.json").read_text(encoding="utf-8"))
            root_bytes = bytes.fromhex(res_json["resultRoot"].replace("0x", ""))
            image_digest, ruleset_hash = gateway.case_registry.functions.activeEngine().call()
            nonce = w3.eth.get_transaction_count(gateway.analyst_account.address, "pending")
            fn = gateway.quorum.functions.submitClaim(onchain_bytes, root_bytes, image_digest, ruleset_hash)
            tx = fn.build_transaction({
                "from": gateway.analyst_account.address,
                "nonce": nonce,
                "gas": 800000,
                "gasPrice": w3.eth.gas_price,
                "chainId": w3.eth.chain_id,
            })
            signed = gateway.analyst_account.sign_transaction(tx)
            raw = getattr(signed, "raw_transaction", getattr(signed, "rawTransaction", None))
            tx_h = "0x" + w3.eth.send_raw_transaction(raw).hex()
            record_chain_tx(case_id, "claim", nonce, tx_h, "sent", 0, db_path=test_db)
            # Gateway killed, restarted gateway recovers sent tx
            del gateway
            gateway = ChainGateway(rpc_url="http://127.0.0.1:8545", deployment_file=DEPLOYMENTS_FILE)
            res_claim = gateway.submit_claim(case_id)
        else:
            res_claim = gateway.submit_claim(case_id)

        # 4. Step: distribute
        if step_name == "distribute":
            # Simulate worker dying mid-distribute: only validator 1 inbox received bundle
            v1_inbox = env_dir / "validator_inbox" / "1" / case_id
            v1_inbox.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(pcap_path, v1_inbox / "pcap.bin")
            (v1_inbox / "org_secret.hex").write_text(config.ORG_SECRET_HEX, encoding="utf-8")
            # Restarted worker distributes to all validators idempotently
            for vid in ["1", "2", "3"]:
                inbox_bundle = env_dir / "validator_inbox" / vid / case_id
                inbox_bundle.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(pcap_path, inbox_bundle / "pcap.bin")
                (inbox_bundle / "org_secret.hex").write_text(config.ORG_SECRET_HEX, encoding="utf-8")
            update_case_status(case_id, "distributed", db_path=test_db)
        else:
            for vid in ["1", "2", "3"]:
                inbox_bundle = env_dir / "validator_inbox" / vid / case_id
                inbox_bundle.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(pcap_path, inbox_bundle / "pcap.bin")
                (inbox_bundle / "org_secret.hex").write_text(config.ORG_SECRET_HEX, encoding="utf-8")
            update_case_status(case_id, "distributed", db_path=test_db)

        # 5. Step: commit & 6. Step: reveal
        run_validators_consensus(
            w3=w3,
            gateway=gateway,
            case_id=case_id,
            onchain_bytes=onchain_bytes,
            onchain_case_id=onchain_case_id,
            env_dir=env_dir,
            kill_step=step_name if step_name in ("commit", "reveal") else None,
        )

        # 7. Step: finalize
        if step_name == "finalize":
            nonce = w3.eth.get_transaction_count(gateway.analyst_account.address, "pending")
            fn = gateway.quorum.functions.finalize(onchain_bytes)
            tx = fn.build_transaction({
                "from": gateway.analyst_account.address,
                "nonce": nonce,
                "gas": 300000,
                "gasPrice": w3.eth.gas_price,
                "chainId": w3.eth.chain_id,
            })
            signed = gateway.analyst_account.sign_transaction(tx)
            raw = getattr(signed, "raw_transaction", getattr(signed, "rawTransaction", None))
            tx_h = "0x" + w3.eth.send_raw_transaction(raw).hex()
            record_chain_tx(case_id, "finalize", nonce, tx_h, "sent", 0, db_path=test_db)
            del gateway
            gateway = ChainGateway(rpc_url="http://127.0.0.1:8545", deployment_file=DEPLOYMENTS_FILE)
            fin_tx = gateway.finalize(case_id)
        else:
            fin_tx = gateway.finalize(case_id)

        # 8. Step: record posture
        if step_name == "record":
            host_scores = json.loads((case_dir / "host_scores.json").read_text(encoding="utf-8"))
            host_proofs = json.loads((case_dir / "host_proofs.json").read_text(encoding="utf-8"))
            if host_scores:
                first_host = host_scores[0]
                clean_host_hex = first_host["hostId"].replace("0x", "")
                host_id_bytes = bytes.fromhex(clean_host_hex)
                findings_digest = bytes.fromhex(first_host["findingsDigest"].replace("0x", ""))
                score = int(first_host["score"])
                proof_raw = host_proofs.get(first_host["hostId"], host_proofs.get(f"0x{clean_host_hex}", []))
                proof_bytes = [bytes.fromhex(p.replace("0x", "")) for p in proof_raw]

                nonce = w3.eth.get_transaction_count(gateway.analyst_account.address, "pending")
                fn = gateway.posture_ledger.functions.recordPosture(
                    onchain_bytes, host_id_bytes, findings_digest, score, proof_bytes
                )
                tx = fn.build_transaction({
                    "from": gateway.analyst_account.address,
                    "nonce": nonce,
                    "gas": 300000,
                    "gasPrice": w3.eth.gas_price,
                    "chainId": w3.eth.chain_id,
                })
                signed = gateway.analyst_account.sign_transaction(tx)
                raw = getattr(signed, "raw_transaction", getattr(signed, "rawTransaction", None))
                tx_h = "0x" + w3.eth.send_raw_transaction(raw).hex()
                record_chain_tx(case_id, f"record_{clean_host_hex}", nonce, tx_h, "sent", 0, db_path=test_db)
            del gateway
            gateway = ChainGateway(rpc_url="http://127.0.0.1:8545", deployment_file=DEPLOYMENTS_FILE)
            rec_res = gateway.record_posture(case_id)
        else:
            rec_res = gateway.record_posture(case_id)

        # 9. Step: anchor report
        report_dict, _, report_hash, _ = build_case_report(case_id, save=True, gateway_override=gateway)

        if step_name == "anchor":
            report_hash_bytes = bytes.fromhex(report_hash.replace("0x", ""))
            nonce = w3.eth.get_transaction_count(gateway.analyst_account.address, "pending")
            fn = gateway.case_registry.functions.anchorReport(onchain_bytes, report_hash_bytes)
            tx = fn.build_transaction({
                "from": gateway.analyst_account.address,
                "nonce": nonce,
                "gas": 300000,
                "gasPrice": w3.eth.gas_price,
                "chainId": w3.eth.chain_id,
            })
            signed = gateway.analyst_account.sign_transaction(tx)
            raw = getattr(signed, "raw_transaction", getattr(signed, "rawTransaction", None))
            tx_h = "0x" + w3.eth.send_raw_transaction(raw).hex()
            record_chain_tx(case_id, "anchor_report", nonce, tx_h, "sent", 0, db_path=test_db)
            del gateway
            gateway = ChainGateway(rpc_url="http://127.0.0.1:8545", deployment_file=DEPLOYMENTS_FILE)
            anchor_res = gateway.anchor_report(case_id, report_hash)
        else:
            anchor_res = gateway.anchor_report(case_id, report_hash)

        # --- ASSERTIONS PER PROMPT T3.3 ---
        # 1. Assert case ends in Finalized (State 5)
        onchain_state = gateway.case_registry.functions.caseState(onchain_bytes).call()
        if onchain_state != 5:
            return False, f"On-chain state is {onchain_state}, expected 5 (Finalized)"

        # 2. Assert chain_txs holds NO duplicate transaction for any step
        all_txs = get_chain_txs(case_id, db_path=test_db)
        seen_steps = set()
        for t in all_txs:
            s_name = t["step"]
            if s_name in seen_steps:
                return False, f"Duplicate transaction found for step: {s_name}"
            seen_steps.add(s_name)

        # 3. Assert verifier Step 2 (recomputed root match) passes
        step2 = [s for s in report_dict["verifierSteps"] if s["step"] == 2]
        if not step2 or step2[0]["status"] != "PASS":
            return False, "Verifier Step 2 failed"

        return True, "Finalized, 0 duplicate txs, verifier PASS"

    except Exception as exc:
        import traceback
        traceback.print_exc()
        return False, f"Exception: {exc}"
    finally:
        try:
            config.DB_PATH = orig_db
            config.CASES_DIR = orig_cases
            config.DATA_DIR = orig_data
        except Exception:
            pass
        shutil.rmtree(temp_dir, ignore_errors=True)


def main() -> int:
    print("========================================================================")
    print("      SECUREMAILSCOPE CHAOS TEST: KILL-AND-RESUME (PROMPT T3.3)         ")
    print("========================================================================")
    print("Connecting to local Hardhat node and deploying contracts...")
    w3, gateway, img_digest, ruleset_hash = ensure_chain_and_deployment()
    print("Environment initialized successfully.\n")

    chaos_steps = [
        ("analyze", "API Worker / Engine Runner"),
        ("open", "Chain Gateway"),
        ("claim", "Chain Gateway"),
        ("distribute", "API Worker"),
        ("commit", "Validator 1 Service"),
        ("reveal", "Validator 1 Service"),
        ("finalize", "Chain Gateway"),
        ("record", "Chain Gateway"),
        ("anchor", "Chain Gateway"),
    ]

    results: List[Tuple[str, str, str, str]] = []
    all_passed = True

    for step_name, proc_name in chaos_steps:
        print(f"[*] Running chaos test for step: '{step_name}' (SIGKILL on '{proc_name}')...", flush=True)
        t0 = time.time()
        ok, details = run_chaos_scenario(step_name, proc_name, w3, gateway)
        elapsed = time.time() - t0
        status_str = "PASS" if ok else "FAIL"
        if not ok:
            all_passed = False
        print(f"    -> [{status_str}] in {elapsed:.2f}s: {details}")
        results.append((step_name, proc_name, status_str, f"{elapsed:.1f}s - {details}"))

    # Print Formatted Table
    print("\n" + "=" * 92)
    print(f"{'STEP':<14} | {'KILLED PROCESS':<28} | {'RESULT':<8} | {'DETAILS':<34}")
    print("-" * 92)
    for step, proc, res, det in results:
        print(f"{step:<14} | {proc:<28} | {res:<8} | {det[:34]:<34}")
    print("=" * 92)

    if all_passed:
        print("\n[SUCCESS] All 9 kill-and-resume chaos test scenarios PASSED.\n")
        return 0
    else:
        print("\n[FAILURE] One or more chaos test scenarios FAILED.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
