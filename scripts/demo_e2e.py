"""End-to-End Demonstration for SecureMailScope (Prompt 3.2).

Starts Hardhat node, deploys contracts, registers engine, adds validators,
opens case, analyzes PCAP, submits claim, runs 3 validator node processes,
time travels to reveal, finalizes case, records per-host posture,
anchors report, and prints custody log table.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "engine"))

from eth_account import Account
from web3 import Web3

try:
    from engine.smscope.rules import compute_ruleset_hash
    from engine.smscope.results.canonical import canonical_json
except ImportError:
    from smscope.rules import compute_ruleset_hash
    from smscope.results.canonical import canonical_json

STATE_NAMES = {
    0: "None",
    1: "Opened",
    2: "Claimed",
    3: "Committing",
    4: "Revealing",
    5: "Finalized",
    6: "Disputed",
    7: "Expired",
    8: "Rejected",
}

# Standard Hardhat dev accounts
DEV_KEYS = [
    ("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", "Admin / Analyst"),
    ("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", "Validator 1"),
    ("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a", "Validator 2"),
    ("0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6", "Validator 3"),
]

ACCOUNTS = [
    {
        "address": Account.from_key(k).address,
        "key": k,
        "role": r,
    }
    for k, r in DEV_KEYS
]


def send_tx(w3: Web3, contract_fn: Any, account: Any, private_key: str) -> Any:
    nonce = w3.eth.get_transaction_count(account.address, "pending")
    try:
        gas_est = contract_fn.estimate_gas({"from": account.address})
        gas = int(gas_est * 1.3)
    except Exception:
        gas = 600000

    tx_params = {
        "from": account.address,
        "nonce": nonce,
        "gas": gas,
        "gasPrice": w3.eth.gas_price,
        "chainId": w3.eth.chain_id,
    }
    tx = contract_fn.build_transaction(tx_params)
    signed = account.sign_transaction(tx)
    raw_tx = getattr(signed, "raw_transaction", getattr(signed, "rawTransaction", None))
    tx_hash = w3.eth.send_raw_transaction(raw_tx)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    if receipt.status != 1:
        raise RuntimeError(f"Transaction failed: {tx_hash.hex()}")
    return receipt


def main():
    repo_root = Path(__file__).resolve().parents[1]
    contracts_dir = repo_root / "contracts"
    rpc_url = "http://127.0.0.1:8545"

    steps_log: List[Tuple[str, str, str]] = []

    def log_step(step_name: str, tx_hash: str, case_state_str: str):
        steps_log.append((step_name, tx_hash, case_state_str))
        print(f"[{step_name}] tx: {tx_hash[:18]}... | state: {case_state_str}")

    print("================================================================")
    print("      SECUREMAILSCOPE END-TO-END DEMONSTRATION (PROMPT 3.2)     ")
    print("================================================================")

    # 1. Start Hardhat node as a subprocess
    print("[1] Starting local Hardhat node...", flush=True)
    node_log_file = open(contracts_dir / "hardhat_node.log", "w", encoding="utf-8")
    node_proc = subprocess.Popen(
        "npx hardhat node",
        cwd=str(contracts_dir),
        shell=True,
        stdout=node_log_file,
        stderr=node_log_file,
    )

    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        for _ in range(30):
            if w3.is_connected():
                print("[+] Connected to Hardhat node.")
                break
            time.sleep(0.5)
        else:
            raise TimeoutError("Failed to connect to local Hardhat node at 127.0.0.1:8545")

        # 2. Deploy contracts
        print("[2] Deploying smart contract suite to local node...")
        deploy_res = subprocess.run(
            "npx hardhat run scripts/deploy.ts --network localhost",
            cwd=str(contracts_dir),
            shell=True,
            capture_output=True,
            text=True,
        )
        if deploy_res.returncode != 0:
            raise RuntimeError(f"Deploy script failed: {deploy_res.stderr}\n{deploy_res.stdout}")
        print("[+] Contracts deployed successfully.")

        # Load deployments
        deployment_file = contracts_dir / "deployments" / "local.json"
        with open(deployment_file, "r", encoding="utf-8") as f:
            deployment = json.load(f)

        def get_contract(name: str):
            meta = deployment["contracts"][name]
            abi_path = contracts_dir / meta["abiPath"]
            with open(abi_path, "r", encoding="utf-8") as af:
                artifact = json.load(af)
            return w3.eth.contract(address=Web3.to_checksum_address(meta["address"]), abi=artifact["abi"])

        case_registry = get_contract("CaseRegistry")
        quorum = get_contract("ValidationQuorum")
        posture_ledger = get_contract("PostureLedger")

        admin_account = Account.from_key(ACCOUNTS[0]["key"])
        analyst_account = admin_account

        # 3. Register engine
        # In dev, use a 32-byte dev digest (non-zero per Decision 003 and EngineNotConfigured guard)
        image_digest_bytes = bytes.fromhex("00" * 31 + "01")
        os.environ["ENGINE_IMAGE_DIGEST"] = f"0x{image_digest_bytes.hex()}"
        ruleset_hash_hex = compute_ruleset_hash()
        ruleset_hash_bytes = bytes.fromhex(ruleset_hash_hex)

        print(f"[3] Registering engine on-chain (imageDigest=0x{image_digest_bytes.hex()[:12]}..., rulesetHash=0x{ruleset_hash_hex[:12]}...)...", flush=True)
        reg_fn = case_registry.functions.registerEngine(image_digest_bytes, ruleset_hash_bytes)
        reg_receipt = send_tx(w3, reg_fn, admin_account, ACCOUNTS[0]["key"])
        log_step("registerEngine", reg_receipt.transactionHash.hex(), "N/A")

        # 4. Add 3 validators
        print("[4] Registering 3 validators in CaseRegistry...")
        for i in range(1, 4):
            val_addr = Web3.to_checksum_address(ACCOUNTS[i]["address"])
            add_val_fn = case_registry.functions.addValidator(val_addr)
            add_receipt = send_tx(w3, add_val_fn, admin_account, ACCOUNTS[0]["key"])
            log_step(f"addValidator({i})", add_receipt.transactionHash.hex(), "N/A")

        # 5. openCase(SHA-256 of PCAP)
        print("[5] Opening forensic case in CaseRegistry...")
        s05_path = repo_root / "lab" / "captures" / "S05.pcap"
        if s05_path.exists():
            pcap_content = s05_path.read_bytes()
        else:
            pcap_content = b"SECUREMAILSCOPE_FORENSIC_PCAP_STREAM_DATA_M1_DEMO"
        pcap_sha256_bytes = hashlib.sha256(pcap_content).digest()
        pcap_sha256_hex = pcap_sha256_bytes.hex()

        open_fn = case_registry.functions.openCase(pcap_sha256_bytes)
        open_receipt = send_tx(w3, open_fn, analyst_account, ACCOUNTS[0]["key"])

        # Extract caseId from CaseOpened event log
        case_opened_event = case_registry.events.CaseOpened().process_receipt(open_receipt)[0]
        case_id_bytes = case_opened_event.args.caseId
        case_id_hex = case_id_bytes.hex()
        log_step("openCase", open_receipt.transactionHash.hex(), STATE_NAMES[1])

        # 6. Analysis stage
        print(f"[6] Running engine analysis for Case 0x{case_id_hex[:12]}...")
        with tempfile.TemporaryDirectory() as td:
            temp_pcap = Path(td) / "capture.pcap"
            temp_pcap.write_bytes(pcap_content)
            analyst_out = Path(td) / "engine_out"
            org_secret_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

            cmd = [
                sys.executable,
                "-m",
                "smscope",
                "analyze",
                str(temp_pcap),
                "--org-secret-hex",
                org_secret_hex,
                "--out",
                str(analyst_out),
                "--case-id",
                case_id_hex,
            ]
            run_res = subprocess.run(cmd, capture_output=True, text=True)
            if run_res.returncode != 0:
                raise RuntimeError(f"Analysis engine CLI failed: {run_res.stderr}")

            with open(analyst_out / "result.json", "r", encoding="utf-8") as f:
                result_data = json.load(f)
            with open(analyst_out / "host_scores.json", "r", encoding="utf-8") as f:
                host_scores = json.load(f)
            with open(analyst_out / "host_proofs.json", "r", encoding="utf-8") as f:
                host_proofs = json.load(f)

            result_root_hex = result_data["resultRoot"].replace("0x", "")
            result_root_bytes = bytes.fromhex(result_root_hex)

            # 7. submitClaim
            print(f"[7] Submitting claim with resultRoot 0x{result_root_hex[:12]}...")
            claim_fn = quorum.functions.submitClaim(
                case_id_bytes,
                result_root_bytes,
                image_digest_bytes,
                ruleset_hash_bytes,
            )
            claim_receipt = send_tx(w3, claim_fn, analyst_account, ACCOUNTS[0]["key"])
            cur_state = case_registry.functions.caseState(case_id_bytes).call()
            log_step("submitClaim", claim_receipt.transactionHash.hex(), STATE_NAMES[cur_state])

            # 8. Run 3 validator processes
            print("[8] Starting 3 validator node processes in parallel...", flush=True)
            val_procs = []
            val_logs = []
            env_base = os.environ.copy()

            val_log_dir = repo_root / "validator_state" / "logs"
            val_log_dir.mkdir(parents=True, exist_ok=True)

            for i in range(1, 4):
                key_env_var = f"DEMO_VAL_KEY_{i}"
                env_base[key_env_var] = ACCOUNTS[i]["key"]
                log_p = val_log_dir / f"val_{i}.log"
                lf = open(log_p, "w", encoding="utf-8")
                val_logs.append((i, lf, log_p))
                val_cmd = [
                    sys.executable,
                    "-u",
                    "-m",
                    "validator.node",
                    "--case-id",
                    case_id_hex,
                    "--pcap",
                    str(temp_pcap),
                    "--org-secret-hex",
                    org_secret_hex,
                    "--key-env",
                    key_env_var,
                    "--rpc-url",
                    rpc_url,
                    "--deployment-file",
                    str(deployment_file),
                ]
                proc = subprocess.Popen(val_cmd, env=env_base, stdout=lf, stderr=lf)
                val_procs.append((i, proc))

            # Wait until all 3 validators have committed
            print("[*] Waiting for commitments from all 3 validators...", flush=True)
            for _ in range(60):
                c1 = quorum.functions.hasCommitted(case_id_bytes, 1, Web3.to_checksum_address(ACCOUNTS[1]["address"])).call()
                c2 = quorum.functions.hasCommitted(case_id_bytes, 1, Web3.to_checksum_address(ACCOUNTS[2]["address"])).call()
                c3 = quorum.functions.hasCommitted(case_id_bytes, 1, Web3.to_checksum_address(ACCOUNTS[3]["address"])).call()
                if c1 and c2 and c3:
                    print("[+] All 3 validators submitted commitments on-chain.", flush=True)
                    log_step("commitValidators", "3 commits confirmed", STATE_NAMES[3])
                    break
                time.sleep(0.5)
            else:
                for i, lf, log_p in val_logs:
                    lf.flush()
                    print(f"Log for val_{i}:\n{log_p.read_text(encoding='utf-8')}", flush=True)
                raise TimeoutError("Validators did not commit within timeout")

            # 9. Time travel with evm_increaseTime and evm_mine
            print("[9] Advancing time past commit deadline (evm_increaseTime + 65s)...", flush=True)
            w3.provider.make_request("evm_increaseTime", [65])
            w3.provider.make_request("evm_mine", [])

            # Wait for all 3 validator processes to complete reveal
            print("[*] Waiting for validator reveals...", flush=True)
            for i, p in val_procs:
                p.wait(timeout=60)
                val_logs[i - 1][1].close()
                if p.returncode != 0:
                    log_content = val_logs[i - 1][2].read_text(encoding="utf-8")
                    raise RuntimeError(f"Validator {i} failed (code {p.returncode}):\n{log_content}")
                print(f"[+] Validator {i} finished cleanly.", flush=True)

            cur_state = case_registry.functions.caseState(case_id_bytes).call()
            log_step("revealValidators", "3 reveals confirmed", STATE_NAMES[cur_state])

            # 10. finalize
            print("[10] Triggering finalize()...")
            fin_fn = quorum.functions.finalize(case_id_bytes)
            fin_receipt = send_tx(w3, fin_fn, admin_account, ACCOUNTS[0]["key"])
            cur_state = case_registry.functions.caseState(case_id_bytes).call()
            log_step("finalize", fin_receipt.transactionHash.hex(), STATE_NAMES[cur_state])
            assert cur_state == 5, f"Expected state Finalized (5), got {cur_state}"

            # 11. recordPosture for every host using host_proofs.json
            print(f"[11] Recording posture in PostureLedger for {len(host_scores)} hosts...")
            for host in host_scores:
                h_id_bytes = bytes.fromhex(host["hostId"].replace("0x", ""))
                score_val = host["score"]
                f_digest_bytes = bytes.fromhex(host["findingsDigest"].replace("0x", ""))
                raw_proof = host_proofs[host["hostId"]]
                proof_bytes_list = [bytes.fromhex(p.replace("0x", "")) for p in raw_proof]

                posture_fn = posture_ledger.functions.recordPosture(
                    case_id_bytes,
                    h_id_bytes,
                    f_digest_bytes,
                    score_val,
                    proof_bytes_list,
                )
                posture_receipt = send_tx(w3, posture_fn, analyst_account, ACCOUNTS[0]["key"])
                log_step(f"recordPosture({host['hostId'][:8]}...)", posture_receipt.transactionHash.hex(), STATE_NAMES[5])

            # 12. anchorReport (SHA-256 of placeholder report.json)
            print("[12] Anchoring report hash in CaseRegistry...")
            report_placeholder = {
                "caseId": f"0x{case_id_hex}",
                "summary": "SecureMailScope Automated Forensic Assessment Report",
                "finalRoot": f"0x{result_root_hex}",
                "hosts": host_scores,
                "timestamp": int(time.time()),
            }
            report_bytes = canonical_json(report_placeholder)
            report_sha256_bytes = hashlib.sha256(report_bytes).digest()

            anchor_fn = case_registry.functions.anchorReport(case_id_bytes, report_sha256_bytes)
            anchor_receipt = send_tx(w3, anchor_fn, analyst_account, ACCOUNTS[0]["key"])
            log_step("anchorReport", anchor_receipt.transactionHash.hex(), STATE_NAMES[5])

            # Verify on-chain final state
            final_state_val = case_registry.functions.caseState(case_id_bytes).call()
            final_report_val = case_registry.functions.reportHash(case_id_bytes).call()
            assert final_state_val == 5, f"Case not in Finalized state! Got {final_state_val}"
            assert final_report_val == report_sha256_bytes, "Report hash mismatch on-chain!"
            print("[+] Verified on-chain: State=Finalized, Report anchored, Posture records committed.", flush=True)

    finally:
        print("[*] Terminating Hardhat node process...", flush=True)
        node_proc.terminate()
        try:
            node_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            node_proc.kill()
        node_log_file.close()
        print("[+] Hardhat node shut down.", flush=True)

    # 13. Print custody log table
    print("\n================================================================================")
    print("                    CUSTODY AUDIT LOG & TRANSACTION SUMMARY                    ")
    print("================================================================================")
    print(f"{'Step Name':<28} | {'Transaction / Result':<42} | {'Case State'}")
    print("-" * 84)
    for step_name, tx_h, state_s in steps_log:
        print(f"{step_name:<28} | {tx_h:<42} | {state_s}")
    print("================================================================================\n")
    print("[SUCCESS] End-to-end walking skeleton execution completed successfully!")


if __name__ == "__main__":
    main()
