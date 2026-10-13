"""Scenario (d): One Changed Finding in findings.json Fails Verifier Step 2.

Asserts that altering a single finding in findings.json causes Verifier Step 2
(Leaves and result root rebuilt from findings and scores equal result.json) to FAIL
and verifier to exit with non-zero code.
"""
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Add repo and engine to path
repo_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "engine"))

from eth_account import Account
from web3 import Web3

try:
    from engine.smscope.rules import compute_ruleset_hash
    from engine.smscope.results.canonical import canonical_json
except ImportError:
    from smscope.rules import compute_ruleset_hash
    from smscope.results.canonical import canonical_json

DEV_KEYS = [
    ("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", "Admin / Analyst"),
    ("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", "Validator 1"),
    ("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a", "Validator 2"),
    ("0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6", "Validator 3"),
]

ACCOUNTS = [
    {"address": Account.from_key(k).address, "key": k, "role": r}
    for k, r in DEV_KEYS
]


def send_tx(w3: Web3, contract_fn, account, private_key: str):
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


def run_scenario_d():
    print("================================================================================")
    print("       SCENARIO (D): 1 CHANGED FINDING IN findings.json FAILS STEP 2            ")
    print("================================================================================")

    contracts_dir = repo_root / "contracts"
    rpc_url = "http://127.0.0.1:8545"

    node_proc = subprocess.Popen(
        "npx hardhat node",
        cwd=str(contracts_dir),
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        for _ in range(30):
            if w3.is_connected():
                break
            time.sleep(0.5)
        else:
            raise TimeoutError("Could not connect to Hardhat node")

        # Deploy contracts
        subprocess.run(
            "npx hardhat run scripts/deploy.ts --network localhost",
            cwd=str(contracts_dir),
            shell=True,
            check=True,
            capture_output=True,
        )

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

        admin_acc = Account.from_key(ACCOUNTS[0]["key"])

        # Register engine
        image_digest_bytes = bytes.fromhex("00" * 31 + "01")
        os.environ["ENGINE_IMAGE_DIGEST"] = f"0x{image_digest_bytes.hex()}"
        ruleset_hash_hex = compute_ruleset_hash()
        ruleset_hash_bytes = bytes.fromhex(ruleset_hash_hex)

        send_tx(w3, case_registry.functions.registerEngine(image_digest_bytes, ruleset_hash_bytes), admin_acc, ACCOUNTS[0]["key"])

        # Add validators
        for i in range(1, 4):
            val_addr = Web3.to_checksum_address(ACCOUNTS[i]["address"])
            send_tx(w3, case_registry.functions.addValidator(val_addr), admin_acc, ACCOUNTS[0]["key"])

        # Open case
        s05_path = repo_root / "lab" / "captures" / "S05.pcap"
        original_pcap_bytes = s05_path.read_bytes() if s05_path.exists() else b"SCENARIO_D_ORIGINAL_AUTHENTIC_PCAP_DATA"
        pcap_sha256_bytes = hashlib.sha256(original_pcap_bytes).digest()
        open_rc = send_tx(w3, case_registry.functions.openCase(pcap_sha256_bytes), admin_acc, ACCOUNTS[0]["key"])
        case_id_bytes = case_registry.events.CaseOpened().process_receipt(open_rc)[0].args.caseId
        case_id_hex = case_id_bytes.hex()
        print(f"[*] Case opened: 0x{case_id_hex[:16]}...")

        with tempfile.TemporaryDirectory() as td:
            pcap_file = Path(td) / "original.pcap"
            pcap_file.write_bytes(original_pcap_bytes)

            findings_dir = Path(td) / "findings"
            org_secret_hex = "33445566778899001122aabbccddeeff33445566778899001122aabbccddeeff"

            subprocess.run([
                sys.executable, "-m", "smscope", "analyze",
                str(pcap_file), "--org-secret-hex", org_secret_hex,
                "--out", str(findings_dir),
            ], check=True, capture_output=True)

            with open(findings_dir / "result.json") as f:
                root_hex = json.load(f)["resultRoot"].replace("0x", "")
            root_bytes = bytes.fromhex(root_hex)

            with open(findings_dir / "host_scores.json") as f:
                host_scores = json.load(f)
            with open(findings_dir / "host_proofs.json") as f:
                host_proofs = json.load(f)

            # Submit claim
            send_tx(w3, quorum.functions.submitClaim(
                case_id_bytes, root_bytes, image_digest_bytes, ruleset_hash_bytes
            ), admin_acc, ACCOUNTS[0]["key"])

            # 2 validators commit and reveal
            val_procs = []
            env_base = os.environ.copy()
            for i in range(1, 3):
                env_base[f"KEY_{i}"] = ACCOUNTS[i]["key"]
                p = subprocess.Popen([
                    sys.executable, "-m", "validator.node",
                    "--case-id", case_id_hex, "--pcap", str(pcap_file),
                    "--org-secret-hex", org_secret_hex, "--key-env", f"KEY_{i}",
                    "--deployment-file", str(deployment_file),
                ], env=env_base, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                val_procs.append(p)

            for _ in range(60):
                c1 = quorum.functions.hasCommitted(case_id_bytes, 1, ACCOUNTS[1]["address"]).call()
                c2 = quorum.functions.hasCommitted(case_id_bytes, 1, ACCOUNTS[2]["address"]).call()
                if c1 and c2:
                    break
                time.sleep(0.5)

            w3.provider.make_request("evm_increaseTime", [65])
            w3.provider.make_request("evm_mine", [])

            for p in val_procs:
                p.wait(timeout=30)

            # Finalize
            send_tx(w3, quorum.functions.finalize(case_id_bytes), admin_acc, ACCOUNTS[0]["key"])

            # Record posture
            for h in host_scores:
                h_id_b = bytes.fromhex(h["hostId"].replace("0x", ""))
                f_dig_b = bytes.fromhex(h["findingsDigest"].replace("0x", ""))
                prf_b = [bytes.fromhex(x.replace("0x", "")) for x in host_proofs[h["hostId"]]]
                send_tx(w3, posture_ledger.functions.recordPosture(
                    case_id_bytes, h_id_b, f_dig_b, h["score"], prf_b
                ), admin_acc, ACCOUNTS[0]["key"])

            # Anchor report
            report_file = Path(td) / "report.json"
            report_data = {"caseId": case_id_hex, "summary": "Audit report", "timestamp": int(time.time())}
            report_bytes = canonical_json(report_data)
            report_file.write_bytes(report_bytes)
            report_hash = hashlib.sha256(report_bytes).digest()
            send_tx(w3, case_registry.functions.anchorReport(case_id_bytes, report_hash), admin_acc, ACCOUNTS[0]["key"])

            print("[+] Base case finalized and report anchored.")

            # Test 1: Verify authentic findings -> MUST PASS ALL 5 STEPS
            print("[*] Running verifier against authentic findings...")
            v_good = subprocess.run([
                sys.executable, "-m", "verifier.verify",
                "--case-id", case_id_hex,
                "--pcap", str(pcap_file),
                "--findings-dir", str(findings_dir),
                "--report", str(report_file),
                "--deployment-file", str(deployment_file),
            ], capture_output=True, text=True)

            print("Verifier output on authentic findings:\n" + v_good.stdout)
            assert v_good.returncode == 0, f"Verifier should succeed on authentic findings! Error: {v_good.stderr}"
            assert "[Step 2] Leaves and root rebuilt from findings and scores equal result.json: PASS" in v_good.stdout
            assert "[VERIFICATION RESULT] ALL FIVE STEPS PASSED SUCCESSFULLY." in v_good.stdout
            print("[SUCCESS] Authentic findings passed all five verifier steps.")

            # Test 2: Create tampered findings directory with 1 changed finding in findings.json
            tampered_findings_dir = Path(td) / "findings_tampered"
            shutil.copytree(findings_dir, tampered_findings_dir)

            tampered_findings_file = tampered_findings_dir / "findings.json"
            with open(tampered_findings_file, "r", encoding="utf-8") as f:
                findings_data = json.load(f)

            assert len(findings_data) > 0, "Expected at least one finding in findings.json"
            # Mutate 1 field of the first finding: e.g. ruleId or severity
            findings_data[0]["description"] = "TAMPERED: Modified finding description"
            with open(tampered_findings_file, "w", encoding="utf-8") as f:
                json.dump(findings_data, f, indent=2)

            print("[*] Running verifier against tampered findings.json (1 modified finding)...")
            v_bad = subprocess.run([
                sys.executable, "-m", "verifier.verify",
                "--case-id", case_id_hex,
                "--pcap", str(pcap_file),
                "--findings-dir", str(tampered_findings_dir),
                "--report", str(report_file),
                "--deployment-file", str(deployment_file),
            ], capture_output=True, text=True)

            print("Verifier output on tampered findings:\n" + v_bad.stdout)
            assert v_bad.returncode != 0, "Verifier should exit non-zero on tampered findings.json!"
            assert "[Step 1] PCAP SHA-256 equals on-chain pcapHash: PASS" in v_bad.stdout
            assert "[Step 2]" in v_bad.stdout and "FAIL" in v_bad.stdout, "Step 2 must FAIL on tampered findings!"
            assert "[VERIFICATION RESULT] ONE OR MORE VERIFICATION STEPS FAILED." in v_bad.stdout
            print("[SUCCESS] 1 changed finding was correctly caught and failed Verifier Step 2!")

    finally:
        node_proc.terminate()
        try:
            node_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            node_proc.kill()


if __name__ == "__main__":
    run_scenario_d()
