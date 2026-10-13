"""Scenario (a): Minority Outvoted Validator.

One validator runs with --no-strict and a modified ruleset file,
produces a different root, and is outvoted while the case still finalizes.
The output names that validator as a minority revealer.
"""
import hashlib
import json
import os
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
except ImportError:
    from smscope.rules import compute_ruleset_hash

DEV_KEYS = [
    ("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", "Admin / Analyst"),
    ("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", "Validator 1"),
    ("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a", "Validator 2"),
    ("0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6", "Validator 3 (Minority)"),
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


def run_scenario_a():
    print("================================================================================")
    print("       SCENARIO (A): MINORITY DIVERGENT VALIDATOR OUTVOTED AT QUORUM          ")
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

        admin_acc = Account.from_key(ACCOUNTS[0]["key"])

        # Register engine
        image_digest_bytes = bytes.fromhex("00" * 31 + "01")
        os.environ["ENGINE_IMAGE_DIGEST"] = f"0x{image_digest_bytes.hex()}"
        ruleset_hash_hex = compute_ruleset_hash()
        ruleset_hash_bytes = bytes.fromhex(ruleset_hash_hex)

        send_tx(w3, case_registry.functions.registerEngine(image_digest_bytes, ruleset_hash_bytes), admin_acc, ACCOUNTS[0]["key"])

        # Add 3 validators
        for i in range(1, 4):
            val_addr = Web3.to_checksum_address(ACCOUNTS[i]["address"])
            send_tx(w3, case_registry.functions.addValidator(val_addr), admin_acc, ACCOUNTS[0]["key"])

        # Open case
        s05_path = repo_root / "lab" / "captures" / "S05.pcap"
        pcap_content = s05_path.read_bytes() if s05_path.exists() else b"SCENARIO_A_MINORITY_TEST_PCAP_STREAM"
        pcap_sha256_bytes = hashlib.sha256(pcap_content).digest()
        open_rc = send_tx(w3, case_registry.functions.openCase(pcap_sha256_bytes), admin_acc, ACCOUNTS[0]["key"])
        case_id_bytes = case_registry.events.CaseOpened().process_receipt(open_rc)[0].args.caseId
        case_id_hex = case_id_bytes.hex()
        print(f"[*] Case opened: 0x{case_id_hex[:16]}...")

        # Setup files and run analysis
        with tempfile.TemporaryDirectory() as td:
            temp_pcap = Path(td) / "capture.pcap"
            temp_pcap.write_bytes(pcap_content)
            analyst_out = Path(td) / "out"
            org_secret_hex = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"

            subprocess.run([
                sys.executable, "-m", "smscope", "analyze",
                str(temp_pcap), "--org-secret-hex", org_secret_hex,
                "--out", str(analyst_out),
            ], check=True, capture_output=True)

            with open(analyst_out / "result.json") as f:
                standard_root_hex = json.load(f)["resultRoot"].replace("0x", "")
            standard_root_bytes = bytes.fromhex(standard_root_hex)

            # Submit claim
            send_tx(w3, quorum.functions.submitClaim(
                case_id_bytes, standard_root_bytes, image_digest_bytes, ruleset_hash_bytes
            ), admin_acc, ACCOUNTS[0]["key"])
            print(f"[+] Claim submitted with standard root: 0x{standard_root_hex[:12]}...")

            # Create modified ruleset for Validator 3
            modified_ruleset_file = Path(td) / "modified_ruleset.yaml"
            with open(repo_root / "ruleset" / "ruleset.yaml", "r", encoding="utf-8") as f:
                rules_text = f.read()
            # Disable rule R01 in modified ruleset to produce different root
            modified_text = rules_text.replace("id: R01\n    title: Cleartext credentials sent before encryption\n    severity: Critical\n    enabled: true",
                                               "id: R01\n    title: Cleartext credentials sent before encryption\n    severity: Critical\n    enabled: false")
            modified_ruleset_file.write_text(modified_text, encoding="utf-8")

            # Launch Validator 1 and 2 (standard strict)
            env1 = os.environ.copy()
            env1["VAL_KEY_1"] = ACCOUNTS[1]["key"]
            p1 = subprocess.Popen([
                sys.executable, "-m", "validator.node",
                "--case-id", case_id_hex, "--pcap", str(temp_pcap),
                "--org-secret-hex", org_secret_hex, "--key-env", "VAL_KEY_1",
                "--deployment-file", str(deployment_file),
            ], env=env1, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            env2 = os.environ.copy()
            env2["VAL_KEY_2"] = ACCOUNTS[2]["key"]
            p2 = subprocess.Popen([
                sys.executable, "-m", "validator.node",
                "--case-id", case_id_hex, "--pcap", str(temp_pcap),
                "--org-secret-hex", org_secret_hex, "--key-env", "VAL_KEY_2",
                "--deployment-file", str(deployment_file),
            ], env=env2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Launch Validator 3 with --no-strict and modified ruleset
            val3_out = Path(td) / "val3_out"
            # Pre-run engine for val3 with modified ruleset to populate val3_out
            subprocess.run([
                sys.executable, "-m", "smscope", "analyze",
                str(temp_pcap), "--org-secret-hex", org_secret_hex,
                "--out", str(val3_out), "--ruleset", str(modified_ruleset_file),
            ], check=True, capture_output=True)

            with open(val3_out / "result.json") as f:
                divergent_root_hex = json.load(f)["resultRoot"].replace("0x", "")
            print(f"[!] Validator 3 produced divergent root: 0x{divergent_root_hex[:12]}...")
            assert divergent_root_hex != standard_root_hex, "Modified ruleset should produce divergent root!"

            env3 = os.environ.copy()
            env3["VAL_KEY_3"] = ACCOUNTS[3]["key"]
            p3 = subprocess.Popen([
                sys.executable, "-m", "validator.node",
                "--case-id", case_id_hex, "--pcap", str(temp_pcap),
                "--org-secret-hex", org_secret_hex, "--key-env", "VAL_KEY_3",
                "--deployment-file", str(deployment_file),
                "--no-strict",
                "--ruleset", str(modified_ruleset_file),
                "--out", str(val3_out),
            ], env=env3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Wait for all 3 commitments
            for _ in range(60):
                c1 = quorum.functions.hasCommitted(case_id_bytes, 1, ACCOUNTS[1]["address"]).call()
                c2 = quorum.functions.hasCommitted(case_id_bytes, 1, ACCOUNTS[2]["address"]).call()
                c3 = quorum.functions.hasCommitted(case_id_bytes, 1, ACCOUNTS[3]["address"]).call()
                if c1 and c2 and c3:
                    print("[+] All 3 validators committed.")
                    break
                time.sleep(0.5)
            else:
                raise TimeoutError("Commitments timeout")

            # Time travel past commit deadline
            w3.provider.make_request("evm_increaseTime", [65])
            w3.provider.make_request("evm_mine", [])

            p1.wait(timeout=30)
            p2.wait(timeout=30)
            p3.wait(timeout=30)
            print("[+] All 3 validators revealed their roots.")

            # Finalize case
            send_tx(w3, quorum.functions.finalize(case_id_bytes), admin_acc, ACCOUNTS[0]["key"])

            final_state = case_registry.functions.caseState(case_id_bytes).call()
            final_root_bytes = case_registry.functions.finalRoot(case_id_bytes).call()

            # Confirm Case is Finalized
            assert final_state == 5, f"Case state should be Finalized (5), got {final_state}"
            assert final_root_bytes == standard_root_bytes, "Finalized root must equal standard claimed root!"

            # Check validator reveal roots
            val1_root = quorum.functions.getValidatorRoot(case_id_bytes, 1, ACCOUNTS[1]["address"]).call()
            val2_root = quorum.functions.getValidatorRoot(case_id_bytes, 1, ACCOUNTS[2]["address"]).call()
            val3_root = quorum.functions.getValidatorRoot(case_id_bytes, 1, ACCOUNTS[3]["address"]).call()

            assert val1_root == final_root_bytes, "Validator 1 agreed with majority"
            assert val2_root == final_root_bytes, "Validator 2 agreed with majority"
            assert val3_root != final_root_bytes, "Validator 3 was in minority"

            print(f"[SUCCESS] Case finalized with root: 0x{final_root_bytes.hex()}")
            print(f"[SUCCESS] Majority revealers: {ACCOUNTS[1]['address']}, {ACCOUNTS[2]['address']}")
            print(f"[SUCCESS] Minority revealer: {ACCOUNTS[3]['address']} (outvoted divergent root: 0x{val3_root.hex()})")

    finally:
        node_proc.terminate()
        try:
            node_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            node_proc.kill()


if __name__ == "__main__":
    run_scenario_a()
