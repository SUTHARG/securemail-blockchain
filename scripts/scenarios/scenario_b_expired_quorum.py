"""Scenario (b): Fewer Than k Validators Reveal and Case Ends Expired.

Asserts that if participation is below quorum k when the reveal window elapses,
calling finalize() transitions the case to State.Expired (7).
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


def run_scenario_b():
    print("================================================================================")
    print("       SCENARIO (B): FEWER THAN K VALIDATORS REVEAL -> STATE EXPIRED           ")
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

        # Add 3 validators (N=3, k=2)
        for i in range(1, 4):
            val_addr = Web3.to_checksum_address(ACCOUNTS[i]["address"])
            send_tx(w3, case_registry.functions.addValidator(val_addr), admin_acc, ACCOUNTS[0]["key"])

        # Open case
        s05_path = repo_root / "lab" / "captures" / "S05.pcap"
        pcap_content = s05_path.read_bytes() if s05_path.exists() else b"SCENARIO_B_EXPIRED_TEST_PCAP_STREAM"
        pcap_sha256_bytes = hashlib.sha256(pcap_content).digest()
        open_rc = send_tx(w3, case_registry.functions.openCase(pcap_sha256_bytes), admin_acc, ACCOUNTS[0]["key"])
        case_id_bytes = case_registry.events.CaseOpened().process_receipt(open_rc)[0].args.caseId
        case_id_hex = case_id_bytes.hex()
        print(f"[*] Case opened: 0x{case_id_hex[:16]}...")

        with tempfile.TemporaryDirectory() as td:
            temp_pcap = Path(td) / "capture.pcap"
            temp_pcap.write_bytes(pcap_content)
            analyst_out = Path(td) / "out"
            org_secret_hex = "22334455667788990011aabbccddeeff22334455667788990011aabbccddeeff"

            subprocess.run([
                sys.executable, "-m", "smscope", "analyze",
                str(temp_pcap), "--org-secret-hex", org_secret_hex,
                "--out", str(analyst_out),
            ], check=True, capture_output=True)

            with open(analyst_out / "result.json") as f:
                root_hex = json.load(f)["resultRoot"].replace("0x", "")
            root_bytes = bytes.fromhex(root_hex)

            # Submit claim
            send_tx(w3, quorum.functions.submitClaim(
                case_id_bytes, root_bytes, image_digest_bytes, ruleset_hash_bytes
            ), admin_acc, ACCOUNTS[0]["key"])
            print(f"[+] Claim submitted with root: 0x{root_hex[:12]}...")

            # Validator 1 commits and will reveal
            # Validator 2 commits but will NOT reveal
            # Validator 3 does not reveal either
            # Total reveals will be 1 (< k=2)

            env1 = os.environ.copy()
            env1["VAL_KEY_1"] = ACCOUNTS[1]["key"]
            p1 = subprocess.Popen([
                sys.executable, "-m", "validator.node",
                "--case-id", case_id_hex, "--pcap", str(temp_pcap),
                "--org-secret-hex", org_secret_hex, "--key-env", "VAL_KEY_1",
                "--deployment-file", str(deployment_file),
            ], env=env1, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Wait for Validator 1 to commit
            for _ in range(60):
                if quorum.functions.hasCommitted(case_id_bytes, 1, ACCOUNTS[1]["address"]).call():
                    print("[+] Validator 1 committed.")
                    break
                time.sleep(0.5)

            # Validator 2 manually commits directly to simulate committing but abandoning before reveal
            val2_acc = Account.from_key(ACCOUNTS[2]["key"])
            salt2 = os.urandom(32)
            from eth_abi import encode
            c2_hash = Web3.keccak(encode(
                ["bytes32", "address", "bytes32", "bytes32"],
                [case_id_bytes, ACCOUNTS[2]["address"], root_bytes, salt2]
            ))
            send_tx(w3, quorum.functions.commit(case_id_bytes, c2_hash), val2_acc, ACCOUNTS[2]["key"])
            print("[+] Validator 2 committed.")

            # Advance past commit window
            print("[*] Advancing time past commit deadline (evm_increaseTime + 65s)...")
            w3.provider.make_request("evm_increaseTime", [65])
            w3.provider.make_request("evm_mine", [])

            # Wait for Validator 1 to complete reveal
            p1.wait(timeout=30)
            print("[+] Validator 1 revealed.")

            # Confirm only 1 reveal exists (totalReveals = 1 < k = 2)
            round_params = quorum.functions.getRoundParams(case_id_bytes, 1).call()
            total_reveals = round_params[4]
            quorum_k = round_params[1]
            print(f"[*] On-chain status: totalReveals={total_reveals}, required quorum k={quorum_k}")
            assert total_reveals == 1, f"Expected exactly 1 reveal, got {total_reveals}"
            assert quorum_k == 2, f"Expected quorum k=2, got {quorum_k}"

            # Advance past reveal deadline
            print("[*] Advancing time past reveal deadline (evm_increaseTime + 70s)...")
            w3.provider.make_request("evm_increaseTime", [70])
            w3.provider.make_request("evm_mine", [])

            # Now call finalize(): since reveal window elapsed and totalReveals < k, must transition to Expired (7)
            print("[*] Calling finalize() after reveal window expiration...")
            send_tx(w3, quorum.functions.finalize(case_id_bytes), admin_acc, ACCOUNTS[0]["key"])

            final_state = case_registry.functions.caseState(case_id_bytes).call()
            print(f"[*] Final case state on-chain: {final_state}")

            assert final_state == 7, f"Expected State.Expired (7), got {final_state}"
            print("[SUCCESS] Fewer than k validators revealed and case ended in Expired state (7).")

    finally:
        node_proc.terminate()
        try:
            node_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            node_proc.kill()


if __name__ == "__main__":
    run_scenario_b()
