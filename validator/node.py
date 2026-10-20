"""SecureMailScope Validator Node.

CLI: python -m validator.node --case-id <hex> --pcap <path> --org-secret-hex <hex> --key-env <ENV_VAR_NAME> [--no-strict]
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from eth_abi import encode
from eth_account import Account
from web3 import Web3

try:
    from dotenv import load_dotenv
    repo_root = Path(__file__).resolve().parents[1]
    load_dotenv(repo_root / ".env")
except ImportError:
    pass

from validator.crypto import StrictModeError, parse_and_validate_engine_digest


def resolve_path(p: str, base_dir: Path) -> Path:
    path_obj = Path(p)
    if path_obj.is_absolute():
        return path_obj
    return base_dir / path_obj


def load_deployment(deployment_path: Path) -> Dict[str, Any]:
    if not deployment_path.exists():
        raise FileNotFoundError(f"Deployment file not found at: {deployment_path}")
    with open(deployment_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_contract_abi(deployment_dir: Path, abi_rel_path: str) -> list:
    # Look for ABI in contracts root
    contracts_root = deployment_dir.parent
    full_path = contracts_root / abi_rel_path
    if not full_path.exists():
        # Try relative to repo root
        repo_root = contracts_root.parent
        full_path = repo_root / "contracts" / abi_rel_path
    if not full_path.exists():
        raise FileNotFoundError(f"Contract artifact not found at: {full_path}")
    with open(full_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)
    return artifact["abi"]


def send_transaction(w3: Web3, contract_fn: Any, account: Any, private_key: str) -> Any:
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


def run_validator(
    case_id_hex: str,
    pcap_path: Path,
    org_secret_hex: str,
    key_env: Optional[str] = None,
    private_key_hex: Optional[str] = None,
    strict: bool = True,
    rpc_url: str = "http://127.0.0.1:8545",
    deployment_file: Optional[Path] = None,
    out_dir: Optional[Path] = None,
    state_dir: Optional[Path] = None,
    ruleset_path: Optional[Path] = None,
) -> Dict[str, Any]:
    # 1. Resolve private key from env or argument
    if private_key_hex:
        private_key = private_key_hex
    elif key_env:
        private_key = os.environ.get(key_env)
        if not private_key:
            raise ValueError(f"Environment variable '{key_env}' not set or empty")
    else:
        raise ValueError("Either private_key_hex or key_env must be provided")
    account = Account.from_key(private_key)
    validator_addr = Web3.to_checksum_address(account.address)
    print(f"[*] Validator Node running for address: {validator_addr}")

    # 2. Connect to web3
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise ConnectionError(f"Could not connect to Ethereum node at {rpc_url}")

    # 3. Load deployment contracts
    if deployment_file is None:
        repo_root = Path(__file__).resolve().parents[1]
        deployment_file = repo_root / "contracts" / "deployments" / "local.json"

    deployment = load_deployment(deployment_file)
    contracts_meta = deployment.get("contracts", deployment)

    reg_entry = contracts_meta.get("CaseRegistry", {})
    if "abi" in reg_entry:
        registry_abi = reg_entry["abi"]
    else:
        registry_abi = load_contract_abi(deployment_file.parent, reg_entry.get("abiPath", ""))
    registry_addr = Web3.to_checksum_address(reg_entry.get("address", "0x" + "0" * 40))
    case_registry = w3.eth.contract(address=registry_addr, abi=registry_abi)

    quorum_entry = contracts_meta.get("ValidationQuorum", {})
    if "abi" in quorum_entry:
        quorum_abi = quorum_entry["abi"]
    else:
        quorum_abi = load_contract_abi(deployment_file.parent, quorum_entry.get("abiPath", ""))
    quorum_addr = Web3.to_checksum_address(quorum_entry.get("address", "0x" + "0" * 40))
    quorum = w3.eth.contract(address=quorum_addr, abi=quorum_abi)

    # 4. Normalize caseId
    clean_case_hex = case_id_hex.lower().replace("0x", "")
    if len(clean_case_hex) != 64:
        raise ValueError(f"case-id must be 32 bytes (64 hex characters), got {case_id_hex}")
    case_id_bytes = bytes.fromhex(clean_case_hex)

    # 5. Check case exists on-chain and retrieve pinned hashes
    case_state = case_registry.functions.caseState(case_id_bytes).call()
    if case_state == 0:  # State.None
        raise RuntimeError(f"Case {case_id_hex} does not exist on-chain")

    case_round = case_registry.functions.caseRound(case_id_bytes).call()
    onchain_engine_hash = case_registry.functions.engineHash(case_id_bytes).call()
    onchain_ruleset_hash = case_registry.functions.rulesetHash(case_id_bytes).call()
    onchain_pcap_hash = case_registry.functions.pcapHash(case_id_bytes).call()

    # Check bundle metadata if present
    case_id_txt = pcap_path.parent / "onchain_case_id.txt"
    if case_id_txt.exists():
        txt_id = case_id_txt.read_text(encoding="utf-8").strip()
        clean_txt = txt_id.lower().replace("0x", "")
        clean_target = case_id_bytes.hex().lower().replace("0x", "")
        if clean_txt != clean_target:
            raise ValueError(
                f"Delivered bundle case ID (0x{clean_txt}) does not match target case ID (0x{clean_target})"
            )
    elif strict and pcap_path.name == "pcap.bin" and (pcap_path.parent / "org_secret.hex").exists():
        raise ValueError("Plaintext bundle missing onchain_case_id.txt in strict mode")

    # Validate delivered PCAP SHA-256 against on-chain pcapHash (fail-closed)
    pcap_sha256 = hashlib.sha256(pcap_path.read_bytes()).digest()
    if not onchain_pcap_hash or onchain_pcap_hash == b"\x00" * 32:
        raise ValueError("Target case has missing or zero on-chain pcapHash")
    if pcap_sha256 != onchain_pcap_hash:
        raise ValueError(
            f"Delivered PCAP hash (0x{pcap_sha256.hex()}) does not match on-chain case pcapHash (0x{onchain_pcap_hash.hex()})"
        )

    # 6. Run smscope analysis
    temp_dir_obj = None
    if out_dir is None:
        temp_dir_obj = tempfile.TemporaryDirectory()
        target_out = Path(temp_dir_obj.name)
    else:
        target_out = out_dir
        target_out.mkdir(parents=True, exist_ok=True)

    try:
        print(f"[*] Running analysis engine on {pcap_path} -> {target_out}")
        cmd = [
            sys.executable,
            "-m",
            "smscope",
            "analyze",
            str(pcap_path),
            "--org-secret-hex",
            org_secret_hex,
            "--out",
            str(target_out),
            "--case-id",
            case_id_hex,
        ]
        if ruleset_path:
            cmd.extend(["--ruleset", str(ruleset_path)])
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Engine analysis failed (code {res.returncode}): {res.stderr}")

        result_json_path = target_out / "result.json"
        manifest_json_path = target_out / "manifest.json"
        if not result_json_path.exists() or not manifest_json_path.exists():
            raise FileNotFoundError("Engine did not produce result.json or manifest.json")

        with open(result_json_path, "r", encoding="utf-8") as f:
            result_data = json.load(f)
        with open(manifest_json_path, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)

        local_root_hex = result_data["resultRoot"].lower().replace("0x", "")
        local_root_bytes = bytes.fromhex(local_root_hex)
        local_ruleset_hex = manifest_data["rulesetHash"].lower().replace("0x", "")
        local_engine_version = manifest_data["engineVersion"]

        print(f"[*] Engine produced resultRoot: 0x{local_root_hex}")

        # 7. Strict mode validation BEFORE committing
        if strict:
            onchain_ruleset_hex = onchain_ruleset_hash.hex().lower().replace("0x", "")
            if local_ruleset_hex != onchain_ruleset_hex:
                raise StrictModeError(
                    f"Strict mode violation: local rulesetHash (0x{local_ruleset_hex}) differs from "
                    f"on-chain case rulesetHash (0x{onchain_ruleset_hex})"
                )

            env_engine_digest = os.environ.get("ENGINE_IMAGE_DIGEST")
            clean_env_engine = parse_and_validate_engine_digest(env_engine_digest)
            onchain_engine_hex = onchain_engine_hash.hex().lower().replace("0x", "")
            if clean_env_engine != onchain_engine_hex:
                raise StrictModeError(
                    f"Strict mode violation: ENGINE_IMAGE_DIGEST (0x{clean_env_engine}) differs from "
                    f"on-chain case engineHash (0x{onchain_engine_hex})"
                )
            print("[+] Strict mode pre-commit checks passed")
        else:
            print("[!] Strict mode DISABLED (--no-strict); proceeding without digest/ruleset verification")

        # 8. Check validator snapshot eligibility
        is_in_snapshot = quorum.functions.isSnapshotValidator(case_id_bytes, case_round, validator_addr).call()
        if not is_in_snapshot:
            raise RuntimeError(f"Validator {validator_addr} is not in snapshot for case round {case_round}")

        # 9. Manage state directory & salt
        if state_dir is None:
            repo_root = Path(__file__).resolve().parents[1]
            state_dir = repo_root / "validator_state"
        state_dir.mkdir(parents=True, exist_ok=True)

        state_file = state_dir / f"{validator_addr.lower()}.json"
        temp_state_file = state_dir / f"{validator_addr.lower()}.json.tmp"

        already_committed = quorum.functions.hasCommitted(case_id_bytes, case_round, validator_addr).call()

        if not already_committed:
            # Generate random 32-byte salt
            salt_bytes = os.urandom(32)
            salt_hex = salt_bytes.hex()

            # Compute commitment = keccak256(abi.encode(caseId, validator, resultRoot, salt))
            encoded_payload = encode(
                ["bytes32", "address", "bytes32", "bytes32"],
                [case_id_bytes, validator_addr, local_root_bytes, salt_bytes],
            )
            commitment_bytes = Web3.keccak(encoded_payload)

            # Atomic write to validator_state/<address>.json
            state_payload = {
                "caseId": f"0x{clean_case_hex}",
                "round": case_round,
                "salt": f"0x{salt_hex}",
                "resultRoot": f"0x{local_root_hex}",
                "commitment": f"0x{commitment_bytes.hex()}",
                "strict": strict,
            }
            with open(temp_state_file, "w", encoding="utf-8") as f:
                json.dump(state_payload, f, indent=2)
            os.replace(temp_state_file, state_file)

            print(f"[*] Submitting commitment: 0x{commitment_bytes.hex()}")
            commit_fn = quorum.functions.commit(case_id_bytes, commitment_bytes)
            commit_receipt = send_transaction(w3, commit_fn, account, private_key)
            print(f"[+] Commit transaction confirmed (tx: {commit_receipt.transactionHash.hex()})")
        else:
            print(f"[*] Validator {validator_addr} has already committed. Reading saved salt from {state_file}")
            if not state_file.exists():
                raise FileNotFoundError(f"State file {state_file} missing for already-committed validator")
            with open(state_file, "r", encoding="utf-8") as f:
                saved_state = json.load(f)
            salt_bytes = bytes.fromhex(saved_state["salt"].replace("0x", ""))

        # 10. Wait until commit deadline
        round_params = quorum.functions.getRoundParams(case_id_bytes, case_round).call()
        commit_deadline = round_params[2]
        print(f"[*] Waiting for commit deadline: {commit_deadline}")

        while True:
            current_block = w3.eth.get_block("latest")
            if current_block.timestamp >= commit_deadline:
                break
            if getattr(w3.provider, "make_request", None):
                try:
                    if w3.eth.chain_id in (31337, 1337):
                        diff = commit_deadline - current_block.timestamp + 1
                        if diff > 0:
                            w3.provider.make_request("evm_increaseTime", [int(diff)])
                            w3.provider.make_request("evm_mine", [])
                    else:
                        w3.provider.make_request("evm_mine", [])
                except Exception:
                    pass
            time.sleep(0.5)

        # 11. Advance case state to Revealing if needed
        cur_state = case_registry.functions.caseState(case_id_bytes).call()
        if cur_state == 3:  # State.Committing
            try:
                print("[*] Commit window passed. Calling advance()...")
                advance_fn = quorum.functions.advance(case_id_bytes)
                send_transaction(w3, advance_fn, account, private_key)
                print("[+] advance() succeeded. Case moved to Revealing.")
            except Exception as e:
                # Could have been advanced by another validator in the meantime
                print(f"[*] advance() note: {e}")

        # 12. Submit reveal
        already_revealed = quorum.functions.hasRevealed(case_id_bytes, case_round, validator_addr).call()
        if not already_revealed:
            print(f"[*] Submitting reveal for root 0x{local_root_hex}...")
            reveal_fn = quorum.functions.reveal(
                case_id_bytes,
                local_root_bytes,
                salt_bytes,
                onchain_engine_hash,
                onchain_ruleset_hash,
            )
            reveal_receipt = send_transaction(w3, reveal_fn, account, private_key)
            print(f"[+] Reveal transaction confirmed (tx: {reveal_receipt.transactionHash.hex()})")
        else:
            print(f"[*] Validator {validator_addr} has already revealed.")

        return {
            "validator": validator_addr,
            "caseId": f"0x{clean_case_hex}",
            "resultRoot": f"0x{local_root_hex}",
            "salt": f"0x{salt_bytes.hex()}",
        }

    finally:
        if temp_dir_obj is not None:
            temp_dir_obj.cleanup()


process_case = run_validator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="validator.node",
        description="SecureMailScope Validator Node",
    )
    parser.add_argument("--case-id", required=True, type=str, help="Case ID hex")
    parser.add_argument("--pcap", required=True, type=str, help="Path to PCAP file")
    parser.add_argument("--org-secret-hex", required=True, type=str, help="Org secret hex")
    parser.add_argument("--key-env", required=True, type=str, help="Environment variable name with private key")
    parser.add_argument(
        "--no-strict",
        action="store_true",
        default=False,
        help="Disable strict mode ruleset and engine checks (simulates faulty validator)",
    )
    parser.add_argument("--rpc-url", type=str, default="http://127.0.0.1:8545", help="EVM RPC endpoint")
    parser.add_argument("--deployment-file", type=str, default=None, help="Path to local.json deployment file")
    parser.add_argument("--out", type=str, default=None, help="Output directory for engine artifacts")
    parser.add_argument("--state-dir", type=str, default=None, help="Directory to store validator commit salts")
    parser.add_argument("--ruleset", type=str, default=None, help="Path to ruleset.yaml file")
    return parser


def main(args=None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(args)

    pcap_path = Path(parsed.pcap)
    deployment_file = Path(parsed.deployment_file) if parsed.deployment_file else None
    out_dir = Path(parsed.out) if parsed.out else None
    state_dir = Path(parsed.state_dir) if parsed.state_dir else None
    ruleset_path = Path(parsed.ruleset) if parsed.ruleset else None

    strict_mode = not parsed.no_strict

    try:
        run_validator(
            case_id_hex=parsed.case_id,
            pcap_path=pcap_path,
            org_secret_hex=parsed.org_secret_hex,
            key_env=parsed.key_env,
            strict=strict_mode,
            rpc_url=parsed.rpc_url,
            deployment_file=deployment_file,
            out_dir=out_dir,
            state_dir=state_dir,
            ruleset_path=ruleset_path,
        )
        return 0
    except Exception as e:
        sys.stderr.write(f"Error in validator node: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
