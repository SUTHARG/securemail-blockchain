"""SecureMailScope Verifier.

CLI: python -m verifier.verify --case-id <hex> --pcap <path> --findings-dir <dir> --report <path>
Performs the 5 steps of Section 8 and prints PASS or FAIL for each.
Exit code 0 only if all 5 pass.
"""
import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from eth_abi import encode
from web3 import Web3

# Ensure engine and root are on sys.path
repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "engine"))

try:
    from engine.smscope.results.canonical import canonical_json
    from engine.smscope.results.hashing import finding_leaf, host_score_leaf
    from engine.smscope.results.merkle import MerkleTree
except ImportError:
    from smscope.results.canonical import canonical_json
    from smscope.results.hashing import finding_leaf, host_score_leaf
    from smscope.results.merkle import MerkleTree


def load_deployment(deployment_path: Path) -> Dict[str, Any]:
    if not deployment_path.exists():
        raise FileNotFoundError(f"Deployment file not found at: {deployment_path}")
    with open(deployment_path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_contract_abi(deployment_dir: Path, abi_rel_path: str) -> list:
    contracts_root = deployment_dir.parent
    full_path = contracts_root / abi_rel_path
    if not full_path.exists():
        full_path = contracts_root.parent / "contracts" / abi_rel_path
    if not full_path.exists():
        raise FileNotFoundError(f"Contract artifact not found at: {full_path}")
    with open(full_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)
    return artifact["abi"]


def verify_case(
    case_id_hex: str,
    pcap_path: Path,
    findings_dir: Path,
    report_path: Path,
    rpc_url: str = "http://127.0.0.1:8545",
    deployment_file: Optional[Path] = None,
) -> bool:
    clean_case_hex = case_id_hex.lower().replace("0x", "")
    if len(clean_case_hex) != 64:
        raise ValueError(f"case-id must be 32 bytes (64 hex characters), got {case_id_hex}")
    case_id_bytes = bytes.fromhex(clean_case_hex)

    # 1. Connect to web3 and load contracts
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        raise ConnectionError(f"Could not connect to EVM RPC node at {rpc_url}")

    if deployment_file is None:
        deployment_file = repo_root / "contracts" / "deployments" / "local.json"

    deployment = load_deployment(deployment_file)
    contracts_meta = deployment["contracts"]

    registry_abi = load_contract_abi(deployment_file.parent, contracts_meta["CaseRegistry"]["abiPath"])
    registry_addr = Web3.to_checksum_address(contracts_meta["CaseRegistry"]["address"])
    case_registry = w3.eth.contract(address=registry_addr, abi=registry_abi)

    posture_abi = load_contract_abi(deployment_file.parent, contracts_meta["PostureLedger"]["abiPath"])
    posture_addr = Web3.to_checksum_address(contracts_meta["PostureLedger"]["address"])
    posture_ledger = w3.eth.contract(address=posture_addr, abi=posture_abi)

    all_pass = True

    print("================================================================================")
    print(f"            SECUREMAILSCOPE VERIFICATION SUITE: 0x{clean_case_hex[:16]}...       ")
    print("================================================================================")

    # --------------------------------------------------------------------------
    # Step 1: SHA-256 of the PCAP equals the on-chain pcapHash
    # --------------------------------------------------------------------------
    try:
        with open(pcap_path, "rb") as f:
            local_pcap_sha256 = hashlib.sha256(f.read()).hexdigest().lower()
        onchain_pcap_bytes = case_registry.functions.pcapHash(case_id_bytes).call()
        onchain_pcap_hex = onchain_pcap_bytes.hex().lower()

        if local_pcap_sha256 == onchain_pcap_hex:
            print("[Step 1] PCAP SHA-256 equals on-chain pcapHash: PASS")
        else:
            print(f"[Step 1] PCAP SHA-256 equals on-chain pcapHash: FAIL (local={local_pcap_sha256}, onchain={onchain_pcap_hex})")
            all_pass = False
    except Exception as e:
        print(f"[Step 1] PCAP SHA-256 check error: FAIL ({e})")
        all_pass = False

    # --------------------------------------------------------------------------
    # Step 2: Leaves and root rebuilt from findings.json and host_scores.json equal result.json
    # --------------------------------------------------------------------------
    recomputed_root_hex = None
    try:
        findings_file = findings_dir / "findings.json"
        scores_file = findings_dir / "host_scores.json"
        result_file = findings_dir / "result.json"

        with open(findings_file, "r", encoding="utf-8") as f:
            findings_data = json.load(f)
        with open(scores_file, "r", encoding="utf-8") as f:
            scores_data = json.load(f)
        with open(result_file, "r", encoding="utf-8") as f:
            expected_result = json.load(f)

        leaves_bytes: List[bytes] = []
        for f in findings_data:
            c_bytes = canonical_json(f)
            leaves_bytes.append(finding_leaf(c_bytes))

        for h in scores_data:
            leaves_bytes.append(host_score_leaf(h["hostId"], h["findingsDigest"], h["score"]))

        tree = MerkleTree(leaves_bytes)
        recomputed_root_hex = tree.root_hex.lower()
        expected_root_hex = expected_result["resultRoot"].lower().replace("0x", "")

        expected_leaf_hashes = sorted([l["leafHash"].lower().replace("0x", "") for l in expected_result["leaves"]])
        recomputed_leaf_hashes = sorted([l.hex().lower() for l in tree.leaves])

        if recomputed_root_hex == expected_root_hex and expected_leaf_hashes == recomputed_leaf_hashes:
            print("[Step 2] Leaves and root rebuilt from findings and scores equal result.json: PASS")
        else:
            print(f"[Step 2] Rebuilt root equals result.json: FAIL (rebuilt={recomputed_root_hex}, expected={expected_root_hex})")
            all_pass = False
    except Exception as e:
        print(f"[Step 2] Off-chain Merkle rebuild error: FAIL ({e})")
        all_pass = False

    # --------------------------------------------------------------------------
    # Step 3: That root equals the on-chain finalRoot
    # --------------------------------------------------------------------------
    try:
        onchain_final_bytes = case_registry.functions.finalRoot(case_id_bytes).call()
        onchain_final_hex = onchain_final_bytes.hex().lower()

        if recomputed_root_hex and recomputed_root_hex == onchain_final_hex:
            print("[Step 3] Recomputed root equals on-chain finalRoot: PASS")
        else:
            print(f"[Step 3] Recomputed root equals on-chain finalRoot: FAIL (recomputed={recomputed_root_hex}, onchain={onchain_final_hex})")
            all_pass = False
    except Exception as e:
        print(f"[Step 3] On-chain finalRoot check error: FAIL ({e})")
        all_pass = False

    # --------------------------------------------------------------------------
    # Step 4: For every host in host_scores.json, verify posture chain:
    #         recompute every recordHash and check every prevHash link
    # --------------------------------------------------------------------------
    try:
        scores_file = findings_dir / "host_scores.json"
        with open(scores_file, "r", encoding="utf-8") as f:
            scores_data = json.load(f)

        step4_ok = True
        total_records_checked = 0

        for h in scores_data:
            h_id_bytes = bytes.fromhex(h["hostId"].lower().replace("0x", ""))
            count = posture_ledger.functions.recordCount(h_id_bytes).call()
            if count == 0:
                print(f"[Step 4] No posture records found for host 0x{h['hostId'][:12]}: FAIL")
                step4_ok = False
                break

            prev_hash = bytes(32)
            for idx in range(count):
                rec = posture_ledger.functions.recordAt(h_id_bytes, idx).call()
                # rec: (hostId, caseId, score, resultRoot, prevHash, timestamp, recordHash)
                r_host, r_case, r_score, r_root, r_prev, r_ts, r_hash = rec

                # Check prevHash link
                if r_prev != prev_hash:
                    print(f"[Step 4] Host 0x{h['hostId'][:12]} index {idx} prevHash broken: FAIL (got {r_prev.hex()}, expected {prev_hash.hex()})")
                    step4_ok = False
                    break

                # Recompute recordHash = keccak256(abi.encode(hostId, caseId, score, resultRoot, prevHash, timestamp))
                encoded_rec = encode(
                    ["bytes32", "bytes32", "uint16", "bytes32", "bytes32", "uint256"],
                    [r_host, r_case, r_score, r_root, r_prev, r_ts],
                )
                computed_hash = Web3.keccak(encoded_rec)
                if computed_hash != r_hash:
                    print(f"[Step 4] Host 0x{h['hostId'][:12]} index {idx} recordHash mismatch: FAIL (computed {computed_hash.hex()}, onchain {r_hash.hex()})")
                    step4_ok = False
                    break

                prev_hash = r_hash
                total_records_checked += 1

            if not step4_ok:
                break

        if step4_ok:
            print(f"[Step 4] Posture chain verified ({total_records_checked} records checked): PASS")
        else:
            all_pass = False
    except Exception as e:
        print(f"[Step 4] Posture chain check error: FAIL ({e})")
        all_pass = False

    # --------------------------------------------------------------------------
    # Step 5: SHA-256 of the report equals the anchored reportHash
    # --------------------------------------------------------------------------
    try:
        # Check canonical JSON if JSON file, else raw bytes
        report_raw = report_path.read_bytes()
        try:
            report_json_obj = json.loads(report_raw.decode("utf-8"))
            local_report_hash = hashlib.sha256(canonical_json(report_json_obj)).digest()
        except Exception:
            local_report_hash = hashlib.sha256(report_raw).digest()

        onchain_report_bytes = case_registry.functions.reportHash(case_id_bytes).call()

        if local_report_hash == onchain_report_bytes:
            print("[Step 5] Report SHA-256 equals on-chain reportHash: PASS")
        else:
            print(f"[Step 5] Report SHA-256 equals on-chain reportHash: FAIL (local={local_report_hash.hex()}, onchain={onchain_report_bytes.hex()})")
            all_pass = False
    except Exception as e:
        print(f"[Step 5] Report hash check error: FAIL ({e})")
        all_pass = False

    print("================================================================================")
    if all_pass:
        print("[VERIFICATION RESULT] ALL FIVE STEPS PASSED SUCCESSFULLY.")
    else:
        print("[VERIFICATION RESULT] ONE OR MORE VERIFICATION STEPS FAILED.")
    print("================================================================================\n")

    return all_pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verifier.verify",
        description="SecureMailScope 5-Step Independent Verification CLI",
    )
    parser.add_argument("--case-id", required=True, type=str, help="Case ID hex")
    parser.add_argument("--pcap", required=True, type=str, help="Path to PCAP file")
    parser.add_argument("--findings-dir", required=True, type=str, help="Directory with findings.json, host_scores.json, result.json")
    parser.add_argument("--report", required=True, type=str, help="Path to report file (JSON or raw)")
    parser.add_argument("--rpc-url", type=str, default="http://127.0.0.1:8545", help="EVM RPC endpoint")
    parser.add_argument("--deployment-file", type=str, default=None, help="Path to local.json deployment file")
    return parser


def main(args=None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(args)

    pcap_path = Path(parsed.pcap)
    findings_dir = Path(parsed.findings_dir)
    report_path = Path(parsed.report)
    deployment_file = Path(parsed.deployment_file) if parsed.deployment_file else None

    try:
        passed = verify_case(
            case_id_hex=parsed.case_id,
            pcap_path=pcap_path,
            findings_dir=findings_dir,
            report_path=report_path,
            rpc_url=parsed.rpc_url,
            deployment_file=deployment_file,
        )
        return 0 if passed else 1
    except Exception as e:
        sys.stderr.write(f"Verification error: {e}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
