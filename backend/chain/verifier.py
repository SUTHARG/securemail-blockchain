"""Independent verification helpers for blockchain state, Merkle trees, and PostureLedger hash chains."""
from typing import Any, Dict, List, Optional, Tuple
import eth_abi
from web3 import Web3


def verify_posture_ledger_hash_chain(
    posture_ledger_contract: Any,
    onchain_case_bytes: bytes,
    result_root_bytes: bytes,
    expected_host_scores: List[Dict[str, Any]],
    w3_instance: Optional[Web3] = None,
) -> Tuple[bool, str]:
    """
    Validates PostureLedger records in order for each host:
    - First record prevHash must be bytes32(0).
    - Each record prevHash must match the previous record's recordHash.
    - Each record recordHash must match keccak256(abi.encode(hostId, caseId, score, resultRoot, prevHash, timestamp)).
    - For each expected host, a record matching onchain_case_bytes, host score, and result_root_bytes must be found.
    """
    if not posture_ledger_contract:
        return False, "PostureLedger contract unavailable"
    if not expected_host_scores:
        return False, "No host scores to verify"

    keccak_fn = w3_instance.keccak if w3_instance else Web3.keccak

    for h in expected_host_scores:
        raw_host = str(h.get("hostId", "")).replace("0x", "")
        if not raw_host:
            return False, "Malformed host ID in host scores"
        host_bytes = bytes.fromhex(raw_host)

        try:
            rec_count = posture_ledger_contract.functions.recordCount(host_bytes).call()
        except Exception as exc:
            return False, f"Failed to get record count for host 0x{raw_host}: {exc}"

        if rec_count == 0:
            return False, f"No posture records on-chain for host 0x{raw_host}"

        expected_prev_hash = bytes(32)
        found_target_case_record = False

        for idx in range(rec_count):
            try:
                rec = posture_ledger_contract.functions.recordAt(host_bytes, idx).call()
            except Exception as exc:
                return False, f"Failed to retrieve record {idx} for host 0x{raw_host}: {exc}"

            r_host, r_case, r_score, r_root, r_prev, r_time, r_hash = rec

            if r_host != host_bytes:
                return False, f"Record {idx} hostId mismatch: expected 0x{host_bytes.hex()}, got 0x{r_host.hex()}"

            if r_prev != expected_prev_hash:
                return False, f"Broken prevHash chain at record {idx} for host 0x{raw_host}: expected 0x{expected_prev_hash.hex()}, got 0x{r_prev.hex()}"

            # Exact Solidity abi.encode: (bytes32, bytes32, uint16, bytes32, bytes32, uint256)
            encoded = eth_abi.encode(
                ["bytes32", "bytes32", "uint16", "bytes32", "bytes32", "uint256"],
                [r_host, r_case, int(r_score), r_root, r_prev, int(r_time)],
            )
            recomputed_hash = keccak_fn(encoded)
            if r_hash != recomputed_hash:
                return False, f"Record hash mismatch at record {idx} for host 0x{raw_host}: on-chain 0x{r_hash.hex()} != recomputed 0x{recomputed_hash.hex()}"

            expected_prev_hash = r_hash

            if r_case == onchain_case_bytes:
                expected_score = int(h["score"])
                if int(r_score) != expected_score:
                    return False, f"Score mismatch on-chain for host 0x{raw_host}: expected {expected_score}, got {r_score}"
                if r_root != result_root_bytes:
                    return False, f"Result root mismatch on-chain for host 0x{raw_host}: expected 0x{result_root_bytes.hex()}, got 0x{r_root.hex()}"
                found_target_case_record = True

        if not found_target_case_record:
            return False, f"Host 0x{raw_host} has records on-chain but none for case 0x{onchain_case_bytes.hex()}"

    return True, f"Verified hash chain across {len(expected_host_scores)} hosts on PostureLedger"
