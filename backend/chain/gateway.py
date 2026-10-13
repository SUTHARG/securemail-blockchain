"""Blockchain Gateway for SecureMailScope (Prompt 6.2).

Owns signing keys (ANALYST_KEY and ADMIN_KEY) and nonce sequences (one lock per account).
Manages all on-chain interactions: open_case, submit_claim, advance, finalize,
record_posture, anchor_report, and resolve.
Enforces idempotence, transient RPC retries with backoff, revert detection without retry,
and event listener log polling to keep database in sync with the blockchain source of truth.
"""
import hashlib
import json
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from eth_account import Account
from web3 import Web3

import backend.config as config
from backend.database import (
    add_audit_entry,
    get_case,
    get_case_by_onchain_id,
    get_case_by_pcap_sha,
    get_chain_tx,
    get_chain_txs,
    get_sync_state,
    record_chain_tx,
    set_case_onchain_id,
    set_sync_state,
    update_case_status,
)
from backend.storage import get_case_dir, read_case_json

logger = logging.getLogger("securemailscope.chain.gateway")

STATE_MAP = {
    0: "none",
    1: "opened",
    2: "claimed",
    3: "committing",
    4: "revealing",
    5: "finalized",
    6: "disputed",
    7: "expired",
    8: "rejected",
}

STATE_NAMES_REV = {v: k for k, v in STATE_MAP.items()}


class GatewayError(Exception):
    """Base error for blockchain gateway operations."""
    pass


class TransactionRevertedError(GatewayError):
    """Raised when an on-chain transaction reverts (never retried)."""
    pass


class TransientRPCError(GatewayError):
    """Raised when an RPC transient error persists after max retries."""
    pass


class CaseNotFoundError(GatewayError):
    """Raised when case is not found in database or storage."""
    pass


class InvalidStateError(GatewayError):
    """Raised when case is in an invalid state for requested operation."""
    pass


def to_hex0x(val: Any) -> str:
    """Safely convert bytes/HexBytes to 0x-prefixed hex string without stripping leading zeros."""
    h = val.hex() if hasattr(val, "hex") else str(val)
    if h.startswith("0x"):
        return h
    return "0x" + h


def load_contract_artifact(deployment_file: Path, abi_rel_path: str) -> list:
    """Load contract ABI from build artifacts relative to contracts directory."""
    contracts_dir = deployment_file.parent.parent
    abi_path = contracts_dir / abi_rel_path
    if not abi_path.exists():
        # Fallback to repo root / contracts / abi_rel_path
        repo_root = config.REPO_ROOT
        abi_path = repo_root / "contracts" / abi_rel_path
    if not abi_path.exists():
        raise FileNotFoundError(f"Contract artifact not found at {abi_path}")
    with open(abi_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)
    return artifact["abi"]


class ChainGateway:
    """Gateway orchestrating all on-chain transactions and event synchronization."""

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        deployment_file: Optional[Path] = None,
    ):
        self.rpc_url = rpc_url or config.RPC_URL
        self.deployment_file = deployment_file or config.DEPLOYMENT_FILE

        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))

        # Signing keys and accounts (owned exclusively by gateway)
        self.analyst_account = Account.from_key(config.ANALYST_KEY)
        self.admin_account = Account.from_key(config.ADMIN_KEY)

        # One lock per account for thread-safe sequential nonces
        self._analyst_lock = threading.Lock()
        self._admin_lock = threading.Lock()

        # Load deployed contracts
        self._load_contracts()

    def _load_contracts(self) -> None:
        """Initialize web3 contract instances from deployment file and artifacts."""
        if not self.deployment_file.exists():
            raise FileNotFoundError(
                f"Deployment file not found at {self.deployment_file}. Ensure contracts are deployed."
            )

        with open(self.deployment_file, "r", encoding="utf-8") as f:
            deployment = json.load(f)

        c_info = deployment["contracts"]

        # CaseRegistry
        reg_abi = load_contract_artifact(self.deployment_file, c_info["CaseRegistry"]["abiPath"])
        self.case_registry = self.w3.eth.contract(
            address=c_info["CaseRegistry"]["address"],
            abi=reg_abi,
        )

        # ValidationQuorum
        quorum_abi = load_contract_artifact(self.deployment_file, c_info["ValidationQuorum"]["abiPath"])
        self.quorum = self.w3.eth.contract(
            address=c_info["ValidationQuorum"]["address"],
            abi=quorum_abi,
        )

        # PostureLedger
        ledger_abi = load_contract_artifact(self.deployment_file, c_info["PostureLedger"]["abiPath"])
        self.posture_ledger = self.w3.eth.contract(
            address=c_info["PostureLedger"]["address"],
            abi=ledger_abi,
        )

        # Roles
        roles_abi = load_contract_artifact(self.deployment_file, c_info["Roles"]["abiPath"])
        self.roles = self.w3.eth.contract(
            address=c_info["Roles"]["address"],
            abi=roles_abi,
        )

    def _extract_revert_reason(self, exc: Exception) -> str:
        """Extract custom Solidity error or revert reason string from exception."""
        msg = str(exc)
        known_errors = [
            "NotCaseAnalyst",
            "CaseNotFound",
            "CaseNotFinalized",
            "ReportAlreadyAnchored",
            "InvalidPcapHash",
            "InvalidReportHash",
            "InvalidEngineHash",
            "InvalidCaseState",
            "InsufficientValidators",
            "EngineMismatch",
            "RulesetMismatch",
            "EngineNotConfigured",
            "InvalidResultRoot",
            "InvalidCommitment",
            "NotSnapshotValidator",
            "CommitDeadlinePassed",
            "CommitWindowActive",
            "AlreadyCommitted",
            "RevealDeadlinePassed",
            "NoPriorCommitment",
            "AlreadyRevealed",
            "CommitmentMismatch",
            "OutcomeNotReady",
            "QuorumNotReached",
            "AttestMajorityNotAllowedForExpired",
            "InvalidHostId",
            "InvalidScore",
            "InvalidInclusionProof",
            "PostureAlreadyRecorded",
            "AccessControlUnauthorizedAccount",
        ]
        for err in known_errors:
            if err in msg:
                return err
        return msg[:200]

    def _send_tx(
        self,
        contract_fn: Any,
        account: Any,
        lock: threading.Lock,
        case_id: str,
        step: str,
        max_retries: int = 3,
    ) -> Any:
        """
        Send an on-chain transaction with:
        1. Pre-send check: if step was already confirmed, return existing receipt.
        2. Crash check: if step was previously sent but receipt not stored, resolve receipt first.
        3. Gas estimation & revert detection: never retry a reverted transaction.
        4. Storing in chain_txs BEFORE waiting for receipt.
        5. Updating chain_txs status after receipt confirmation.
        """
        # Step 1: Idempotency check in database
        existing = get_chain_tx(case_id, step)
        if existing:
            if existing["status"] == "confirmed" and existing["tx_hash"]:
                try:
                    receipt = self.w3.eth.get_transaction_receipt(existing["tx_hash"])
                    if receipt and receipt.status == 1:
                        target_to = getattr(contract_fn, "address", None)
                        if not target_to or (receipt.get("to") and receipt.get("to").lower() == target_to.lower()):
                            return receipt
                except Exception:
                    pass

            if existing["status"] == "sent" and existing["tx_hash"]:
                # Crash recovery: transaction was already sent; check if mined
                try:
                    receipt = self.w3.eth.get_transaction_receipt(existing["tx_hash"])
                    if receipt:
                        if receipt.status == 1:
                            record_chain_tx(
                                case_id, step, existing["nonce"], existing["tx_hash"], "confirmed", existing["retries"]
                            )
                            return receipt
                        else:
                            record_chain_tx(
                                case_id, step, existing["nonce"], existing["tx_hash"], "reverted", existing["retries"]
                            )
                            raise TransactionRevertedError(f"Transaction {existing['tx_hash']} reverted on-chain")
                except TransactionRevertedError:
                    raise
                except Exception:
                    # Not mined yet, wait for receipt below
                    try:
                        receipt = self.w3.eth.wait_for_transaction_receipt(existing["tx_hash"], timeout=15)
                        if receipt.status == 1:
                            record_chain_tx(
                                case_id, step, existing["nonce"], existing["tx_hash"], "confirmed", existing["retries"]
                            )
                            return receipt
                        else:
                            record_chain_tx(
                                case_id, step, existing["nonce"], existing["tx_hash"], "reverted", existing["retries"]
                            )
                            raise TransactionRevertedError(f"Transaction {existing['tx_hash']} reverted on-chain")
                    except TransactionRevertedError:
                        raise
                    except Exception:
                        pass

        # Step 2: Acquire lock and execute with transient retries
        with lock:
            # First estimate gas / simulate transaction
            try:
                gas_est = contract_fn.estimate_gas({"from": account.address})
                gas = int(gas_est * 1.3)
            except Exception as exc:
                revert_reason = self._extract_revert_reason(exc)
                record_chain_tx(case_id, step, None, None, "reverted", 0)
                update_case_status(case_id, f"reverted: {revert_reason}")
                raise TransactionRevertedError(revert_reason)

            retries = 0
            while retries <= max_retries:
                try:
                    nonce = self.w3.eth.get_transaction_count(account.address, "pending")
                    tx_params = {
                        "from": account.address,
                        "nonce": nonce,
                        "gas": gas,
                        "gasPrice": self.w3.eth.gas_price,
                        "chainId": self.w3.eth.chain_id,
                    }
                    tx = contract_fn.build_transaction(tx_params)
                    signed = account.sign_transaction(tx)
                    raw_tx = getattr(signed, "raw_transaction", getattr(signed, "rawTransaction", None))
                    tx_hash_bytes = self.w3.eth.send_raw_transaction(raw_tx)
                    tx_hash = to_hex0x(tx_hash_bytes)

                    # PROMPT 6.2 MANDATE: Store in chain_txs BEFORE waiting for receipt!
                    record_chain_tx(case_id, step, nonce, tx_hash, "sent", retries)

                    # Now wait for receipt
                    receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
                    if receipt.status == 1:
                        record_chain_tx(case_id, step, nonce, tx_hash, "confirmed", retries)
                        return receipt
                    else:
                        record_chain_tx(case_id, step, nonce, tx_hash, "reverted", retries)
                        update_case_status(case_id, "reverted")
                        raise TransactionRevertedError(f"Transaction {tx_hash} reverted on-chain")

                except TransactionRevertedError:
                    raise
                except Exception as exc:
                    err_msg = str(exc).lower()
                    if "revert" in err_msg or "unauthorized" in err_msg or "invalid" in err_msg:
                        record_chain_tx(
                            case_id, step, nonce if 'nonce' in locals() else None, None, "reverted", retries
                        )
                        update_case_status(case_id, f"reverted: {self._extract_revert_reason(exc)}")
                        raise TransactionRevertedError(self._extract_revert_reason(exc))

                    retries += 1
                    if retries > max_retries:
                        record_chain_tx(
                            case_id, step, nonce if 'nonce' in locals() else None, None, "failed", retries
                        )
                        raise TransientRPCError(f"RPC failure after {max_retries} retries: {exc}")
                    time.sleep(0.2 * (2 ** retries))

    def _resolve_onchain_id(self, case_id: str) -> Tuple[Dict[str, Any], bytes]:
        """Fetch case from database and return onchain_case_id as bytes32."""
        case = get_case(case_id)
        if not case:
            # Check if case_id was passed directly as onchain_case_id
            case = get_case_by_onchain_id(case_id)
        if not case:
            raise CaseNotFoundError(f"Case {case_id} not found")

        onchain_id = case.get("onchain_case_id")
        if not onchain_id:
            raise InvalidStateError(f"Case {case_id} has not been opened on-chain yet")

        clean_hex = onchain_id.replace("0x", "")
        return case, bytes.fromhex(clean_hex)

    # -----------------------------------------------------------------------
    # Core Operations (Prompt 6.2)
    # -----------------------------------------------------------------------

    def open_case(self, case_id: str) -> Dict[str, Any]:
        """
        Open a forensic case in CaseRegistry.
        Idempotent: skips if case is already opened for this PCAP hash and recorded in chain_txs.
        """
        case = get_case(case_id)
        if not case:
            raise CaseNotFoundError(f"Case {case_id} not found")

        # Check existing confirmed open transaction
        existing_tx = get_chain_tx(case_id, "open")
        if existing_tx and existing_tx["status"] == "confirmed" and case.get("onchain_case_id"):
            return {
                "caseId": case_id,
                "onchainCaseId": case["onchain_case_id"],
                "status": "opened",
                "txHash": existing_tx["tx_hash"],
                "idempotent": True,
            }

        pcap_sha = bytes.fromhex(case["pcap_sha256"])
        contract_fn = self.case_registry.functions.openCase(pcap_sha)

        receipt = self._send_tx(
            contract_fn=contract_fn,
            account=self.analyst_account,
            lock=self._analyst_lock,
            case_id=case_id,
            step="open",
        )

        # Extract on-chain caseId from CaseOpened event
        event = self.case_registry.events.CaseOpened().process_receipt(receipt)[0]
        onchain_id = to_hex0x(event.args.caseId)

        set_case_onchain_id(case_id, onchain_id)
        update_case_status(case_id, "opened_on_chain")
        add_audit_entry(
            actor="analyst",
            action="case_opened_on_chain",
            case_id=case_id,
            detail=f"onchainCaseId={onchain_id}",
        )

        return {
            "caseId": case_id,
            "onchainCaseId": onchain_id,
            "status": "opened",
            "txHash": "0x" + receipt.transactionHash.hex(),
            "idempotent": False,
        }

    def submit_claim(self, case_id: str) -> Dict[str, Any]:
        """
        Submit analyst's claimed result root to ValidationQuorum.
        Idempotent: skips if claim was already submitted.
        """
        case, onchain_bytes = self._resolve_onchain_id(case_id)
        onchain_hex = case["onchain_case_id"]

        # Check on-chain state: if state is already >= Claimed (2), skip
        cur_state_int = self.case_registry.functions.caseState(onchain_bytes).call()
        if cur_state_int >= 2:
            existing_tx = get_chain_tx(case_id, "claim")
            return {
                "caseId": case_id,
                "onchainCaseId": onchain_hex,
                "status": STATE_MAP.get(cur_state_int, "claimed"),
                "txHash": existing_tx["tx_hash"] if existing_tx else None,
                "idempotent": True,
            }

        # Read resultRoot from canonical result.json
        result_data = read_case_json(case_id, "result.json")
        if not result_data or "resultRoot" not in result_data:
            raise GatewayError(f"Case {case_id} must be analyzed before submitting claim")

        root_hex = result_data["resultRoot"].replace("0x", "")
        root_bytes = bytes.fromhex(root_hex)

        # Read pinned active engine release and ruleset hash
        image_digest, ruleset_hash = self.case_registry.functions.activeEngine().call()
        if image_digest == bytes(32) or ruleset_hash == bytes(32):
            raise GatewayError("Engine not configured on-chain. Admin must register engine first.")

        contract_fn = self.quorum.functions.submitClaim(
            onchain_bytes,
            root_bytes,
            image_digest,
            ruleset_hash,
        )

        receipt = self._send_tx(
            contract_fn=contract_fn,
            account=self.analyst_account,
            lock=self._analyst_lock,
            case_id=case_id,
            step="claim",
        )

        update_case_status(case_id, "claimed")
        add_audit_entry(
            actor="analyst",
            action="claim_submitted",
            case_id=case_id,
            detail=f"resultRoot=0x{root_hex}",
        )

        return {
            "caseId": case_id,
            "onchainCaseId": onchain_hex,
            "status": "claimed",
            "txHash": "0x" + receipt.transactionHash.hex(),
            "idempotent": False,
        }

    def advance(self, case_id: str) -> Dict[str, Any]:
        """
        Advance case from Committing to Revealing after commit deadline.
        Idempotent: skips if case is already in Revealing or beyond.
        """
        case, onchain_bytes = self._resolve_onchain_id(case_id)
        cur_state_int = self.case_registry.functions.caseState(onchain_bytes).call()
        if cur_state_int >= 4:  # Revealing or beyond
            return {
                "caseId": case_id,
                "status": STATE_MAP.get(cur_state_int, "revealing"),
                "idempotent": True,
            }

        contract_fn = self.quorum.functions.advance(onchain_bytes)
        receipt = self._send_tx(
            contract_fn=contract_fn,
            account=self.analyst_account,
            lock=self._analyst_lock,
            case_id=case_id,
            step="advance",
        )

        add_audit_entry(actor="analyst", action="case_advanced", case_id=case_id)
        return {
            "caseId": case_id,
            "status": "revealing",
            "txHash": "0x" + receipt.transactionHash.hex(),
            "idempotent": False,
        }

    def finalize(self, case_id: str) -> Dict[str, Any]:
        """
        Finalize case verification quorum.
        Idempotent: skips if case is already Finalized, Disputed, or Expired.
        """
        case, onchain_bytes = self._resolve_onchain_id(case_id)
        cur_state_int = self.case_registry.functions.caseState(onchain_bytes).call()
        if cur_state_int >= 5:  # Finalized, Disputed, Expired, Rejected
            existing_tx = get_chain_tx(case_id, "finalize")
            return {
                "caseId": case_id,
                "status": STATE_MAP.get(cur_state_int, "finalized"),
                "txHash": existing_tx["tx_hash"] if existing_tx else None,
                "idempotent": True,
            }

        contract_fn = self.quorum.functions.finalize(onchain_bytes)
        receipt = self._send_tx(
            contract_fn=contract_fn,
            account=self.analyst_account,
            lock=self._analyst_lock,
            case_id=case_id,
            step="finalize",
        )

        new_state_int = self.case_registry.functions.caseState(onchain_bytes).call()
        status_name = STATE_MAP.get(new_state_int, "finalized")
        update_case_status(case_id, status_name)
        add_audit_entry(actor="analyst", action=f"case_{status_name}", case_id=case_id)

        return {
            "caseId": case_id,
            "status": status_name,
            "txHash": "0x" + receipt.transactionHash.hex(),
            "idempotent": False,
        }

    def record_posture(self, case_id: str) -> Dict[str, Any]:
        """
        Record host posture scores on PostureLedger for each host in host_scores.json.
        Idempotent: skips any host already recorded on-chain.
        """
        case, onchain_bytes = self._resolve_onchain_id(case_id)

        # Must be finalized
        cur_state_int = self.case_registry.functions.caseState(onchain_bytes).call()
        if cur_state_int != 5:
            raise InvalidStateError(f"Case {case_id} is in state {STATE_MAP.get(cur_state_int)}, must be Finalized")

        host_scores = read_case_json(case_id, "host_scores.json") or []
        host_proofs = read_case_json(case_id, "host_proofs.json") or {}

        recorded_hosts = []
        for host_entry in host_scores:
            host_id_raw = host_entry["hostId"]
            clean_host_hex = host_id_raw.replace("0x", "")
            host_id_bytes = bytes.fromhex(clean_host_hex)

            # Idempotency: check if host already recorded on-chain
            # PostureLedger exposes hasRecorded(caseId, hostId)
            is_recorded = self.posture_ledger.functions.hasRecorded(
                onchain_bytes, host_id_bytes
            ).call()
            step_name = f"record_{clean_host_hex}"

            if is_recorded:
                recorded_hosts.append({"hostId": f"0x{clean_host_hex}", "status": "already_recorded"})
                continue

            findings_digest = bytes.fromhex(host_entry["findingsDigest"].replace("0x", ""))
            # score must be uint16 (0-100); cast explicitly to plain int for web3 encoding
            score = int(host_entry["score"])

            proof_raw = host_proofs.get(host_id_raw, host_proofs.get(f"0x{clean_host_hex}", []))
            proof_bytes = [bytes.fromhex(p.replace("0x", "")) for p in proof_raw]

            contract_fn = self.posture_ledger.functions.recordPosture(
                onchain_bytes,
                host_id_bytes,
                findings_digest,
                score,
                proof_bytes,
            )

            receipt = self._send_tx(
                contract_fn=contract_fn,
                account=self.analyst_account,
                lock=self._analyst_lock,
                case_id=case_id,
                step=step_name,
            )

            recorded_hosts.append({
                "hostId": f"0x{clean_host_hex}",
                "status": "recorded",
                "txHash": receipt.transactionHash.hex(),
            })

        update_case_status(case_id, "recorded")
        add_audit_entry(
            actor="analyst",
            action="posture_recorded",
            case_id=case_id,
            detail=f"hosts={len(host_scores)}",
        )

        return {
            "caseId": case_id,
            "status": "recorded",
            "hosts": recorded_hosts,
        }

    def anchor_report(self, case_id: str, report_hash_hex: Optional[str] = None) -> Dict[str, Any]:
        """
        Anchor custody report hash in CaseRegistry.
        Idempotent: skips if report is already anchored.
        """
        case, onchain_bytes = self._resolve_onchain_id(case_id)

        cur_state_int = self.case_registry.functions.caseState(onchain_bytes).call()
        if cur_state_int != 5:
            raise InvalidStateError(f"Case {case_id} must be Finalized before report anchoring")

        # Determine report hash
        if not report_hash_hex:
            # Check manifest or report.json
            manifest = read_case_json(case_id, "manifest.json")
            if manifest and manifest.get("reportHash"):
                report_hash_hex = manifest["reportHash"]
            else:
                report_file = get_case_dir(case_id) / "report.json"
                if report_file.exists():
                    with open(report_file, "rb") as rf:
                        report_hash_hex = hashlib.sha256(rf.read()).hexdigest()
                else:
                    try:
                        from backend.reports.builder import build_case_report
                        _, _, report_hash_hex, _ = build_case_report(case_id, save=True, gateway_override=self)
                    except Exception:
                        res_data = read_case_json(case_id, "result.json") or {}
                        report_hash_hex = hashlib.sha256(json.dumps(res_data, sort_keys=True).encode()).hexdigest()


        clean_report_hex = report_hash_hex.replace("0x", "")
        report_bytes = bytes.fromhex(clean_report_hex)

        # Idempotence check on-chain
        existing_report = self.case_registry.functions.reportHash(onchain_bytes).call()
        if existing_report != bytes(32):
            return {
                "caseId": case_id,
                "status": "report_anchored",
                "reportHash": "0x" + existing_report.hex(),
                "idempotent": True,
            }

        contract_fn = self.case_registry.functions.anchorReport(onchain_bytes, report_bytes)
        receipt = self._send_tx(
            contract_fn=contract_fn,
            account=self.analyst_account,
            lock=self._analyst_lock,
            case_id=case_id,
            step="anchor",
        )

        update_case_status(case_id, "report_anchored")
        add_audit_entry(
            actor="analyst",
            action="report_anchored",
            case_id=case_id,
            detail=f"reportHash=0x{clean_report_hex}",
        )

        return {
            "caseId": case_id,
            "status": "report_anchored",
            "reportHash": f"0x{clean_report_hex}",
            "txHash": "0x" + receipt.transactionHash.hex(),
            "idempotent": False,
        }

    def resolve(
        self,
        case_id: str,
        action: str,
        root_hex: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Administrator resolution of a Disputed or Expired case.
        Actions: 'AttestMajority', 'NewRound', 'Reject'.
        """
        case, onchain_bytes = self._resolve_onchain_id(case_id)

        action_map = {"AttestMajority": 0, "NewRound": 1, "Reject": 2}
        if action not in action_map:
            raise GatewayError(f"Invalid resolution action: {action}")

        action_enum = action_map[action]
        root_bytes = bytes.fromhex(root_hex.replace("0x", "")) if root_hex else bytes(32)

        contract_fn = self.quorum.functions.resolve(onchain_bytes, action_enum, root_bytes)
        receipt = self._send_tx(
            contract_fn=contract_fn,
            account=self.admin_account,
            lock=self._admin_lock,
            case_id=case_id,
            step="resolve",
        )

        new_state_int = self.case_registry.functions.caseState(onchain_bytes).call()
        status_name = STATE_MAP.get(new_state_int, "resolved")
        update_case_status(case_id, status_name)
        add_audit_entry(
            actor="admin",
            action=f"case_resolved_{action.lower()}",
            case_id=case_id,
            detail=f"state={status_name}",
        )

        return {
            "caseId": case_id,
            "status": status_name,
            "action": action,
            "txHash": "0x" + receipt.transactionHash.hex(),
        }

    # -----------------------------------------------------------------------
    # Status and Event Synchronization (Prompt 6.2)
    # -----------------------------------------------------------------------

    def get_chain_status(self, case_id: str) -> Dict[str, Any]:
        """
        Return comprehensive on-chain case state, commits and reveals per validator,
        and transaction records from chain_txs.
        """
        case = get_case(case_id)
        if not case:
            case = get_case_by_onchain_id(case_id)
        if not case:
            raise CaseNotFoundError(f"Case {case_id} not found")

        txs = get_chain_txs(case["id"])

        onchain_hex = case.get("onchain_case_id")
        if not onchain_hex:
            result_json = read_case_json(case["id"], "result.json")
            result_root = result_json.get("resultRoot") if result_json else None
            return {
                "caseId": case["id"],
                "status": case["status"],
                "onchainCaseId": None,
                "state": "None",
                "resultRoot": result_root,
                "claimedRoot": None,
                "finalRoot": None,
                "reportHash": None,
                "round": 0,
                "validators": [],
                "transactions": txs,
            }

        onchain_bytes = bytes.fromhex(onchain_hex.replace("0x", ""))

        state_int = self.case_registry.functions.caseState(onchain_bytes).call()
        state_str = STATE_MAP.get(state_int, "unknown").capitalize()

        c_root = self.case_registry.functions.claimedRoot(onchain_bytes).call()
        f_root = self.case_registry.functions.finalRoot(onchain_bytes).call()
        r_hash = self.case_registry.functions.reportHash(onchain_bytes).call()
        contradicted = self.case_registry.functions.isContradicted(onchain_bytes).call()
        round_num = self.case_registry.functions.caseRound(onchain_bytes).call()
        analyst_addr = self.case_registry.functions.analyst(onchain_bytes).call()

        # Retrieve validator commits and reveals if in an active round
        validators_info = []
        if round_num > 0 and state_int >= 2:
            try:
                # ValidationQuorum exposes getValidatorSnapshot(caseId, round)
                snap_addrs = self.quorum.functions.getValidatorSnapshot(onchain_bytes, round_num).call()
                for addr in snap_addrs:
                    committed = self.quorum.functions.hasCommitted(onchain_bytes, round_num, addr).call()
                    revealed = self.quorum.functions.hasRevealed(onchain_bytes, round_num, addr).call()
                    commit_val = self.quorum.functions.getCommitment(onchain_bytes, round_num, addr).call()
                    # getValidatorRoot(caseId, round, validator) — only populated after reveal
                    rev_root = self.quorum.functions.getValidatorRoot(onchain_bytes, round_num, addr).call()

                    validators_info.append({
                        "address": addr,
                        "committed": committed,
                        "commitment": "0x" + commit_val.hex() if committed else None,
                        "revealed": revealed,
                        "resultRoot": "0x" + rev_root.hex() if revealed else None,
                    })
            except Exception:
                pass

        result_root_hex = "0x" + c_root.hex() if c_root != bytes(32) else None
        if not result_root_hex:
            result_json = read_case_json(case["id"], "result.json")
            result_root_hex = result_json.get("resultRoot") if result_json else None

        return {
            "caseId": case["id"],
            "status": case["status"],
            "onchainCaseId": onchain_hex,
            "state": state_str,
            "resultRoot": result_root_hex,
            "analyst": analyst_addr,
            "claimedRoot": "0x" + c_root.hex() if c_root != bytes(32) else None,
            "finalRoot": "0x" + f_root.hex() if f_root != bytes(32) else None,
            "contradicted": contradicted,
            "reportHash": "0x" + r_hash.hex() if r_hash != bytes(32) else None,
            "round": round_num,
            "validators": validators_info,
            "transactions": txs,
        }

    def poll_events(self) -> int:
        """
        Poll contract logs from last processed block to current block.
        The chain is the source of truth; on any disagreement the database is corrected from the chain.
        """
        last_block_str = get_sync_state("last_processed_block", "0")
        from_block = int(last_block_str) + 1
        current_block = self.w3.eth.block_number

        if from_block > current_block:
            return 0

        event_count = 0

        # Poll CaseRegistry events
        try:
            opened_logs = self.case_registry.events.CaseOpened().get_logs(
                from_block=from_block, to_block=current_block
            )
            for log in opened_logs:
                event_count += 1
                case_id_bytes = log.args.caseId
                onchain_id_hex = to_hex0x(case_id_bytes)
                pcap_hash_hex = log.args.pcapHash.hex()

                case = get_case_by_onchain_id(onchain_id_hex)
                if not case:
                    cand = get_case_by_pcap_sha(pcap_hash_hex)
                    if cand and not cand.get("onchain_case_id") and get_chain_tx(cand["id"], "open"):
                        set_case_onchain_id(cand["id"], onchain_id_hex)
                        update_case_status(cand["id"], "opened_on_chain")
        except Exception as exc:
            logger.warning("Error polling CaseOpened logs: %s", exc)

        try:
            state_logs = self.case_registry.events.StateChanged().get_logs(
                from_block=from_block, to_block=current_block
            )
            for log in state_logs:
                event_count += 1
                onchain_id_hex = to_hex0x(log.args.caseId)
                new_state = log.args.newState
                state_name = STATE_MAP.get(new_state, "unknown")

                case = get_case_by_onchain_id(onchain_id_hex)
                if case and case["status"] != state_name:
                    update_case_status(case["id"], state_name)
                    add_audit_entry(
                        actor="system",
                        action="chain_sync_state_corrected",
                        case_id=case["id"],
                        detail=f"from={case['status']},to={state_name}",
                    )
        except Exception as exc:
            logger.warning("Error polling StateChanged logs: %s", exc)

        set_sync_state("last_processed_block", str(current_block))
        return event_count

    # -----------------------------------------------------------------------
    # Admin Utilities
    # -----------------------------------------------------------------------

    def register_engine(self, image_digest: bytes, ruleset_hash: bytes) -> Dict[str, Any]:
        """Register approved engine release and ruleset hash (Admin only)."""
        cur_img, cur_ruleset = self.case_registry.functions.activeEngine().call()
        if cur_img == image_digest and cur_ruleset == ruleset_hash:
            return {"status": "registered"}

        contract_fn = self.case_registry.functions.registerEngine(image_digest, ruleset_hash)
        receipt = self._send_tx(
            contract_fn=contract_fn,
            account=self.admin_account,
            lock=self._admin_lock,
            case_id="admin",
            step=f"register_engine_{image_digest.hex()[:8]}",
        )
        return {"status": "registered", "txHash": "0x" + receipt.transactionHash.hex()}

    def add_validator(self, validator_address: str) -> Dict[str, Any]:
        """Register validator address and grant VALIDATOR_ROLE (Admin only)."""
        checksum_addr = Web3.to_checksum_address(validator_address)
        if self.case_registry.functions.isValidator(checksum_addr).call():
            return {"status": "validator_added"}

        contract_fn = self.case_registry.functions.addValidator(checksum_addr)
        receipt = self._send_tx(
            contract_fn=contract_fn,
            account=self.admin_account,
            lock=self._admin_lock,
            case_id="admin",
            step=f"add_validator_{checksum_addr[:8]}",
        )
        return {"status": "validator_added", "txHash": "0x" + receipt.transactionHash.hex()}
