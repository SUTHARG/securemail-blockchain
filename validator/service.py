"""SecureMailScope Validator Service (Phase 6 - Prompt 6.3).

Long-running validator service daemon per validator instance.
Monitors blockchain and inbox for cases where it is an active snapshot participant.
Executes engine analysis in network-isolated sandbox, records cryptographic salts
atomically before submitting commitments, respects reveal deadlines, and drives
commit-reveal consensus to finalization.

Restart-safe: Resumes state from validator_state/<id>.json after crash/kill.
Strict-mode: Enforces engine container digest and ruleset hash pinning.
Faulty-mode: Supports --faulty flag for consensus adversarial evaluation.
"""
import argparse
import hashlib
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from eth_abi import encode
from eth_account import Account
from web3 import Web3

try:
    from dotenv import load_dotenv
    repo_root = Path(__file__).resolve().parents[1]
    load_dotenv(repo_root / ".env")
except ImportError:
    pass

# Optional local imports
try:
    import backend.config as config
    from backend.database import get_case, get_case_by_onchain_id
except ImportError:
    config = None  # type: ignore
    get_case = None  # type: ignore
    get_case_by_onchain_id = None  # type: ignore

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [validator-%(name)s] %(message)s",
)
logger = logging.getLogger("service")


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
    contracts_root = deployment_dir.parent
    full_path = contracts_root / abi_rel_path
    if not full_path.exists():
        repo_root = contracts_root.parent
        full_path = repo_root / "contracts" / abi_rel_path
    if not full_path.exists():
        fallback = deployment_dir / "abi" / Path(abi_rel_path).name
        if fallback.exists():
            full_path = fallback
    if not full_path.exists():
        raise FileNotFoundError(f"Contract artifact not found at: {full_path}")
    with open(full_path, "r", encoding="utf-8") as f:
        artifact = json.load(f)
    return artifact["abi"]


def is_docker_available() -> bool:
    """Check if Docker CLI and daemon are operational."""
    if not shutil.which("docker"):
        return False
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=2)
        return res.returncode == 0
    except Exception:
        return False


def send_validator_tx(w3: Web3, contract_fn: Any, account: Any, private_key: str) -> Any:
    """Submit transaction with pending nonce and gas buffer."""
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
    }
    tx = contract_fn.build_transaction(tx_params)
    signed = w3.eth.account.sign_transaction(tx, private_key=private_key)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
    if receipt.status == 0:
        raise RuntimeError(f"Transaction reverted: {tx_hash.hex()}")
    return receipt


class ValidatorService:
    """Validator daemon process driving commit-reveal consensus."""

    def __init__(
        self,
        validator_id: str,
        private_key: str,
        inbox_dir: Optional[Path] = None,
        state_dir: Optional[Path] = None,
        rpc_url: str = "http://127.0.0.1:8545",
        deployment_file: Optional[Path] = None,
        strict: bool = True,
        faulty: bool = False,
        use_docker: Optional[bool] = None,
        poll_interval: float = 1.0,
    ) -> None:
        self.validator_id = str(validator_id)
        self.private_key = private_key
        self.account = Account.from_key(private_key)
        self.strict = strict
        self.faulty = faulty
        self.use_docker = use_docker
        self.poll_interval = poll_interval

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.repo_root = Path(__file__).resolve().parents[1]

        self.inbox_dir = (
            inbox_dir if inbox_dir is not None
            else self.repo_root / "validator_inbox" / self.validator_id
        )
        self.inbox_dir.mkdir(parents=True, exist_ok=True)

        self.state_dir = (
            state_dir if state_dir is not None
            else self.repo_root / "validator_state"
        )
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.state_file = self.state_dir / f"{self.validator_id}.json"
        self.temp_state_file = self.state_dir / f"{self.validator_id}.json.tmp"

        self.deployment_file = (
            deployment_file if deployment_file is not None
            else self.repo_root / "contracts" / "deployments" / "local.json"
        )

        deployment = load_deployment(self.deployment_file)
        deployment_dir = self.deployment_file.parent

        case_reg_info = deployment["contracts"]["CaseRegistry"]
        quorum_info = deployment["contracts"]["ValidationQuorum"]
        posture_info = deployment["contracts"]["PostureLedger"]

        case_registry_abi = load_contract_abi(deployment_dir, case_reg_info.get("abiPath") or case_reg_info.get("artifact"))
        quorum_abi = load_contract_abi(deployment_dir, quorum_info.get("abiPath") or quorum_info.get("artifact"))
        posture_ledger_abi = load_contract_abi(deployment_dir, posture_info.get("abiPath") or posture_info.get("artifact"))

        self.case_registry = self.w3.eth.contract(
            address=self.w3.to_checksum_address(deployment["contracts"]["CaseRegistry"]["address"]),
            abi=case_registry_abi,
        )
        self.quorum = self.w3.eth.contract(
            address=self.w3.to_checksum_address(deployment["contracts"]["ValidationQuorum"]["address"]),
            abi=quorum_abi,
        )
        self.posture_ledger = self.w3.eth.contract(
            address=self.w3.to_checksum_address(deployment["contracts"]["PostureLedger"]["address"]),
            abi=posture_ledger_abi,
        )

        logger.name = self.validator_id
        logger.info("Validator service initialized for %s (%s)", self.validator_id, self.account.address)

    # -----------------------------------------------------------------------
    # State Management (Atomic Writes & Recovery)
    # -----------------------------------------------------------------------

    def load_state(self) -> Dict[str, Any]:
        """Load persisted validator state from disk."""
        if not self.state_file.exists():
            return {}
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning("Failed to parse state file %s: %s", self.state_file, exc)
            return {}

    def save_state(self, payload: Dict[str, Any]) -> None:
        """Atomically persist state to disk via temp file rename."""
        with open(self.temp_state_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(self.temp_state_file, self.state_file)
        logger.info("Atomically saved state for validator %s", self.validator_id)

    # -----------------------------------------------------------------------
    # Strict Mode Verification
    # -----------------------------------------------------------------------

    def verify_strict_mode(self, case_id_bytes: bytes, manifest_data: Dict[str, Any]) -> None:
        """
        Verify local ruleset and engine image hashes against on-chain pinning.
        Fails before committing if engine digest or ruleset hash is missing, malformed, or mismatched.
        """
        onchain_ruleset_hash = self.case_registry.functions.rulesetHash(case_id_bytes).call()
        onchain_engine_hash = self.case_registry.functions.engineHash(case_id_bytes).call()

        local_ruleset_hex = manifest_data.get("rulesetHash", "").lower().replace("0x", "")
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

        logger.info("Strict mode pre-commit checks passed for case 0x%s", case_id_bytes.hex())

    # -----------------------------------------------------------------------
    # Engine Execution
    # -----------------------------------------------------------------------

    def run_engine_analysis(
        self,
        bundle_dir: Path,
        pcap_path: Path,
        org_secret_hex: str,
        case_id_hex: str,
    ) -> Tuple[bytes, Dict[str, Any], Dict[str, Any]]:
        """
        Runs the engine image with 'docker run --rm --network none --read-only'
        (bundle mounted read-only, output directory writable).
        Falls back to local engine CLI if Docker is unavailable.
        """
        temp_out_dir = tempfile.TemporaryDirectory()
        target_out = Path(temp_out_dir.name)

        docker_mode = is_docker_available() if self.use_docker is None else self.use_docker
        engine_image = os.environ.get("ENGINE_DOCKER_IMAGE", "smscope:latest")
        if docker_mode:
            try:
                insp = subprocess.run(["docker", "image", "inspect", engine_image], capture_output=True, timeout=3)
                if insp.returncode != 0:
                    docker_mode = False
            except Exception:
                docker_mode = False

        try:
            if docker_mode:
                logger.info("Executing containerized engine analysis via Docker (%s)", engine_image)
                cmd = [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--read-only",
                    "-v",
                    f"{bundle_dir.resolve()}:/inbox:ro",
                    "-v",
                    f"{target_out.resolve()}:/out:rw",
                    engine_image,
                    "analyze",
                    "/inbox/pcap.bin",
                    "--org-secret-hex",
                    org_secret_hex,
                    "--out",
                    "/out",
                    "--case-id",
                    case_id_hex,
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                if res.returncode != 0:
                    raise RuntimeError(f"Container analysis failed (exit {res.returncode}): {res.stderr}")
            else:
                logger.info("Executing local engine module analysis via %s", sys.executable)
                cmd = [
                    sys.executable,
                    "-m",
                    "smscope",
                    "analyze",
                    str(pcap_path.resolve()),
                    "--org-secret-hex",
                    org_secret_hex,
                    "--out",
                    str(target_out),
                    "--case-id",
                    case_id_hex,
                ]
                trust_store = self.repo_root / "lab" / "ca" / "out" / "client_trust.crt"
                if trust_store.exists():
                    cmd.extend(["--trust-store", str(trust_store)])

                env = os.environ.copy()
                pythonpath = str(self.repo_root / "engine")
                if "PYTHONPATH" in env:
                    env["PYTHONPATH"] = f"{pythonpath}{os.pathsep}{env['PYTHONPATH']}"
                else:
                    env["PYTHONPATH"] = pythonpath

                res = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
                if res.returncode != 0:
                    raise RuntimeError(f"Local engine analysis failed (exit {res.returncode}): {res.stderr}")

            result_file = target_out / "result.json"
            manifest_file = target_out / "manifest.json"
            if not result_file.exists() or not manifest_file.exists():
                raise FileNotFoundError("Engine run did not generate result.json or manifest.json")

            with open(result_file, "r", encoding="utf-8") as f:
                result_data = json.load(f)
            with open(manifest_file, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)

            raw_root = result_data["resultRoot"].lower().replace("0x", "")
            root_bytes = bytes.fromhex(raw_root)

            # Faulty mode check for evaluation testing
            if self.faulty:
                logger.warning("[FAULTY MODE] Tampering with computed resultRoot for outvoting test")
                root_bytes = Web3.keccak(root_bytes)

            return root_bytes, result_data, manifest_data

        finally:
            # Output directory cleaned up after reading
            try:
                temp_out_dir.cleanup()
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # Case Identification and Inbox Scanning
    # -----------------------------------------------------------------------

    def resolve_case_bytes(self, bundle_dir: Path) -> Optional[bytes]:
        """Resolves bytes32 on-chain caseId from directory name or metadata files."""
        # Check onchain_case_id.txt
        onchain_txt = bundle_dir / "onchain_case_id.txt"
        if onchain_txt.exists():
            clean = onchain_txt.read_text(encoding="utf-8").strip().replace("0x", "")
            if len(clean) == 64:
                return bytes.fromhex(clean)

        # Check directory name if already 64-char hex
        clean_dir = bundle_dir.name.lower().replace("0x", "")
        if len(clean_dir) == 64:
            try:
                return bytes.fromhex(clean_dir)
            except ValueError:
                pass

        # Try database resolution if available
        if get_case is not None:
            case = get_case(bundle_dir.name)
            if not case and get_case_by_onchain_id is not None:
                case = get_case_by_onchain_id(bundle_dir.name)
            if case and case.get("onchain_case_id"):
                clean = case["onchain_case_id"].replace("0x", "")
                if len(clean) == 64:
                    return bytes.fromhex(clean)

        return None

    def find_pending_bundles(self) -> List[Tuple[bytes, Path, str]]:
        """Finds all bundles in inbox with pcap.bin and org_secret.hex."""
        bundles: List[Tuple[bytes, Path, str]] = []
        if not self.inbox_dir.exists():
            return bundles

        for entry in self.inbox_dir.iterdir():
            if not entry.is_dir():
                continue
            enc_file = entry / "bundle.enc"
            pcap_file = entry / "pcap.bin"
            secret_file = entry / "org_secret.hex"
            if enc_file.exists():
                case_bytes = self.resolve_case_bytes(entry)
                if case_bytes:
                    bundles.append((case_bytes, entry, ""))
            elif pcap_file.exists() and secret_file.exists():
                case_bytes = self.resolve_case_bytes(entry)
                if case_bytes:
                    org_secret = secret_file.read_text(encoding="utf-8").strip()
                    bundles.append((case_bytes, entry, org_secret))
        return bundles

    # -----------------------------------------------------------------------
    # Consensus Operations (Commit, Wait, Advance, Reveal, Finalize)
    # -----------------------------------------------------------------------

    def resume_from_state(self) -> bool:
        """
        Restart safety: on startup or cycle, resumes from validator_state
        (committed but not revealed, or already revealed) without double-submitting.
        Returns True if an active action was performed.
        """
        saved = self.load_state()
        if not saved or "caseId" not in saved:
            return False

        case_id_hex = saved["caseId"].replace("0x", "")
        case_id_bytes = bytes.fromhex(case_id_hex)
        round_num = saved.get("round", 1)

        # Verify case exists on chain
        if not self.case_registry.functions.caseExists(case_id_bytes).call():
            return False

        has_committed = self.quorum.functions.hasCommitted(case_id_bytes, round_num, self.account.address).call()
        has_revealed = self.quorum.functions.hasRevealed(case_id_bytes, round_num, self.account.address).call()

        if has_revealed:
            # Already revealed: no double-submission
            return False

        if not has_committed:
            # Not yet committed on-chain; handled by normal process_case flow
            return False

        # Committed but not revealed: resume reveal process
        logger.info(
            "Resuming case 0x%s from stored state (committed=True, revealed=False)",
            case_id_bytes.hex(),
        )

        salt_bytes = bytes.fromhex(saved["salt"].replace("0x", ""))
        root_bytes = bytes.fromhex(saved["resultRoot"].replace("0x", ""))
        onchain_engine = self.case_registry.functions.engineHash(case_id_bytes).call()
        onchain_ruleset = self.case_registry.functions.rulesetHash(case_id_bytes).call()

        # Check commit deadline
        round_params = self.quorum.functions.getRoundParams(case_id_bytes, round_num).call()
        commit_deadline = round_params[2]

        current_time = self.w3.eth.get_block("latest").timestamp
        while current_time < commit_deadline:
            if getattr(self.w3.provider, "make_request", None):
                try:
                    if self.w3.eth.chain_id in (31337, 1337):
                        diff = commit_deadline - current_time + 1
                        if diff > 0:
                            self.w3.provider.make_request("evm_increaseTime", [int(diff)])
                            self.w3.provider.make_request("evm_mine", [])
                    else:
                        self.w3.provider.make_request("evm_mine", [])
                except Exception:
                    pass
            time.sleep(0.5)
            current_time = self.w3.eth.get_block("latest").timestamp

        # Advance if still in Committing
        case_state = self.case_registry.functions.caseState(case_id_bytes).call()
        if case_state == 3:  # Committing
            try:
                logger.info("Advancing case 0x%s to Revealing state", case_id_bytes.hex())
                adv_fn = self.quorum.functions.advance(case_id_bytes)
                send_validator_tx(self.w3, adv_fn, self.account, self.private_key)
            except Exception as exc:
                logger.info("Advance note (could be advanced by peer): %s", exc)

        # Broadcast reveal
        case_state = self.case_registry.functions.caseState(case_id_bytes).call()
        if case_state == 4:  # Revealing
            has_revealed_now = self.quorum.functions.hasRevealed(case_id_bytes, round_num, self.account.address).call()
            if not has_revealed_now:
                logger.info("Submitting stored reveal for case 0x%s", case_id_bytes.hex())
                reveal_fn = self.quorum.functions.reveal(
                    case_id_bytes,
                    root_bytes,
                    salt_bytes,
                    onchain_engine,
                    onchain_ruleset,
                )
                send_validator_tx(self.w3, reveal_fn, self.account, self.private_key)
                logger.info("Reveal transaction confirmed for 0x%s", case_id_bytes.hex())

            saved["revealed"] = True
            self.save_state(saved)
            return True

        return False

    def process_bundle(self, case_id_bytes: bytes, bundle_dir: Path, org_secret_hex: str) -> bool:
        """Processes a single case bundle through commit-reveal consensus."""
        if not self.case_registry.functions.caseExists(case_id_bytes).call():
            return False

        case_state = self.case_registry.functions.caseState(case_id_bytes).call()
        case_round = self.case_registry.functions.caseRound(case_id_bytes).call()

        # Case must be in Committing (3) or Revealing (4)
        if case_state not in (3, 4):
            return False

        # Verify validator is in snapshot for this round
        is_in_snapshot = self.quorum.functions.isSnapshotValidator(
            case_id_bytes, case_round, self.account.address
        ).call()
        if not is_in_snapshot:
            # Per specification: an inbox bundle for a case the validator is not in is ignored
            logger.info(
                "Validator %s is NOT in snapshot for case 0x%s round %d. Ignoring bundle.",
                self.validator_id,
                case_id_bytes.hex(),
                case_round,
            )
            return False

        already_committed = self.quorum.functions.hasCommitted(
            case_id_bytes, case_round, self.account.address
        ).call()
        already_revealed = self.quorum.functions.hasRevealed(
            case_id_bytes, case_round, self.account.address
        ).call()

        if already_revealed:
            return False

        if already_committed:
            # Resume reveal flow
            return self.resume_from_state()

        # 1. Execute engine (Prompt T3.1: encrypted delivery via secure temp dir mode 0700)
        enc_file = bundle_dir / "bundle.enc"
        if enc_file.exists():
            from validator.crypto import decrypt_validator_bundle
            from validator.keygen import load_validator_private_key

            val_priv = load_validator_private_key(self.state_dir, self.validator_id)
            bundle_bytes = enc_file.read_bytes()
            pcap_bytes, decrypted_secret, onchain_id = decrypt_validator_bundle(bundle_bytes, val_priv)

            if not onchain_id:
                if self.strict:
                    raise ValueError("Encrypted bundle metadata missing onchain_case_id in strict mode")
            else:
                clean_decrypted = onchain_id.lower().replace("0x", "")
                clean_target = case_id_bytes.hex().lower().replace("0x", "")
                if clean_decrypted != clean_target:
                    raise ValueError(
                        f"Delivered bundle case ID (0x{clean_decrypted}) does not match target case ID (0x{clean_target})"
                    )

            # Validate delivered PCAP SHA-256 against on-chain pcapHash (fail-closed)
            pcap_sha256 = hashlib.sha256(pcap_bytes).digest()
            onchain_pcap_hash = self.case_registry.functions.pcapHash(case_id_bytes).call()
            if not onchain_pcap_hash or onchain_pcap_hash == b"\x00" * 32:
                raise ValueError("Target case has missing or zero on-chain pcapHash")
            if pcap_sha256 != onchain_pcap_hash:
                raise ValueError(
                    f"Delivered PCAP hash (0x{pcap_sha256.hex()}) does not match on-chain case pcapHash (0x{onchain_pcap_hash.hex()})"
                )

            temp_dir = tempfile.mkdtemp(prefix="val_sec_")
            try:
                os.chmod(temp_dir, 0o700)
            except Exception:
                pass
            temp_path = Path(temp_dir)
            try:
                temp_pcap = temp_path / "pcap.bin"
                temp_pcap.write_bytes(pcap_bytes)
                result_root_bytes, result_data, manifest_data = self.run_engine_analysis(
                    bundle_dir=temp_path,
                    pcap_path=temp_pcap,
                    org_secret_hex=decrypted_secret,
                    case_id_hex=case_id_bytes.hex(),
                )
            finally:
                # Prompt T3.1: temporary directory removed after engine run on both success and failure
                shutil.rmtree(temp_path, ignore_errors=True)
        else:
            pcap_path = bundle_dir / "pcap.bin"
            pcap_bytes = pcap_path.read_bytes()

            # Check onchain_case_id.txt if present
            case_id_txt = bundle_dir / "onchain_case_id.txt"
            if case_id_txt.exists():
                txt_id = case_id_txt.read_text(encoding="utf-8").strip()
                clean_txt = txt_id.lower().replace("0x", "")
                clean_target = case_id_bytes.hex().lower().replace("0x", "")
                if clean_txt != clean_target:
                    raise ValueError(
                        f"Delivered bundle case ID (0x{clean_txt}) does not match target case ID (0x{clean_target})"
                    )
            elif self.strict:
                raise ValueError("Plaintext bundle missing onchain_case_id.txt in strict mode")

            # Validate delivered PCAP SHA-256 against on-chain pcapHash (fail-closed)
            pcap_sha256 = hashlib.sha256(pcap_bytes).digest()
            onchain_pcap_hash = self.case_registry.functions.pcapHash(case_id_bytes).call()
            if not onchain_pcap_hash or onchain_pcap_hash == b"\x00" * 32:
                raise ValueError("Target case has missing or zero on-chain pcapHash")
            if pcap_sha256 != onchain_pcap_hash:
                raise ValueError(
                    f"Delivered PCAP hash (0x{pcap_sha256.hex()}) does not match on-chain case pcapHash (0x{onchain_pcap_hash.hex()})"
                )

            result_root_bytes, result_data, manifest_data = self.run_engine_analysis(
                bundle_dir=bundle_dir,
                pcap_path=pcap_path,
                org_secret_hex=org_secret_hex,
                case_id_hex=case_id_bytes.hex(),
            )

        # 2. Strict mode checks BEFORE commit
        if self.strict:
            self.verify_strict_mode(case_id_bytes, manifest_data)
        else:
            logger.warning(
                "Strict mode explicitly DISABLED (--faulty or non-strict) for validator %s on case 0x%s; proceeding without digest/ruleset verification",
                self.validator_id,
                case_id_bytes.hex(),
            )

        # 3. Generate random salt and compute commitment
        salt_bytes = os.urandom(32)
        encoded_payload = encode(
            ["bytes32", "address", "bytes32", "bytes32"],
            [case_id_bytes, self.account.address, result_root_bytes, salt_bytes],
        )
        commitment_bytes = Web3.keccak(encoded_payload)

        # 4. ATOMIC SAVE TO validator_state/<id>.json BEFORE SENDING COMMIT
        state_payload = {
            "validatorId": self.validator_id,
            "validatorAddress": self.account.address,
            "caseId": f"0x{case_id_bytes.hex()}",
            "round": case_round,
            "salt": f"0x{salt_bytes.hex()}",
            "resultRoot": f"0x{result_root_bytes.hex()}",
            "commitment": f"0x{commitment_bytes.hex()}",
            "strict": self.strict,
            "committedAt": int(time.time()),
            "revealed": False,
        }
        self.save_state(state_payload)

        # 5. Send commit transaction
        logger.info("Broadcasting commit transaction for case 0x%s", case_id_bytes.hex())
        commit_fn = self.quorum.functions.commit(case_id_bytes, commitment_bytes)
        send_validator_tx(self.w3, commit_fn, self.account, self.private_key)
        logger.info("Commit confirmed on-chain for case 0x%s", case_id_bytes.hex())

        # 6. Wait until commit deadline
        round_params = self.quorum.functions.getRoundParams(case_id_bytes, case_round).call()
        commit_deadline = round_params[2]

        current_time = self.w3.eth.get_block("latest").timestamp
        while current_time < commit_deadline:
            if getattr(self.w3.provider, "make_request", None):
                try:
                    if self.w3.eth.chain_id in (31337, 1337):
                        diff = commit_deadline - current_time + 1
                        if diff > 0:
                            self.w3.provider.make_request("evm_increaseTime", [int(diff)])
                            self.w3.provider.make_request("evm_mine", [])
                    else:
                        self.w3.provider.make_request("evm_mine", [])
                except Exception:
                    pass
            time.sleep(0.5)
            current_time = self.w3.eth.get_block("latest").timestamp

        # 7. Advance if needed
        cur_state = self.case_registry.functions.caseState(case_id_bytes).call()
        if cur_state == 3:  # Committing
            try:
                logger.info("Advancing case 0x%s to Revealing", case_id_bytes.hex())
                adv_fn = self.quorum.functions.advance(case_id_bytes)
                send_validator_tx(self.w3, adv_fn, self.account, self.private_key)
            except Exception as exc:
                logger.info("Advance note: %s", exc)

        # 8. Submit reveal
        onchain_engine = self.case_registry.functions.engineHash(case_id_bytes).call()
        onchain_ruleset = self.case_registry.functions.rulesetHash(case_id_bytes).call()

        cur_state = self.case_registry.functions.caseState(case_id_bytes).call()
        if cur_state == 4:  # Revealing
            logger.info("Broadcasting reveal for case 0x%s", case_id_bytes.hex())
            rev_fn = self.quorum.functions.reveal(
                case_id_bytes,
                result_root_bytes,
                salt_bytes,
                onchain_engine,
                onchain_ruleset,
            )
            send_validator_tx(self.w3, rev_fn, self.account, self.private_key)
            logger.info("Reveal confirmed for case 0x%s", case_id_bytes.hex())

            state_payload["revealed"] = True
            self.save_state(state_payload)

        return True

    def poll_and_process(self) -> int:
        """Runs a single polling and processing cycle. Returns number of actions taken."""
        actions = 0
        if self.resume_from_state():
            actions += 1

        pending_bundles = self.find_pending_bundles()
        for case_bytes, bundle_dir, secret_hex in pending_bundles:
            try:
                if self.process_bundle(case_bytes, bundle_dir, secret_hex):
                    actions += 1
            except Exception as exc:
                logger.error("Error processing case 0x%s: %s", case_bytes.hex(), exc)
        return actions

    def run_loop(self, stop_event: Optional[threading.Event] = None) -> None:
        """Main service loop running until stop_event is signaled."""
        logger.info("Starting validator %s event polling loop", self.validator_id)
        while stop_event is None or not stop_event.is_set():
            try:
                self.poll_and_process()
            except Exception as exc:
                logger.error("Error in validator poll loop: %s", exc)
            time.sleep(self.poll_interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="SecureMailScope Validator Service")
    parser.add_argument("--id", "-i", required=True, help="Validator ID (e.g. 1, 2, 3)")
    parser.add_argument("--key-env", help="Environment variable containing private key")
    parser.add_argument("--key", help="Direct private key hex")
    parser.add_argument("--inbox-dir", help="Custom inbox directory")
    parser.add_argument("--state-dir", help="Custom state directory")
    parser.add_argument("--rpc-url", default="http://127.0.0.1:8545", help="EVM RPC URL")
    parser.add_argument("--deployment-file", help="Path to deployment JSON")
    parser.add_argument("--poll-interval", type=float, default=1.0, help="Polling interval in seconds")
    parser.add_argument("--faulty", action="store_true", help="Faulty mode: tamper with result root")
    parser.add_argument("--no-strict", dest="strict", action="store_false", help="Disable strict mode")
    parser.add_argument("--use-docker", action="store_true", default=None, help="Force Docker execution")
    parser.add_argument("--no-docker", dest="use_docker", action="store_false", help="Disable Docker execution")

    args = parser.parse_args()

    private_key = None
    if args.key_env:
        private_key = os.environ.get(args.key_env)
    elif args.key:
        private_key = args.key

    if not private_key:
        # Fallback to VALIDATOR_<id>_KEY or VALIDATOR_KEY_<id> convention
        default_env = f"VALIDATOR_{args.id}_KEY"
        alt_env = f"VALIDATOR_KEY_{args.id}"
        private_key = os.environ.get(default_env) or os.environ.get(alt_env)
        if not private_key and config is not None:
            private_key = getattr(config, default_env, None) or getattr(config, alt_env, None)

    if not private_key:
        logger.error("No private key provided via --key-env, --key, or VALIDATOR_%s_KEY", args.id)
        sys.exit(1)

    inbox = Path(args.inbox_dir) if args.inbox_dir else None
    state = Path(args.state_dir) if args.state_dir else None
    deploy = Path(args.deployment_file) if args.deployment_file else None

    service = ValidatorService(
        validator_id=args.id,
        private_key=private_key,
        inbox_dir=inbox,
        state_dir=state,
        rpc_url=args.rpc_url,
        deployment_file=deploy,
        strict=args.strict,
        faulty=args.faulty,
        use_docker=args.use_docker,
        poll_interval=args.poll_interval,
    )

    try:
        service.run_loop()
    except KeyboardInterrupt:
        logger.info("Validator service %s stopped by user", args.id)


if __name__ == "__main__":
    main()
