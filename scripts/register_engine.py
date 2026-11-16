"""Admin CLI script for registering analysis engine image digest and ruleset hash on CaseRegistry.

Usage:
    python scripts/register_engine.py [--case <case_id>] [--image-digest <hex>] [--ruleset-hash <hex>]
"""
import argparse
import logging
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import backend.config as config
from backend.chain.gateway import ChainGateway, GatewayError
from backend.database import get_case
from backend.storage import read_case_json

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("register_engine")


def main():
    parser = argparse.ArgumentParser(
        description="Idempotently register engine image digest and ruleset hash on CaseRegistry (Admin only)."
    )
    parser.add_argument(
        "--case",
        "-c",
        dest="case_id",
        help="Case ID to extract ruleset hash from manifest.json",
        default=None,
    )
    parser.add_argument(
        "--image-digest",
        dest="image_digest",
        help="Override engine image digest (hex string)",
        default=None,
    )
    parser.add_argument(
        "--ruleset-hash",
        dest="ruleset_hash",
        help="Override ruleset hash (hex string)",
        default=None,
    )
    parser.add_argument(
        "--skip-validators",
        dest="skip_validators",
        action="store_true",
        help="Skip automatic registration of validator quorum keys",
        default=False,
    )

    args = parser.parse_args()

    print("=================================================================")
    print(" SecureMailScope - Admin Engine Registration CLI")
    print("=================================================================")

    if args.case_id:
        case = get_case(args.case_id)
        if not case:
            print(f"[-] Error: Case '{args.case_id}' not found in database.", file=sys.stderr)
            sys.exit(1)
        print(f"[*] Targeting Case: {args.case_id}")

    try:
        gateway = ChainGateway()
    except Exception as exc:
        print(f"[-] Error connecting to blockchain gateway: {exc}", file=sys.stderr)
        print("    Ensure your local Hardhat node is running at " + config.RPC_URL)
        sys.exit(1)

    print(f"[*] Blockchain RPC: {gateway.rpc_url}")
    print(f"[*] CaseRegistry Address: {gateway.case_registry.address}")
    print(f"[*] Admin Signing Address: {gateway.admin_account.address}")

    # Inspect current on-chain state
    try:
        active_img, active_ruleset = gateway.case_registry.functions.activeEngine().call()
        print(f"[*] Current On-Chain activeImageDigest: 0x{active_img.hex()}")
        print(f"[*] Current On-Chain activeRulesetHash: 0x{active_ruleset.hex()}")
    except Exception as exc:
        print(f"[-] Failed to read activeEngine from CaseRegistry: {exc}", file=sys.stderr)
        sys.exit(1)

    print("\n[*] Executing idempotent registration...")
    try:
        res = gateway.register_engine_for_case(
            case_id=args.case_id,
            image_digest_hex=args.image_digest,
            ruleset_hash_hex=args.ruleset_hash,
            ensure_validators=not args.skip_validators,
        )
    except Exception as exc:
        print(f"[-] Registration failed: {exc}", file=sys.stderr)
        sys.exit(1)

    if res.get("idempotent"):
        print("[+] IDEMPOTENT: Engine and ruleset are ALREADY registered on-chain.")
        print(f"    - activeImageDigest: {res['imageDigest']}")
        print(f"    - activeRulesetHash: {res['rulesetHash']}")
        print("    - No duplicate transaction was sent.")
    else:
        print("[+] SUCCESS: Engine and ruleset successfully registered on CaseRegistry!")
        print(f"    - Transaction Hash: {res.get('txHash')}")
        print(f"    - activeImageDigest: {res['imageDigest']}")
        print(f"    - activeRulesetHash: {res['rulesetHash']}")

    # Check validator count
    val_count = gateway.case_registry.functions.validatorCount().call()
    print(f"[*] Active registered validators: {val_count}/3")
    if res.get("validatorsAdded"):
        print(f"    - Added validators: {', '.join(res['validatorsAdded'])}")

    print("\n[+] Verification complete! The case workflow is now ready for claim submission.")
    if args.case_id:
        print(f"    You can now click 'Submit Claim On-Chain (submitClaim)' for case {args.case_id}")
        print(f"    or POST to http://127.0.0.1:8000/cases/{args.case_id}/action/claim")
    print("=================================================================\n")


if __name__ == "__main__":
    main()
