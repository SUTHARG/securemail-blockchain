"""Admin CLI script for resolving Disputed or Expired cases on ValidationQuorum.

Usage:
    python scripts/resolve_case.py --case <case_id> [--action NewRound|AttestMajority|Reject] [--root <hex>]
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

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("resolve_case")


def main():
    parser = argparse.ArgumentParser(
        description="Admin CLI to resolve an Expired or Disputed case on ValidationQuorum."
    )
    parser.add_argument(
        "--case",
        "-c",
        dest="case_id",
        required=True,
        help="Case ID or onchain case ID to resolve",
    )
    parser.add_argument(
        "--action",
        "-a",
        dest="action",
        choices=["NewRound", "AttestMajority", "Reject"],
        default="NewRound",
        help="Resolution action (default: NewRound)",
    )
    parser.add_argument(
        "--root",
        "-r",
        dest="root",
        default=None,
        help="Optional result root hex for AttestMajority action",
    )

    args = parser.parse_args()

    print("=================================================================")
    print(" SecureMailScope - Admin Case Resolution CLI")
    print("=================================================================")
    print(f"[*] Targeting Case: {args.case_id}")
    print(f"[*] Resolution Action: {args.action}")

    try:
        gateway = ChainGateway()
    except Exception as exc:
        print(f"[!] ERROR: Failed to connect to blockchain gateway: {exc}")
        sys.exit(1)

    case, onchain_bytes = gateway._resolve_onchain_id(args.case_id)
    cur_state_int = gateway.case_registry.functions.caseState(onchain_bytes).call()
    cur_round = gateway.case_registry.functions.caseRound(onchain_bytes).call()

    from backend.chain.gateway import STATE_MAP
    state_str = STATE_MAP.get(cur_state_int, str(cur_state_int))
    print(f"[*] Current On-Chain State: {state_str} (Round {cur_round})")

    if cur_state_int not in (6, 7):  # Disputed=6, Expired=7
        print(f"[!] NOTICE: Case is in state '{state_str}'. Resolution is only allowed for Disputed or Expired cases.")
        if cur_state_int in (3, 4):
            print("    Run validator consensus or advance/finalize the round first to transition to Expired.")
        sys.exit(1)

    try:
        res = gateway.resolve(args.case_id, action=args.action, root_hex=args.root)
        new_round = gateway.case_registry.functions.caseRound(onchain_bytes).call()
        print("\n[+] SUCCESS: Case resolution applied on-chain!")
        print(f"    - Transaction Hash: {res.get('txHash')}")
        print(f"    - New State: {res.get('status')}")
        print(f"    - Round: {new_round}")
        print(f"\n[+] The case is now ready for validator consensus in Round {new_round}!")
    except Exception as exc:
        print(f"\n[!] ERROR: Failed to resolve case on-chain: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
