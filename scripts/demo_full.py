"""SecureMailScope: Full End-to-End Interactive Demonstration (Phase 9 / Prompt 9.1).

Demonstrates:
1. Happy path: S05 capture -> upload, analyze, open, claim, distribute, 3 validators,
   finalize, record posture, anchor report, verifier PASS.
2. Tamper scenario: Modifies 1 byte of PCAP, verifier Step 1 FAILS.
3. Byzantine Fault Tolerance: Validator 3 runs with --faulty and is outvoted by honest quorum.

Includes guided audience checkpoints explaining cryptographic guarantees at each step.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Pause interval in seconds between steps for presenter explanation
STEP_PAUSE = 2


def banner(title: str):
    print("\n" + "=" * 80)
    print(f" {title.center(78)} ")
    print("=" * 80)


def audience_checkpoint(num: int, title: str, explanation: str):
    print("\n" + "-" * 80)
    print(f"[AUDIENCE CHECKPOINT {num}]: {title.upper()}")
    print("-" * 80)
    print(explanation)
    print("-" * 80)
    if os.environ.get("DEMO_NON_INTERACTIVE") != "1":
        time.sleep(STEP_PAUSE)


def run_run1_happy_path() -> bool:
    banner("RUN 1: END-TO-END FORENSIC AUDIT (HAPPY PATH)")
    print("Scenario: S05 (Postfix SMTP with STARTTLS and cleartext credentials)")
    print("Step 1: Spawning local Hardhat node & deploying consensus smart contracts...")

    # We can invoke demo_e2e.py which executes this full lifecycle against local hardhat
    demo_e2e_path = REPO_ROOT / "scripts" / "demo_e2e.py"
    proc = subprocess.run([sys.executable, str(demo_e2e_path)], cwd=REPO_ROOT, text=True)
    if proc.returncode != 0:
        print("[!] Error in Run 1 demo execution.")
        return False

    audience_checkpoint(
        1,
        "Authentic Case Finalization & Report Anchoring",
        "LOOK AT THE TERMINAL:\n"
        "1. Case was opened and assigned a deterministic keccak256 caseId on-chain.\n"
        "2. Three independent validator nodes analyzed S05 and submitted commitments.\n"
        "3. Consensus reached (3/3 agreement) -> Case transitioned to 'Finalized'.\n"
        "4. Per-host security posture recorded with on-chain Merkle proof verification.\n"
        "5. Canonical SHA-256 report hash was permanently anchored in CaseRegistry.\n"
        "6. Independent 5-step Verifier completed with PASS across all verification stages."
    )
    return True


def run_run2_pcap_tamper() -> bool:
    banner("RUN 2: CRYPTOGRAPHIC TAMPER DETECTION (PCAP TAMPERED)")
    print("Scenario: An attacker attempts to alter 1 byte of the archived forensic PCAP...")

    scenario_c_path = REPO_ROOT / "scripts" / "scenarios" / "scenario_c_pcap_tampered.py"
    proc = subprocess.run([sys.executable, str(scenario_c_path)], cwd=REPO_ROOT, text=True)
    if proc.returncode != 0:
        print("[!] Error in Run 2 scenario execution.")
        return False

    audience_checkpoint(
        2,
        "Anti-Tampering Integrity Protection",
        "LOOK AT THE TERMINAL:\n"
        "1. Exactly one byte in S05.pcap was modified on disk.\n"
        "2. The 5-step forensic verifier executed against on-chain case registry.\n"
        "3. Verifier Step 1 immediately FAILED with 'PCAP SHA-256 hash mismatch'.\n"
        "4. Execution aborted cleanly, preventing fraudulent evidence admission."
    )
    return True


def run_run3_byzantine_fault() -> bool:
    banner("RUN 3: BYZANTINE FAULT TOLERANCE (ADVERSARIAL VALIDATOR OUTVOTED)")
    print("Scenario: Validator 3 is compromised and submits a forged result root...")

    scenario_a_path = REPO_ROOT / "scripts" / "scenarios" / "scenario_a_minority_outvoted.py"
    proc = subprocess.run([sys.executable, str(scenario_a_path)], cwd=REPO_ROOT, text=True)
    if proc.returncode != 0:
        print("[!] Error in Run 3 scenario execution.")
        return False

    audience_checkpoint(
        3,
        "Consensus Resilience Under Byzantine Attacks",
        "LOOK AT THE TERMINAL:\n"
        "1. Validator 3 ran with --faulty and submitted a rogue Merkle root.\n"
        "2. Honest Validators 1 & 2 submitted the true deterministic root.\n"
        "3. Quorum evaluation: 2-of-3 threshold k=2 satisfied by honest majority.\n"
        "4. Case successfully reached 'Finalized' with the authentic root.\n"
        "5. Rogue root was detected as a minority discrepancy and marked contradicted."
    )
    return True


def main():
    banner("SECUREMAILSCOPE FULL LIVE DEMONSTRATION")
    print("Course Project: Passive Network Forensic Framework for Secure Email Infrastructure")
    print("Architecture: Multi-Validator Byzantine Consensus on EVM Smart Contracts")

    success1 = run_run1_happy_path()
    if not success1:
        sys.exit(1)

    success2 = run_run2_pcap_tamper()
    if not success2:
        sys.exit(1)

    success3 = run_run3_byzantine_fault()
    if not success3:
        sys.exit(1)

    banner("DEMONSTRATION COMPLETED SUCCESSFULLY")
    print("Summary of verified capabilities:")
    print(" [PASS] Full End-to-End Forensic Pipeline (Upload -> Consensus -> Verifier PASS)")
    print(" [PASS] Cryptographic Tamper Detection (1-byte PCAP modification caught)")
    print(" [PASS] Byzantine Fault Tolerance (Adversarial validator successfully outvoted)")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
