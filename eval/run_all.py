"""Master Evaluation Orchestrator (Milestone M5).

Executes all evaluation experiments E1 through E7 sequentially, regenerates
all CSV and Markdown result tables in eval/results/, and outputs an overarching
summary report.

Usage:
    python eval/run_all.py
"""
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "eval" / "results"

EXPERIMENTS = [
    {
        "id": "E1",
        "name": "Parsing Agreement",
        "script": "eval/e1_parsing_agreement.py",
        "description": "Compares stream, protocol, TLS, cipher, and cert parsing vs tshark ground truth",
        "csv": "eval/results/e1_parsing_agreement.csv",
        "md": "eval/results/e1_parsing_agreement.md",
    },
    {
        "id": "E2",
        "name": "Detection Accuracy",
        "script": "eval/e2_detection_accuracy.py",
        "description": "Per-rule precision and recall over all 17 lab scenarios with confusion analysis",
        "csv": "eval/results/e2_detection_accuracy.csv",
        "md": "eval/results/e2_detection_accuracy.md",
    },
    {
        "id": "E3",
        "name": "Baseline Comparison",
        "script": "eval/e3_baseline_comparison.py",
        "description": "Comparative audit between Zeek network notices and SecureMailScope findings",
        "csv": "eval/results/e3_baseline_comparison.csv",
        "md": "eval/results/e3_baseline_comparison.md",
    },
    {
        "id": "E4",
        "name": "Determinism",
        "script": "eval/e4_determinism.py",
        "description": "Byte-identical verification of engine output hashes across 5 repeated runs",
        "csv": "eval/results/e4_determinism.csv",
        "md": "eval/results/e4_determinism.md",
    },
    {
        "id": "E5",
        "name": "Chain Tests",
        "script": "eval/e5_chain_tests.py",
        "description": "On-chain tamper detection, Byzantine fault recovery, RBAC, and quorum states",
        "csv": "eval/results/e5_chain_tests.csv",
        "md": "eval/results/e5_chain_tests.md",
    },
    {
        "id": "E6",
        "name": "Gas Consumption",
        "script": "eval/e6_gas.py",
        "description": "EVM gas measurements for all 7 on-chain operations across N=3 and N=5 quorums",
        "csv": "eval/results/e6_gas.csv",
        "md": "eval/results/e6_gas.md",
    },
    {
        "id": "E7",
        "name": "Zero Leak Test",
        "script": "eval/e7_leak_test.py",
        "description": "Full scan of engine outputs, reports, database logs, and state for secret leakage",
        "csv": "eval/results/e7_leak_test.csv",
        "md": "eval/results/e7_leak_test.md",
    },
    {
        "id": "E8",
        "name": "Advisory Anomaly Detection",
        "script": "eval/e8_anomaly.py",
        "description": "Detection rate & false positive evaluation of advisory ML Isolation Forest vs rule engine",
        "csv": "eval/results/e8_anomaly.csv",
        "md": "eval/results/e8_anomaly.md",
    },
]


def run_experiment(exp: dict) -> Tuple[bool, float, str]:
    """Runs a single experiment script as a subprocess."""
    script_path = REPO_ROOT / exp["script"]
    t0 = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, str(script_path)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        elapsed = time.time() - t0
        if proc.returncode == 0:
            return True, elapsed, "SUCCESS"
        else:
            err = proc.stderr.strip() or proc.stdout.strip()
            return False, elapsed, f"FAIL (Exit {proc.returncode}): {err[:200]}"
    except Exception as e:
        elapsed = time.time() - t0
        return False, elapsed, f"EXCEPTION: {str(e)}"


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    print("=" * 78)
    print("      SECUREMAILSCOPE EVALUATION SUITE ORCHESTRATOR (MILESTONE M5)")
    print("=" * 78)
    print(f"Running {len(EXPERIMENTS)} experiments from {REPO_ROOT.as_posix()}...\n")

    summary_rows = []
    all_passed = True

    for exp in EXPERIMENTS:
        print(f"--> Running {exp['id']}: {exp['name']} ({exp['script']})...", end="", flush=True)
        success, elapsed, msg = run_experiment(exp)
        if success:
            print(f" PASS ({elapsed:.2f}s)")
            summary_rows.append((exp["id"], exp["name"], "PASS", f"{elapsed:.2f}s", exp["md"]))
        else:
            print(f" FAIL ({elapsed:.2f}s)")
            print(f"    Details: {msg}")
            summary_rows.append((exp["id"], exp["name"], "FAIL", f"{elapsed:.2f}s", exp["md"]))
            all_passed = False

    print("\n" + "=" * 78)
    print("                         EVALUATION SUMMARY REPORT")
    print("=" * 78)
    print(f"{'Exp':<5} | {'Experiment Name':<24} | {'Status':<6} | {'Runtime':<8} | {'Artifact Path'}")
    print("-" * 78)
    for row in summary_rows:
        print(f"{row[0]:<5} | {row[1]:<24} | {row[2]:<6} | {row[3]:<8} | {row[4]}")
    print("=" * 78)

    if all_passed:
        print("\nAll evaluation experiments completed successfully with 100% acceptance.")
        print(f"All 14 evaluation artifacts generated in: {RESULTS_DIR.as_posix()}\n")
        sys.exit(0)
    else:
        print("\nOne or more evaluation experiments failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
