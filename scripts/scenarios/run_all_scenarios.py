"""Automated Suite Runner for All SecureMailScope Scenarios.

Runs Scenarios (a), (b), (c), and (d) sequentially and verifies that all
failure modes and edge cases pass their respective assertions.
"""
import subprocess
import sys
import time
from pathlib import Path

repo_root = Path(__file__).resolve().parents[2]

SCENARIOS = [
    ("Scenario (a): Minority Outvoted & Identified", repo_root / "scripts" / "scenarios" / "scenario_a_minority_outvoted.py"),
    ("Scenario (b): Expired Quorum When Under-Revealed", repo_root / "scripts" / "scenarios" / "scenario_b_expired_quorum.py"),
    ("Scenario (c): 1-Byte Tampered PCAP Fails Verifier Step 1", repo_root / "scripts" / "scenarios" / "scenario_c_pcap_tampered.py"),
    ("Scenario (d): 1 Changed Finding Fails Verifier Step 2", repo_root / "scripts" / "scenarios" / "scenario_d_finding_tampered.py"),
]


def main():
    print("================================================================================")
    print("           SECUREMAILSCOPE AUTOMATED SCENARIO SUITE RUNNER                      ")
    print("================================================================================")

    results = []
    total_start = time.time()

    for name, script_path in SCENARIOS:
        print(f"\n>>> Running {name}...")
        start_time = time.time()
        res = subprocess.run([sys.executable, str(script_path)], cwd=str(repo_root))
        elapsed = time.time() - start_time
        success = (res.returncode == 0)
        results.append((name, success, elapsed))
        status_str = "PASS" if success else "FAIL"
        print(f">>> {name}: [{status_str}] in {elapsed:.2f}s")
        if not success:
            print(f"[!] Scenario exited with non-zero code {res.returncode}")

    print("\n================================================================================")
    print("                         SCENARIO TEST SUITE SUMMARY                            ")
    print("================================================================================")
    all_passed = True
    for name, success, elapsed in results:
        status_str = "PASS" if success else "FAIL"
        print(f" - {name:<55} : [{status_str}] ({elapsed:.2f}s)")
        if not success:
            all_passed = False

    total_elapsed = time.time() - total_start
    print("================================================================================")
    if all_passed:
        print(f"ALL {len(results)} SCENARIOS PASSED SUCCESSFULLY in {total_elapsed:.2f}s!")
        sys.exit(0)
    else:
        print(f"ONE OR MORE SCENARIOS FAILED. Total time: {total_elapsed:.2f}s")
        sys.exit(1)


if __name__ == "__main__":
    main()
