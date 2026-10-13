"""Python-based determinism check across two consecutive engine runs (Prompt 5.8)."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = Path(__file__).resolve().parents[1]
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"
TRUST_STORE_PATH = REPO_ROOT / "lab" / "ca" / "out" / "client_trust.crt"
ORG_SECRET_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

EXPECTED_FILES = [
    "sessions.json",
    "findings.json",
    "host_scores.json",
    "result.json",
    "host_proofs.json",
    "manifest.json",
]


def run_analysis(pcap_path: Path, out_dir: Path, case_id: str, env: dict) -> None:
    cmd = [
        sys.executable,
        "-m",
        "smscope",
        "analyze",
        str(pcap_path),
        "--org-secret-hex",
        ORG_SECRET_HEX,
        "--out",
        str(out_dir),
        "--case-id",
        case_id,
    ]
    if TRUST_STORE_PATH.exists():
        cmd.extend(["--trust-store", str(TRUST_STORE_PATH)])

    res = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if res.returncode != 0:
        raise RuntimeError(f"Engine analysis failed: {res.stderr}")


def main():
    pcap_files = sorted(CAPTURES_DIR.glob("*.pcap"))
    if not pcap_files:
        print(f"Error: No PCAP files found in {CAPTURES_DIR}", file=sys.stderr)
        return 1

    env = os.environ.copy()
    pythonpath = str(REPO_ROOT / "engine")
    if "PYTHONPATH" in env:
        env["PYTHONPATH"] = f"{pythonpath}{os.pathsep}{env['PYTHONPATH']}"
    else:
        env["PYTHONPATH"] = pythonpath

    failed = 0
    total = len(pcap_files)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_base = Path(tmp_dir)

        print(f"=== Running Determinism Check on {total} captures ===")
        for pcap in pcap_files:
            scenario = pcap.stem
            out1 = tmp_base / f"{scenario}_run1"
            out2 = tmp_base / f"{scenario}_run2"

            run_analysis(pcap, out1, f"det-{scenario}", env)
            run_analysis(pcap, out2, f"det-{scenario}", env)

            scenario_failed = False
            for fname in EXPECTED_FILES:
                f1 = out1 / fname
                f2 = out2 / fname
                if not f1.exists() or not f2.exists():
                    print(f"[-] {scenario}: Missing {fname} in one of the runs", file=sys.stderr)
                    scenario_failed = True
                    break

                sha1 = hashlib.sha256(f1.read_bytes()).hexdigest()
                sha2 = hashlib.sha256(f2.read_bytes()).hexdigest()

                if sha1 != sha2:
                    print(f"[-] {scenario}: Divergence in {fname}! sha1={sha1}, sha2={sha2}", file=sys.stderr)
                    scenario_failed = True
                    break

            if scenario_failed:
                failed += 1
            else:
                print(f"[PASS] {scenario}: Run 1 and Run 2 produced bit-for-bit identical outputs.")

    print("====================================================")
    if failed == 0:
        print(f"SUCCESS: Zero differences detected across all {total} scenarios.")
        return 0
    else:
        print(f"FAILURE: {failed}/{total} scenarios had non-deterministic differences.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
