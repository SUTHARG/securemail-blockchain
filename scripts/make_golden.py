"""Generate committed golden outputs for all lab captures (Prompt 5.8)."""
import os
from pathlib import Path
import subprocess
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"
GOLDEN_DIR = REPO_ROOT / "tests" / "golden"
ENGINE_GOLDEN_DIR = REPO_ROOT / "engine" / "tests" / "golden"
ORG_SECRET_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
TRUST_STORE_PATH = REPO_ROOT / "lab" / "ca" / "out" / "client_trust.crt"


def main():
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    pcap_files = sorted(CAPTURES_DIR.glob("*.pcap"))
    if not pcap_files:
        print(f"Error: No PCAP files found in {CAPTURES_DIR}", file=sys.stderr)
        return 1

    print(f"Generating golden outputs for {len(pcap_files)} captures...")

    env = os.environ.copy()
    pythonpath = str(REPO_ROOT / "engine")
    if "PYTHONPATH" in env:
        env["PYTHONPATH"] = f"{pythonpath}{os.pathsep}{env['PYTHONPATH']}"
    else:
        env["PYTHONPATH"] = pythonpath

    for pcap in pcap_files:
        scenario = pcap.stem
        out_scenario_dir = GOLDEN_DIR / scenario
        out_scenario_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable,
            "-m",
            "smscope",
            "analyze",
            str(pcap),
            "--org-secret-hex",
            ORG_SECRET_HEX,
            "--out",
            str(out_scenario_dir),
            "--case-id",
            f"golden-{scenario}",
        ]
        if TRUST_STORE_PATH.exists():
            cmd.extend(["--trust-store", str(TRUST_STORE_PATH)])

        result = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            print(f"[-] Failed to generate golden outputs for {scenario}: {result.stderr}", file=sys.stderr)
            return 1

        print(f"[+] Generated golden outputs for {scenario} in {out_scenario_dir}")

    print("Successfully generated all golden outputs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
