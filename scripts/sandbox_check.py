#!/usr/bin/env python3
"""Container Sandbox Environment Checker (Tier 2 / Prompt T2.6).

Runs inside the engine container to verify:
1. Passive execution / No network access (outbound connections must fail).
2. Non-root user privileges (UID != 0).
3. Read-only root filesystem (writes outside configured output dir must fail).
4. Output directory is properly writable.
"""
import argparse
import os
import socket
import sys
from pathlib import Path


def check_network() -> bool:
    """Verifies that network calls fail (no external network access)."""
    test_targets = [
        ("1.1.1.1", 53),
        ("8.8.8.8", 53),
        ("93.184.216.34", 80),  # example.com
    ]
    for host, port in test_targets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect((host, port))
            s.close()
            # If any connection succeeds, network isolation is breached
            sys.stderr.write(f"[SANDBOX BREACH] Network connection succeeded to {host}:{port}!\n")
            return False
        except (OSError, socket.timeout):
            # Expected behavior: connection attempt fails
            pass
    return True


def check_non_root() -> bool:
    """Verifies that the process is not running as root (UID 0)."""
    if hasattr(os, "getuid"):
        uid = os.getuid()
        euid = os.geteuid()
        if uid == 0 or euid == 0:
            sys.stderr.write(f"[SANDBOX BREACH] Process running as root! (UID={uid}, EUID={euid})\n")
            return False
        print(f"[SANDBOX PASS] Non-root user confirmed: UID={uid}, EUID={euid}")
        return True
    else:
        # Non-POSIX fallback (e.g. Windows dev machine)
        user = os.environ.get("USERNAME", "unknown")
        print(f"[SANDBOX PASS] User identity check: {user}")
        return True


def check_filesystem(out_dir_path: Path) -> bool:
    """Verifies root filesystem is read-only and output directory is writable."""
    # 1. Test read-only enforcement outside output dir
    test_paths = [
        Path("/app/sandbox_test_write.tmp"),
        Path("/sandbox_test_write.tmp"),
    ]
    
    # In container or Linux, test writing to root or app directory
    for p in test_paths:
        try:
            p.write_bytes(b"fail_test")
            # If written, delete and fail
            p.unlink(missing_ok=True)
            sys.stderr.write(f"[SANDBOX BREACH] Root filesystem is writable at {p}!\n")
            return False
        except (PermissionError, OSError):
            # Expected: read-only filesystem or permission denied
            pass

    # 2. Test output directory writability
    out_dir_path.mkdir(parents=True, exist_ok=True)
    probe_file = out_dir_path / "sandbox_probe.tmp"
    try:
        probe_file.write_bytes(b"sandbox_ok")
        if probe_file.read_bytes() != b"sandbox_ok":
            sys.stderr.write(f"[SANDBOX ERROR] Failed to read probe file in {out_dir_path}\n")
            return False
        probe_file.unlink()
    except Exception as e:
        sys.stderr.write(f"[SANDBOX ERROR] Output directory is not writable: {e}\n")
        return False

    print(f"[SANDBOX PASS] Read-only root filesystem and writable output dir confirmed ({out_dir_path})")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Check container sandbox security constraints")
    parser.add_argument(
        "--out-dir",
        type=str,
        default="/tmp/out",
        help="Designated output directory (default: /tmp/out)",
    )
    args = parser.parse_args()

    print("============================================================")
    print("SecureMailScope Engine Sandbox Verification")
    print("============================================================")

    # 1. Network Isolation Check
    if not check_network():
        print("[FAIL] Network isolation check failed.")
        return 1
    print("[SANDBOX PASS] Passive mode / zero outbound network access confirmed.")

    # 2. Non-Root User Check
    if not check_non_root():
        print("[FAIL] Non-root check failed.")
        return 1

    # 3. Read-Only Root Filesystem Check
    out_dir = Path(args.out_dir)
    # If testing outside container (e.g., local dev), create local temp if /tmp/out is not present
    if not out_dir.exists() and not str(out_dir).startswith("/"):
        out_dir = Path("data/sandbox_out")

    if not check_filesystem(out_dir):
        print("[FAIL] Filesystem permissions check failed.")
        return 1

    print("============================================================")
    print("ALL SANDBOX CONSTRAINTS VERIFIED SUCCESSFULLY.")
    print("============================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
