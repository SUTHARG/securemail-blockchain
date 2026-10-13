"""Validator cryptographic key generation utility (Tier 3 / Prompt T3.1).

Generates asymmetric Curve25519 key pairs for sealed box delivery:
- Private key is stored strictly with mode 0600 in the validator's state directory.
- Public key is output for registration with the backend.
"""
import argparse
import os
import sys
from pathlib import Path
from typing import Tuple

import nacl.public


def generate_validator_keypair(
    state_dir: Path,
    validator_id: str,
) -> Tuple[bytes, bytes]:
    """
    Generates a fresh Curve25519 key pair for a validator.
    Persists private key to <state_dir>/validator_<id>.key with mode 0600.
    Returns (private_key_bytes, public_key_bytes).
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    priv_path = state_dir / f"validator_{validator_id}.key"
    pub_path = state_dir / f"validator_{validator_id}.pub"

    private_key = nacl.public.PrivateKey.generate()
    public_key = private_key.public_key

    priv_bytes = bytes(private_key)
    pub_bytes = bytes(public_key)

    # Write private key with mode 0600 (owner read/write only)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY

    fd = os.open(str(priv_path), flags, 0o600)
    try:
        os.write(fd, priv_bytes.hex().encode("ascii"))
    finally:
        os.close(fd)

    # On POSIX systems, ensure permissions are explicitly mode 0600
    try:
        os.chmod(str(priv_path), 0o600)
    except Exception:
        pass

    # Write public key in hex
    pub_path.write_text(pub_bytes.hex(), encoding="ascii")

    return priv_bytes, pub_bytes


def load_validator_private_key(state_dir: Path, validator_id: str) -> nacl.public.PrivateKey:
    """Loads validator private key from state directory."""
    priv_path = state_dir / f"validator_{validator_id}.key"
    if not priv_path.exists():
        raise FileNotFoundError(f"Validator private key not found at {priv_path}")
    raw_hex = priv_path.read_text(encoding="ascii").strip()
    return nacl.public.PrivateKey(bytes.fromhex(raw_hex))


def load_validator_public_key(state_dir: Path, validator_id: str) -> nacl.public.PublicKey:
    """Loads validator public key from state directory."""
    pub_path = state_dir / f"validator_{validator_id}.pub"
    if not pub_path.exists():
        raise FileNotFoundError(f"Validator public key not found at {pub_path}")
    raw_hex = pub_path.read_text(encoding="ascii").strip()
    return nacl.public.PublicKey(bytes.fromhex(raw_hex))


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Curve25519 key pair for validator")
    parser.add_argument(
        "--validator-id",
        "--id",
        dest="validator_id",
        required=True,
        type=str,
        help="Validator ID (e.g. 1, 2, 3)",
    )
    parser.add_argument(
        "--state-dir",
        type=str,
        default="validator_state",
        help="Directory to store private key with mode 0600",
    )
    parser.add_argument(
        "--register",
        type=str,
        default=None,
        help="Backend API URL to register public key (e.g. http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="Analyst API key for backend registration (defaults to ANALYST_API_KEY env var)",
    )

    args = parser.parse_args()
    state_dir = Path(args.state_dir)

    priv_b, pub_b = generate_validator_keypair(state_dir, args.validator_id)
    print(f"Generated key pair for validator {args.validator_id}")
    print(f"Private key saved to: {state_dir / f'validator_{args.validator_id}.key'} (mode 0600)")
    print(f"Public key (hex): {pub_b.hex()}")

    if args.register:
        import json
        import urllib.request
        import urllib.error

        base_url = args.register.rstrip("/")
        reg_url = f"{base_url}/validators/{args.validator_id}/key"
        api_key = args.api_key or os.environ.get("ANALYST_API_KEY", "")

        req_data = json.dumps({"publicKeyHex": pub_b.hex()}).encode("utf-8")
        req = urllib.request.Request(
            reg_url,
            data=req_data,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": api_key,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                print(f"Successfully registered public key with backend: {resp.status}")
        except urllib.error.HTTPError as err:
            print(f"Failed to register key with backend: HTTP {err.code}: {err.read().decode('utf-8')}", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"Connection failed registering key: {exc}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
