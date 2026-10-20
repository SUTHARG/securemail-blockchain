"""Cryptographic operations for encrypted validator delivery and storage at rest (Tier 3 / Prompt T3.1).

Implements:
1. Envelope encryption with AES-256-GCM and PyNaCl SealedBox (Curve25519) per validator.
2. Secure decryption into temporary directory (mode 0700).
3. Symmetric encryption at rest for case PCAPs.
"""
import base64
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import nacl.public
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_validator_bundle(
    pcap_bytes: bytes,
    org_secret_hex: str,
    validator_public_key: nacl.public.PublicKey,
    onchain_case_id: Optional[str] = None,
) -> bytes:
    """
    Encrypts case PCAP and organization secret for a validator.
    1. Generates fresh random AES-256 key (32 bytes).
    2. Encrypts payload with AES-256-GCM (12-byte nonce).
    3. Wraps AES key with recipient's public key using PyNaCl SealedBox.
    Returns JSON bytes.
    """
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    payload = {
        "pcap": base64.b64encode(pcap_bytes).decode("ascii"),
        "org_secret": org_secret_hex.strip(),
        "onchain_case_id": onchain_case_id.strip() if onchain_case_id else None,
    }
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    ciphertext = aesgcm.encrypt(nonce, payload_bytes, None)

    # Wrap AES key with SealedBox
    sealed_box = nacl.public.SealedBox(validator_public_key)
    wrapped_key = sealed_box.encrypt(aes_key)

    bundle = {
        "version": 1,
        "wrappedKeyHex": wrapped_key.hex(),
        "nonceHex": nonce.hex(),
        "ciphertextHex": ciphertext.hex(),
    }
    return json.dumps(bundle, indent=2).encode("utf-8")


def decrypt_validator_bundle(
    bundle_bytes: bytes,
    validator_private_key: nacl.public.PrivateKey,
) -> Tuple[bytes, str, Optional[str]]:
    """
    Decrypts an encrypted validator bundle using the validator's private key.
    Returns: (pcap_bytes, org_secret_hex, onchain_case_id).
    Raises CryptoError / InvalidTag if key is wrong or ciphertext is tampered.
    """
    bundle = json.loads(bundle_bytes.decode("utf-8"))
    wrapped_key = bytes.fromhex(bundle["wrappedKeyHex"])
    nonce = bytes.fromhex(bundle["nonceHex"])
    ciphertext = bytes.fromhex(bundle["ciphertextHex"])

    # Unwrap AES key
    unseal_box = nacl.public.SealedBox(validator_private_key)
    aes_key = unseal_box.decrypt(wrapped_key)

    # Decrypt AES-256-GCM payload
    aesgcm = AESGCM(aes_key)
    payload_bytes = aesgcm.decrypt(nonce, ciphertext, None)

    payload = json.loads(payload_bytes.decode("utf-8"))
    pcap_bytes = base64.b64decode(payload["pcap"].encode("ascii"))
    org_secret_hex = payload["org_secret"]
    onchain_case_id = payload.get("onchain_case_id")

    return pcap_bytes, org_secret_hex, onchain_case_id


# ---------------------------------------------------------------------------
# Storage Encryption at Rest
# ---------------------------------------------------------------------------

class StorageKeyError(ValueError):
    """Raised when CASE_STORAGE_KEY_HEX is missing, malformed, or wrong size."""
    pass


class StorageDecryptionError(RuntimeError):
    """Raised when decryption of stored PCAP fails."""
    pass


class StorageEncryptionError(RuntimeError):
    """Raised when encryption of stored PCAP fails."""
    pass


VALID_PCAP_MAGICS = [
    b"\xa1\xb2\xc3\xd4",  # Classic PCAP big-endian
    b"\xd4\xc3\xb2\xa1",  # Classic PCAP little-endian
    b"\xa1\xb2\x3c\x4d",  # Nanosecond PCAP big-endian
    b"\x4d\x3c\xb2\xa1",  # Nanosecond PCAP little-endian
    b"\x0a\x0d\x0d\x0a",  # PCAP-NG Section Header
]


def get_storage_at_rest_key() -> bytes:
    """
    Retrieves and validates the explicitly configured 32-byte AES key for data-at-rest encryption.
    Fails closed if missing, malformed, or wrong size.
    """
    key_hex = os.environ.get("CASE_STORAGE_KEY_HEX")
    if not key_hex or not key_hex.strip():
        raise StorageKeyError(
            "CASE_STORAGE_KEY_HEX is required for PCAP storage at rest but not configured."
        )
    key_str = key_hex.strip()
    if len(key_str) != 64:
        raise StorageKeyError(
            f"CASE_STORAGE_KEY_HEX must be exactly 64 hex characters (32 bytes), got {len(key_str)}"
        )
    try:
        key_bytes = bytes.fromhex(key_str)
    except ValueError as e:
        raise StorageKeyError(f"CASE_STORAGE_KEY_HEX is malformed hex: {e}") from e
    if len(key_bytes) != 32:
        raise StorageKeyError(f"CASE_STORAGE_KEY_HEX must decode to 32 bytes, got {len(key_bytes)}")
    return key_bytes


def encrypt_at_rest(data: bytes, key: Optional[bytes] = None) -> bytes:
    """
    Encrypts binary data with AES-256-GCM for storage at rest.
    Fails closed on any error.
    """
    if key is None:
        key = get_storage_at_rest_key()
    elif len(key) != 32:
        raise StorageKeyError(f"Storage key must be exactly 32 bytes, got {len(key)}")
    try:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        # Magic prefix 0x534D5345 ('SMSE') + nonce (12 bytes) + ciphertext
        return b"SMSE" + nonce + ciphertext
    except Exception as exc:
        if isinstance(exc, StorageKeyError):
            raise
        raise StorageEncryptionError(f"AES-256-GCM encryption failed: {exc}") from exc


def decrypt_at_rest(encrypted_data: bytes, key: Optional[bytes] = None) -> bytes:
    """
    Decrypts binary data stored at rest.
    If file starts with SMSE magic, it MUST be successfully decrypted with AES-256-GCM.
    Decryption failure raises StorageDecryptionError. Never returns encrypted bytes.
    If file does not start with SMSE magic, it is treated as legacy plaintext ONLY IF
    it starts with a valid PCAP magic number; otherwise raises StorageDecryptionError.
    """
    if encrypted_data.startswith(b"SMSE"):
        if len(encrypted_data) < 32:  # 4 magic + 12 nonce + 16 min tag
            raise StorageDecryptionError("Corrupted encrypted file: payload shorter than minimum header and tag")
        if key is None:
            key = get_storage_at_rest_key()
        elif len(key) != 32:
            raise StorageKeyError(f"Storage key must be exactly 32 bytes, got {len(key)}")
        nonce = encrypted_data[4:16]
        ciphertext = encrypted_data[16:]
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise StorageDecryptionError(f"Failed to decrypt encrypted PCAP at rest: {exc}") from exc

    # Legacy plaintext check: only allowed if content begins with valid PCAP magic
    if any(encrypted_data.startswith(m) for m in VALID_PCAP_MAGICS):
        return encrypted_data

    raise StorageDecryptionError("Unrecognized file format: neither SMSE encrypted nor valid legacy PCAP")


# ---------------------------------------------------------------------------
# Strict Mode Pinning Verification
# ---------------------------------------------------------------------------

class StrictModeError(RuntimeError):
    """Raised when strict pinning verification fails prior to commit."""
    pass


def parse_and_validate_engine_digest(env_engine_digest: Optional[str]) -> str:
    """
    Parses and validates ENGINE_IMAGE_DIGEST string.
    Supports formats: '0x<64-hex>', 'sha256:<64-hex>', or '<64-hex>'.
    Returns lowercase 64-hex string.
    Raises StrictModeError if missing, empty, malformed, or incorrect length.

    LIMITATION / ASSUMPTION DOCUMENTATION:
    Checking an environment-provided digest (ENGINE_IMAGE_DIGEST) validates
    administrative configuration claim alignment against the pinned on-chain engineHash.
    It does not cryptographically or independently prove which container image or binary
    actually ran inside the host runtime (such proof would require verifiable execution,
    such as TPM-based remote attestation or cryptographic execution enclaves).
    """
    if not env_engine_digest or not env_engine_digest.strip():
        raise StrictModeError(
            "Strict mode violation: ENGINE_IMAGE_DIGEST is missing or empty. "
            "In strict validator mode, ENGINE_IMAGE_DIGEST must be explicitly set and match the pinned on-chain engineHash."
        )
    clean = env_engine_digest.strip().lower()
    if clean.startswith("sha256:"):
        clean = clean[7:]
    elif clean.startswith("0x"):
        clean = clean[2:]

    if len(clean) != 64:
        raise StrictModeError(
            f"Strict mode violation: ENGINE_IMAGE_DIGEST is malformed. Expected 64 hex characters (32 bytes), got {len(clean)}."
        )
    try:
        bytes.fromhex(clean)
    except ValueError as e:
        raise StrictModeError(
            f"Strict mode violation: ENGINE_IMAGE_DIGEST is not valid hexadecimal: {e}."
        ) from e
    return clean
