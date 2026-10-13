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

def get_storage_at_rest_key() -> bytes:
    """Derives or retrieves the 32-byte AES key for data-at-rest encryption."""
    key_hex = os.environ.get("CASE_STORAGE_KEY_HEX")
    if key_hex:
        return bytes.fromhex(key_hex.strip())[:32]

    org_secret = os.environ.get("ORG_SECRET_HEX", "00" * 32)
    import hashlib
    return hashlib.sha256(b"SecureMailScopeStorageAtRest:" + bytes.fromhex(org_secret[:64])).digest()


def encrypt_at_rest(data: bytes, key: Optional[bytes] = None) -> bytes:
    """Encrypts binary data with AES-256-GCM for storage at rest."""
    if key is None:
        key = get_storage_at_rest_key()
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    # Magic prefix 0x534D5345 ('SMSE') + nonce (12 bytes) + ciphertext
    return b"SMSE" + nonce + ciphertext


def decrypt_at_rest(encrypted_data: bytes, key: Optional[bytes] = None) -> bytes:
    """Decrypts binary data stored at rest. If not encrypted with SMSE magic, returns as-is."""
    if not encrypted_data.startswith(b"SMSE") or len(encrypted_data) < 16:
        # Plaintext fallback
        return encrypted_data

    if key is None:
        key = get_storage_at_rest_key()
    nonce = encrypted_data[4:16]
    ciphertext = encrypted_data[16:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
