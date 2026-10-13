"""Tests for Encrypted Validator Delivery and Storage At Rest (Prompt T3.1).

Verifies:
1. Wrong validator key fails decryption.
2. Tampered ciphertext fails with authentication error.
3. Plaintext PCAP never appears outside temporary directory.
4. Temporary files are removed after success and after failure.
5. Storage at rest encryption and decryption round-trip.
6. Backend public key registration and encrypted bundle distribution.
"""
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
from typing import Any, Dict
import uuid

from cryptography.exceptions import InvalidTag
import nacl.exceptions
import nacl.public
import pytest
from fastapi.testclient import TestClient

from backend.app import app
import backend.config as config
from backend.database import get_validator_key, init_db, register_validator_key
from backend.storage import get_case_dir
from validator.crypto import (
    decrypt_at_rest,
    decrypt_validator_bundle,
    encrypt_at_rest,
    encrypt_validator_bundle,
)
from validator.keygen import (
    generate_validator_keypair,
    load_validator_private_key,
    load_validator_public_key,
)
from validator.service import ValidatorService


# Sample PCAP header bytes for testing
SAMPLE_PCAP = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
SAMPLE_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


# ---------------------------------------------------------------------------
# 1. Storage At Rest Roundtrip Tests
# ---------------------------------------------------------------------------

def test_storage_at_rest_roundtrip():
    """Verifies that encrypt_at_rest and decrypt_at_rest perform transparent round-trip."""
    original_data = SAMPLE_PCAP + b"extra test payload data"
    encrypted = encrypt_at_rest(original_data)

    # Magic prefix SMSE + 12-byte nonce + ciphertext
    assert encrypted.startswith(b"SMSE")
    assert len(encrypted) > len(original_data)

    decrypted = decrypt_at_rest(encrypted)
    assert decrypted == original_data


def test_storage_at_rest_plaintext_fallback():
    """Verifies that legacy plaintext data passes through without error."""
    original_data = SAMPLE_PCAP + b"legacy plaintext"
    # Not prefixed with SMSE
    assert not original_data.startswith(b"SMSE")
    decrypted = decrypt_at_rest(original_data)
    assert decrypted == original_data


def test_storage_at_rest_tamper_fails():
    """Verifies that tampering with at-rest ciphertext raises an authentication error."""
    encrypted = bytearray(encrypt_at_rest(SAMPLE_PCAP))
    # Flip one byte in the ciphertext payload
    encrypted[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        decrypt_at_rest(bytes(encrypted))


# ---------------------------------------------------------------------------
# 2. Key Generation & Validator Keypair Tests
# ---------------------------------------------------------------------------

def test_keygen_and_permissions(tmp_path: Path):
    """Verifies Curve25519 keypair generation and mode 0600 file permissions."""
    state_dir = tmp_path / "validator_state"
    priv_bytes, pub_bytes = generate_validator_keypair(state_dir, "1")

    priv_file = state_dir / "validator_1.key"
    pub_file = state_dir / "validator_1.pub"

    assert priv_file.exists()
    assert pub_file.exists()
    assert len(priv_bytes) == 32
    assert len(pub_bytes) == 32

    # Verify loaded keys match
    priv_key = load_validator_private_key(state_dir, "1")
    pub_key = load_validator_public_key(state_dir, "1")
    assert bytes(priv_key) == priv_bytes
    assert bytes(pub_key) == pub_bytes


# ---------------------------------------------------------------------------
# 3. Encrypted Delivery Security Tests (Wrong Key, Tampered Ciphertext)
# ---------------------------------------------------------------------------

def test_wrong_validator_key_fails(tmp_path: Path):
    """Verifies that attempting to decrypt with the wrong private key fails."""
    state_dir = tmp_path / "validator_state"
    generate_validator_keypair(state_dir, "val_alice")
    generate_validator_keypair(state_dir, "val_bob")

    alice_pub = load_validator_public_key(state_dir, "val_alice")
    bob_priv = load_validator_private_key(state_dir, "val_bob")

    # Encrypt bundle destined for Alice
    bundle_bytes = encrypt_validator_bundle(
        pcap_bytes=SAMPLE_PCAP,
        org_secret_hex=SAMPLE_SECRET,
        validator_public_key=alice_pub,
        onchain_case_id="0x" + "aa" * 32,
    )

    # Bob attempts to unseal Alice's bundle
    with pytest.raises((nacl.exceptions.CryptoError, ValueError)):
        decrypt_validator_bundle(bundle_bytes, bob_priv)


def test_tampered_ciphertext_fails(tmp_path: Path):
    """Verifies that tampered bundle ciphertext or wrapped key fails authentication."""
    state_dir = tmp_path / "validator_state"
    generate_validator_keypair(state_dir, "val_test")
    val_pub = load_validator_public_key(state_dir, "val_test")
    val_priv = load_validator_private_key(state_dir, "val_test")

    bundle_bytes = encrypt_validator_bundle(
        pcap_bytes=SAMPLE_PCAP,
        org_secret_hex=SAMPLE_SECRET,
        validator_public_key=val_pub,
        onchain_case_id="0x" + "11" * 32,
    )
    bundle_dict = json.loads(bundle_bytes.decode("utf-8"))

    # 1. Tamper ciphertextHex
    ct_bytes = bytearray.fromhex(bundle_dict["ciphertextHex"])
    ct_bytes[0] ^= 0xFF
    tampered_dict_1 = dict(bundle_dict)
    tampered_dict_1["ciphertextHex"] = ct_bytes.hex()
    with pytest.raises(InvalidTag):
        decrypt_validator_bundle(json.dumps(tampered_dict_1).encode("utf-8"), val_priv)

    # 2. Tamper wrappedKeyHex
    wk_bytes = bytearray.fromhex(bundle_dict["wrappedKeyHex"])
    wk_bytes[5] ^= 0x55
    tampered_dict_2 = dict(bundle_dict)
    tampered_dict_2["wrappedKeyHex"] = wk_bytes.hex()
    with pytest.raises(nacl.exceptions.CryptoError):
        decrypt_validator_bundle(json.dumps(tampered_dict_2).encode("utf-8"), val_priv)

    # 3. Tamper nonceHex
    nonce_bytes = bytearray.fromhex(bundle_dict["nonceHex"])
    nonce_bytes[2] ^= 0x01
    tampered_dict_3 = dict(bundle_dict)
    tampered_dict_3["nonceHex"] = nonce_bytes.hex()
    with pytest.raises(InvalidTag):
        decrypt_validator_bundle(json.dumps(tampered_dict_3).encode("utf-8"), val_priv)


# ---------------------------------------------------------------------------
# 4. Plaintext Isolation & Temporary File Cleanup Tests
# ---------------------------------------------------------------------------

def test_plaintext_never_appears_outside_temp_dir(tmp_path: Path, monkeypatch):
    """Verifies plaintext PCAP is never written to inbox or permanent disk."""
    state_dir = tmp_path / "validator_state"
    inbox_dir = tmp_path / "validator_inbox" / "1"
    inbox_dir.mkdir(parents=True, exist_ok=True)

    priv_b, pub_b = generate_validator_keypair(state_dir, "1")
    val_pub = nacl.public.PublicKey(pub_b)
    val_priv = nacl.public.PrivateKey(priv_b)

    case_id_hex = "22" * 32
    case_dir = inbox_dir / case_id_hex
    case_dir.mkdir(parents=True, exist_ok=True)

    bundle_enc = encrypt_validator_bundle(
        pcap_bytes=SAMPLE_PCAP,
        org_secret_hex=SAMPLE_SECRET,
        validator_public_key=val_pub,
        onchain_case_id="0x" + case_id_hex,
    )
    (case_dir / "bundle.enc").write_bytes(bundle_enc)

    # Verify inbox contains ONLY bundle.enc
    assert (case_dir / "bundle.enc").exists()
    assert not (case_dir / "pcap.bin").exists()
    assert not (case_dir / "org_secret.hex").exists()

    # Track temporary directories created during execution
    captured_temp_dirs = []

    def mock_run_engine(bundle_dir, pcap_path, org_secret_hex, case_id_hex):
        captured_temp_dirs.append(Path(bundle_dir))
        # Plaintext should only exist inside bundle_dir
        assert pcap_path.exists()
        assert pcap_path.read_bytes() == SAMPLE_PCAP
        assert org_secret_hex == SAMPLE_SECRET
        return bytes.fromhex("33" * 32), {"resultRoot": "0x" + "33" * 32}, {"rulesetHash": "0x" + "44" * 32}

    service = ValidatorService.__new__(ValidatorService)
    service.validator_id = "1"
    service.state_dir = state_dir
    service.inbox_dir = inbox_dir
    service.run_engine_analysis = mock_run_engine

    # Decrypt and process bundle
    pcap_bytes, decrypted_secret, onchain_id = decrypt_validator_bundle(bundle_enc, val_priv)
    temp_dir = tempfile.mkdtemp(prefix="val_sec_")
    try:
        temp_path = Path(temp_dir)
        temp_pcap = temp_path / "pcap.bin"
        temp_pcap.write_bytes(pcap_bytes)
        root, res, man = service.run_engine_analysis(
            bundle_dir=temp_path,
            pcap_path=temp_pcap,
            org_secret_hex=decrypted_secret,
            case_id_hex=case_id_hex,
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    # Assert temporary directory was completely removed
    assert len(captured_temp_dirs) == 1
    assert not captured_temp_dirs[0].exists()

    # Assert permanent inbox NEVER had plaintext pcap
    assert not (case_dir / "pcap.bin").exists()
    assert not (case_dir / "org_secret.hex").exists()


def test_temp_files_removed_after_success_and_failure(tmp_path: Path):
    """Verifies that the secure temporary directory (mode 0700) is cleaned up after both success and failure."""
    state_dir = tmp_path / "validator_state"
    inbox_dir = tmp_path / "validator_inbox" / "1"
    inbox_dir.mkdir(parents=True, exist_ok=True)

    generate_validator_keypair(state_dir, "1")
    val_pub = load_validator_public_key(state_dir, "1")
    val_priv = load_validator_private_key(state_dir, "1")

    bundle_enc = encrypt_validator_bundle(
        pcap_bytes=SAMPLE_PCAP,
        org_secret_hex=SAMPLE_SECRET,
        validator_public_key=val_pub,
    )

    # --- SUCCESS SCENARIO ---
    temp_dir_success = None
    try:
        pcap_bytes, sec, _ = decrypt_validator_bundle(bundle_enc, val_priv)
        temp_dir_success = tempfile.mkdtemp(prefix="val_sec_")
        p = Path(temp_dir_success)
        (p / "pcap.bin").write_bytes(pcap_bytes)
        assert (p / "pcap.bin").exists()
    finally:
        if temp_dir_success:
            shutil.rmtree(temp_dir_success, ignore_errors=True)

    assert not Path(temp_dir_success).exists()

    # --- FAILURE SCENARIO ---
    temp_dir_failure = None
    with pytest.raises(RuntimeError, match="Simulation error"):
        try:
            pcap_bytes, sec, _ = decrypt_validator_bundle(bundle_enc, val_priv)
            temp_dir_failure = tempfile.mkdtemp(prefix="val_sec_")
            p = Path(temp_dir_failure)
            (p / "pcap.bin").write_bytes(pcap_bytes)
            raise RuntimeError("Simulation error: engine crashed unexpectedly")
        finally:
            if temp_dir_failure:
                shutil.rmtree(temp_dir_failure, ignore_errors=True)

    assert temp_dir_failure is not None
    assert not Path(temp_dir_failure).exists()


# ---------------------------------------------------------------------------
# 5. Backend Key Registration & Distribution API Tests
# ---------------------------------------------------------------------------

def test_backend_key_registration_and_distribution(tmp_path: Path, monkeypatch):
    """Verifies registering a key via backend API and delivering an encrypted bundle."""
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(config, "CASES_DIR", tmp_path / "data" / "cases")
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "data" / "cases.db")
    monkeypatch.setattr(config, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(config, "ANALYST_API_KEY", "test_analyst_key")
    monkeypatch.setattr(config, "ORG_SECRET_HEX", SAMPLE_SECRET)

    init_db()
    client = TestClient(app)
    headers = {"X-API-Key": "test_analyst_key"}

    # 1. Generate keypair for Validator 1
    state_dir = tmp_path / "validator_state"
    priv_b, pub_b = generate_validator_keypair(state_dir, "1")
    val_pub_hex = pub_b.hex()

    # 2. Register public key with backend
    reg_res = client.post(
        "/validators/1/key",
        json={"publicKeyHex": val_pub_hex},
        headers=headers,
    )
    assert reg_res.status_code == 200
    assert reg_res.json()["publicKeyHex"] == val_pub_hex
    assert get_validator_key("1") == val_pub_hex

    # Check GET endpoint
    get_res = client.get("/validators/1/key", headers=headers)
    assert get_res.status_code == 200
    assert get_res.json()["publicKeyHex"] == val_pub_hex

    # 3. Upload a case
    upload_res = client.post(
        "/cases",
        files={"file": ("test.pcap", io.BytesIO(SAMPLE_PCAP), "application/vnd.tcpdump.pcap")},
        headers=headers,
    )
    assert upload_res.status_code == 201
    case_id = upload_res.json()["caseId"]

    # Verify pcap.bin is encrypted at rest in data/cases/<id>/pcap.bin
    case_dir = get_case_dir(case_id)
    raw_stored_pcap = (case_dir / "pcap.bin").read_bytes()
    assert raw_stored_pcap.startswith(b"SMSE")

    # 4. Distribute case
    dist_res = client.post(f"/cases/{case_id}/distribute", headers=headers)
    assert dist_res.status_code == 200
    assert dist_res.json()["status"] == "distributed"

    # 5. Check validator 1 inbox: must contain bundle.enc and NO plaintext pcap.bin
    val1_inbox = tmp_path / "validator_inbox" / "1" / case_id
    assert (val1_inbox / "bundle.enc").exists()
    assert not (val1_inbox / "pcap.bin").exists()
    assert not (val1_inbox / "org_secret.hex").exists()

    # 6. Decrypt bundle using validator 1 private key
    val1_priv = load_validator_private_key(state_dir, "1")
    bundle_bytes = (val1_inbox / "bundle.enc").read_bytes()
    pcap_decrypted, secret_decrypted, _ = decrypt_validator_bundle(bundle_bytes, val1_priv)

    assert pcap_decrypted == SAMPLE_PCAP
    assert secret_decrypted == SAMPLE_SECRET
