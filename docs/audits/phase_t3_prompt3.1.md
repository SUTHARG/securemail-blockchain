# Phase T3 Prompt 3.1 Audit: Encrypted Validator Delivery & Storage At Rest

**Date:** 2026-10-13  
**Status:** PASS  
**Scope:** Tier 3 - Prompt T3.1 (Encrypted Validator Delivery)

---

## 1. Specification Compliance

| Requirement | Status | Verification & Code Locations |
| :--- | :---: | :--- |
| **PyNaCl SealedBox & AES-256-GCM Envelope Encryption** | **PASS** | `validator/crypto.py` (`encrypt_validator_bundle`, `decrypt_validator_bundle`). Generates fresh random AES-256 key per bundle, encrypts payload via AES-256-GCM (12-byte nonce), unseals via recipient's Curve25519 public key. |
| **Validator Curve25519 Key Generation** | **PASS** | `validator/keygen.py` (`generate_validator_keypair`, `load_validator_private_key`, `load_validator_public_key`). Private key persisted with `mode 0600` strictly to `validator_state/validator_<id>.key`. |
| **Public Key Registration with Backend** | **PASS** | `backend/database.py` (`validator_keys` table, `register_validator_key`, `get_validator_key`), `backend/app.py` (`POST /validators/{id}/key`, `GET /validators/{id}/key`), and CLI `python -m validator.keygen --register <URL>`. |
| **Storage at Rest for `pcap.bin`** | **PASS** | `backend/storage.py` (`stream_and_validate_pcap`, `read_case_pcap`), `validator/crypto.py` (`encrypt_at_rest`, `decrypt_at_rest`). Encrypted with AES-256-GCM using `CASE_STORAGE_KEY_HEX` or derived from `ORG_SECRET_HEX` with magic prefix `SMSE`. |
| **Encrypted Bundle Distribution** | **PASS** | `backend/app.py` (`distribute_case`). When validator registered public keys exist, generates `bundle.enc` per recipient, removing plaintext artifacts from inboxes. |
| **Validator Service Decryption & Temp Directory (mode 0700)** | **PASS** | `validator/service.py` (`find_pending_bundles`, `process_bundle`). Decrypts `bundle.enc` into temporary directory mode `0700` (`val_sec_*`). Deleted recursively in `finally` upon both success and failure. Plaintext PCAP is never written to permanent disk. |

---

## 2. Test Verification

| Test Suite / Objective | Status | Result |
| :--- | :---: | :--- |
| `validator/tests/test_encrypted_delivery.py` | **PASS** | 9/9 tests passed in 2.28s. |
| - `test_wrong_validator_key_fails` | **PASS** | Unsealing with mismatched Curve25519 private key raises `CryptoError` / `ValueError`. |
| - `test_tampered_ciphertext_fails` | **PASS** | Tampering ciphertext, nonce, or wrapped key raises `InvalidTag` / `CryptoError`. |
| - `test_plaintext_never_appears_outside_temp_dir` | **PASS** | Plaintext PCAP never exists in validator inbox or permanent storage outside temporary directory. |
| - `test_temp_files_removed_after_success_and_failure` | **PASS** | Temp directory mode 0700 deleted in `finally` block after both normal completion and simulated error. |
| - `test_storage_at_rest_roundtrip` | **PASS** | Encryption with `encrypt_at_rest` and unsealing with `decrypt_at_rest` is byte-identical. |
| - `test_backend_key_registration_and_distribution` | **PASS** | API registration, upload with at-rest encryption, distribution with `bundle.enc`, and recipient decryption. |
| `backend/tests/` Full Regression Suite | **PASS** | 33/33 tests passed in 58.04s. |

---

## 3. Files Created or Modified
- `validator/keygen.py` (Curve25519 keypair generation, permissions 0600, CLI with `--register`)
- `validator/crypto.py` (SealedBox AES-256-GCM envelope encryption and storage at rest encryption)
- `validator/service.py` (Encrypted bundle detection, secure mode 0700 temp execution and cleanup)
- `validator/tests/__init__.py`
- `validator/tests/test_encrypted_delivery.py` (9 unit tests for encrypted delivery)
- `backend/database.py` (`validator_keys` schema, register and query helper functions)
- `backend/app.py` (`/validators/{id}/key` endpoints, encrypted distribution, verifier at-rest decryption)
- `backend/storage.py` (At-rest PCAP encryption and `read_case_pcap` helper)
- `backend/runner.py` (At-rest decryption into mode 0700 temp dir for analysis engine run)
- `backend/tests/test_api.py` (Updated `test_upload_valid_pcap` to assert at-rest encryption)
- `docs/audits/phase_t3_prompt3.1.md`
