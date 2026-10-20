"""File storage operations for SecureMailScope cases (Prompt 6.1)."""
import hashlib
import json
import os
from pathlib import Path
from typing import Any, List, Optional, Tuple
from fastapi import HTTPException, UploadFile, status

import backend.config as config

VALID_PCAP_MAGICS = [
    b"\xa1\xb2\xc3\xd4",  # Classic PCAP big-endian
    b"\xd4\xc3\xb2\xa1",  # Classic PCAP little-endian
    b"\xa1\xb2\x3c\x4d",  # Nanosecond PCAP big-endian
    b"\x4d\x3c\xb2\xa1",  # Nanosecond PCAP little-endian
    b"\x0a\x0d\x0d\x0a",  # PCAP-NG Section Header
]


def get_case_dir(case_id: str) -> Path:
    """Get path to case directory, creating it with mode 0700 if necessary."""
    case_dir = config.CASES_DIR / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(case_dir, 0o700)
    except Exception:
        pass
    return case_dir


async def stream_and_validate_pcap(
    upload_file: UploadFile,
    case_id: str,
    max_size: Optional[int] = None,
) -> Tuple[str, Path, int]:
    """
    Streams uploaded file to data/cases/<caseId>/pcap.bin while computing SHA-256.
    Enforces PCAP magic number check and maximum size limit.
    """
    effective_max = max_size if max_size is not None else config.MAX_UPLOAD_SIZE
    case_dir = get_case_dir(case_id)
    pcap_path = case_dir / "pcap.bin"

    sha256_hasher = hashlib.sha256()
    total_bytes = 0
    header_checked = False
    chunk_size = 65536
    error_to_raise: Optional[HTTPException] = None

    with open(pcap_path, "wb") as f:
        while True:
            chunk = await upload_file.read(chunk_size)
            if not chunk:
                break

            total_bytes += len(chunk)
            if total_bytes > effective_max:
                error_to_raise = HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"Upload exceeds maximum allowable size of {effective_max} bytes",
                )
                break

            # Check magic number on initial chunk
            if not header_checked:
                if len(chunk) < 4:
                    error_to_raise = HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="File too small to be a valid PCAP capture",
                    )
                    break
                magic = chunk[:4]
                if magic not in VALID_PCAP_MAGICS:
                    error_to_raise = HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid PCAP magic number: {magic.hex()}",
                    )
                    break
                header_checked = True

            sha256_hasher.update(chunk)
            f.write(chunk)

    if error_to_raise:
        if pcap_path.exists():
            pcap_path.unlink(missing_ok=True)
        try:
            case_dir.rmdir()
        except Exception:
            pass
        raise error_to_raise

    if total_bytes == 0:
        if pcap_path.exists():
            pcap_path.unlink(missing_ok=True)
        try:
            case_dir.rmdir()
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty",
        )

    # Encrypt pcap.bin at rest per Prompt T3.1 (fails closed)
    try:
        from validator.crypto import encrypt_at_rest
        plaintext_data = pcap_path.read_bytes()
        encrypted_bytes = encrypt_at_rest(plaintext_data)
        pcap_path.write_bytes(encrypted_bytes)
    except Exception as exc:
        if pcap_path.exists():
            pcap_path.unlink(missing_ok=True)
        try:
            for child in case_dir.iterdir():
                child.unlink(missing_ok=True)
            case_dir.rmdir()
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PCAP-at-rest encryption failed: {exc}",
        ) from exc

    try:
        os.chmod(pcap_path, 0o600)
    except Exception:
        pass

    return sha256_hasher.hexdigest(), pcap_path, total_bytes


def read_case_pcap(case_id: str) -> bytes:
    """Read case pcap, decrypting transparently if encrypted at rest (Prompt T3.1). Fails closed on error."""
    case_dir = get_case_dir(case_id)
    pcap_path = case_dir / "pcap.bin"
    if not pcap_path.exists():
        raise FileNotFoundError(f"pcap.bin not found for case {case_id}")
    raw_data = pcap_path.read_bytes()
    from validator.crypto import decrypt_at_rest
    return decrypt_at_rest(raw_data)


def read_case_json(case_id: str, filename: str) -> Optional[Any]:
    """Read canonical JSON file from case directory on disk."""
    case_dir = get_case_dir(case_id)
    file_path = case_dir / filename
    if not file_path.exists():
        return None
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_case_json(case_id: str, filename: str, data: Any) -> Path:
    """Write JSON data to case directory on disk."""
    case_dir = get_case_dir(case_id)
    file_path = case_dir / filename
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return file_path
