"""Cryptographic hashing functions for SecureMailScope."""
import hashlib
import hmac
from typing import Union, Sequence

from engine.smscope.results.canonical import canonical_json


def finding_id(rule_id: str, server_endpoint: str) -> str:
    """Compute findingId = SHA-256(ASCII('<ruleId>|<serverEndpoint>')) as lowercase hex."""
    msg = f"{rule_id}|{server_endpoint}".encode("ascii")
    return hashlib.sha256(msg).hexdigest()


def findings_digest(finding_ids: Sequence[Union[str, bytes]]) -> str:
    """Compute findingsDigest = SHA-256 of concatenated 32-byte findingIds sorted ascending as bytes."""
    raw_ids = []
    for fid in finding_ids:
        if isinstance(fid, str):
            b = bytes.fromhex(fid)
        elif isinstance(fid, bytes):
            b = fid
        else:
            raise TypeError(f"findingId must be hex str or bytes, got {type(fid)}")
        if len(b) != 32:
            raise ValueError(f"Each findingId must be 32 bytes, got {len(b)}")
        raw_ids.append(b)

    sorted_ids = sorted(raw_ids)
    concatenated = b"".join(sorted_ids)
    return hashlib.sha256(concatenated).hexdigest()


def host_id(org_secret: bytes, server_endpoint: str) -> bytes:
    """Compute hostId = HMAC-SHA-256(org_secret, ASCII(server_endpoint)); returns 32 bytes."""
    if not isinstance(org_secret, (bytes, bytearray)):
        raise TypeError(f"org_secret must be bytes, got {type(org_secret)}")
    msg = server_endpoint.encode("ascii")
    return hmac.new(org_secret, msg, hashlib.sha256).digest()


def host_id_hex(org_secret: bytes, server_endpoint: str) -> str:
    """Compute hostId as lowercase hex string."""
    return host_id(org_secret, server_endpoint).hex()


def finding_leaf(canonical_payload: Union[bytes, dict]) -> bytes:
    """Compute finding_leaf = SHA-256(0x00 + canonical_bytes); returns 32 bytes."""
    if isinstance(canonical_payload, dict):
        canonical_bytes = canonical_json(canonical_payload)
    elif isinstance(canonical_payload, (bytes, bytearray)):
        canonical_bytes = bytes(canonical_payload)
    else:
        raise TypeError(f"canonical_payload must be dict or bytes, got {type(canonical_payload)}")
    return hashlib.sha256(b"\x00" + canonical_bytes).digest()


def host_score_leaf(host_id_val: Union[str, bytes], findings_digest_val: Union[str, bytes], score: int) -> bytes:
    """Compute host_score_leaf = SHA-256(0x02 + host_id[32] + findings_digest[32] + score as 2-byte big-endian)."""
    if isinstance(host_id_val, str):
        h_bytes = bytes.fromhex(host_id_val)
    elif isinstance(host_id_val, (bytes, bytearray)):
        h_bytes = bytes(host_id_val)
    else:
        raise TypeError(f"host_id must be hex str or bytes, got {type(host_id_val)}")

    if len(h_bytes) != 32:
        raise ValueError(f"host_id must be 32 bytes, got {len(h_bytes)}")

    if isinstance(findings_digest_val, str):
        d_bytes = bytes.fromhex(findings_digest_val)
    elif isinstance(findings_digest_val, (bytes, bytearray)):
        d_bytes = bytes(findings_digest_val)
    else:
        raise TypeError(f"findings_digest must be hex str or bytes, got {type(findings_digest_val)}")

    if len(d_bytes) != 32:
        raise ValueError(f"findings_digest must be 32 bytes, got {len(d_bytes)}")

    if not isinstance(score, int) or isinstance(score, bool):
        raise TypeError(f"score must be an integer, got {score!r}")
    if score < 0 or score > 65535:
        raise ValueError(f"score must fit in 2-byte unsigned integer (0-65535), got {score}")

    score_bytes = score.to_bytes(2, byteorder="big")
    return hashlib.sha256(b"\x02" + h_bytes + d_bytes + score_bytes).digest()


def node(a: bytes, b: bytes) -> bytes:
    """Compute internal node hash = SHA-256(0x01 + min(a, b) + max(a, b))."""
    if len(a) != 32 or len(b) != 32:
        raise ValueError(f"Inputs a and b must both be 32 bytes, got {len(a)} and {len(b)}")
    min_val = min(a, b)
    max_val = max(a, b)
    return hashlib.sha256(b"\x01" + min_val + max_val).digest()
