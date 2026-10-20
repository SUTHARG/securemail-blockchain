"""Deterministic session feature extraction for advisory anomaly detection (Tier 2 / Prompt T2.4).

All features are strictly integers or one-hot indicators.
No floating point numbers or floats derived from timestamps.
"""
from typing import Dict, List, Optional, Any, Tuple
from engine.smscope.models import SessionRecord

# Fixed mapping of TLS versions to integers
TLS_VERSION_MAP: Dict[str, int] = {
    "SSL 2.0": 1,
    "SSL 3.0": 2,
    "TLS 1.0": 3,
    "TLS 1.1": 4,
    "TLS 1.2": 5,
    "TLS 1.3": 6,
}


def bucket_value(val: int, bucket_size: int) -> int:
    """Bucket integer value."""
    return val // bucket_size


def extract_session_features(
    session: SessionRecord,
    baseline_ja3_counts: Optional[Dict[str, int]] = None,
    baseline_server_certs: Optional[Dict[str, str]] = None,
) -> Dict[str, int]:
    """
    Extract discrete integer feature dictionary for a SessionRecord:
    1. tls_version: integer code (0=none, 1=SSL2, 2=SSL3, 3=TLS1.0, 4=TLS1.1, 5=TLS1.2, 6=TLS1.3)
    2. cipher_suite_code: integer cipher ID (0 if None)
    3. ja3_rarity_bucket: frequency count of JA3 in baseline (bucketed: 0=unseen, 1=rare 1-5, 2=common 6-20, 3=frequent >20)
    4. cert_differs_from_baseline: 1 if leaf cert differs from baseline for this server, else 0
    5. handshake_size_bucket: total client/server bytes bucketed by 256 bytes
    6. resumed_flag: 1 if resumed, else 0
    7. starttls_offered: 1 if offered, else 0
    8. starttls_used: 1 if outcome was succeeded, else 0
    """
    # Support both SessionRecord objects and dicts from sessions.json
    if isinstance(session, dict):
        tls = session.get("tls")
        certs = session.get("certificates", [])
        server_endpoint = str(session.get("serverEndpoint", ""))
        stream = session.get("stream", {})
        client_b = stream.get("clientByteCount", 0) if isinstance(stream, dict) else 0
        server_b = stream.get("serverByteCount", 0) if isinstance(stream, dict) else 0
        st = session.get("starttls", {})
        starttls_offered_val = bool(st.get("offered")) if isinstance(st, dict) else False
        starttls_outcome = st.get("outcome") if isinstance(st, dict) else ""
        transport_mode = str(session.get("transportMode", ""))
        
        # TLS Version
        tls_ver_code = 0
        if tls and isinstance(tls, dict) and tls.get("version"):
            tls_ver_code = TLS_VERSION_MAP.get(str(tls.get("version")), 0)

        # Cipher Suite Code
        cipher_code = 0
        if tls and isinstance(tls, dict) and tls.get("cipherSuiteCode") is not None:
            try:
                cipher_code = int(tls["cipherSuiteCode"])
            except (ValueError, TypeError):
                cipher_code = 0

        # JA3 Rarity Bucket
        ja3_bucket = 0
        ja3_val = tls.get("ja3") if (tls and isinstance(tls, dict)) else None
        if ja3_val:
            if baseline_ja3_counts is not None:
                count = baseline_ja3_counts.get(ja3_val, 0)
                if count == 0:
                    ja3_bucket = 0
                elif count <= 5:
                    ja3_bucket = 1
                elif count <= 20:
                    ja3_bucket = 2
                else:
                    ja3_bucket = 3
            else:
                ja3_bucket = 2

        # Certificate Differs from Baseline
        cert_differs = 0
        if certs and len(certs) > 0 and baseline_server_certs is not None:
            first_cert = certs[0]
            leaf_fp = first_cert.get("sha256") if isinstance(first_cert, dict) else getattr(first_cert, "sha256", None)
            baseline_fp = baseline_server_certs.get(server_endpoint)
            if baseline_fp is not None and leaf_fp != baseline_fp:
                cert_differs = 1

        client_tls_offset = session.get("clientTlsStartOffset")
        server_tls_offset = session.get("serverTlsStartOffset")
        if client_tls_offset is not None:
            client_b = max(0, client_b - int(client_tls_offset))
        if server_tls_offset is not None:
            server_b = max(0, server_b - int(server_tls_offset))
        handshake_size_bucket = (client_b + server_b) // 256
        resumed_flag = 1 if (tls and isinstance(tls, dict) and tls.get("resumed")) else 0
        starttls_offered = 1 if starttls_offered_val else 0
        starttls_used = 1 if (starttls_outcome == "succeeded" or transport_mode == "starttls") else 0
    else:
        tls = session.tls
        certs = session.certificates
        server_endpoint = session.serverEndpoint

        # 1. TLS Version
        tls_ver_code = 0
        if tls and tls.version:
            tls_ver_code = TLS_VERSION_MAP.get(tls.version, 0)

        # 2. Cipher Suite Code
        cipher_code = 0
        if tls and tls.cipherSuiteCode is not None:
            cipher_code = int(tls.cipherSuiteCode)

        # 3. JA3 Rarity Bucket
        ja3_bucket = 0
        if tls and tls.ja3:
            if baseline_ja3_counts is not None:
                count = baseline_ja3_counts.get(tls.ja3, 0)
                if count == 0:
                    ja3_bucket = 0  # Unseen
                elif count <= 5:
                    ja3_bucket = 1  # Rare
                elif count <= 20:
                    ja3_bucket = 2  # Common
                else:
                    ja3_bucket = 3  # Frequent
            else:
                ja3_bucket = 2  # Default neutral when building baseline

        # 4. Certificate Differs from Baseline
        cert_differs = 0
        if certs and len(certs) > 0 and baseline_server_certs is not None:
            leaf_fp = certs[0].sha256
            baseline_fp = baseline_server_certs.get(server_endpoint)
            if baseline_fp is not None and leaf_fp != baseline_fp:
                cert_differs = 1

        # 5. Handshake Byte Size Bucket (bucket size = 256)
        client_b = len(session.stream.clientBytes) if session.stream else 0
        server_b = len(session.stream.serverBytes) if session.stream else 0
        if session.clientTlsStartOffset is not None:
            client_b = max(0, client_b - session.clientTlsStartOffset)
        if session.serverTlsStartOffset is not None:
            server_b = max(0, server_b - session.serverTlsStartOffset)
        handshake_size_bucket = (client_b + server_b) // 256

        # 6. Resumed Flag
        resumed_flag = 1 if (tls and tls.resumed) else 0

        # 7. STARTTLS Offered Flag
        starttls_offered = 1 if session.starttls.offered else 0

        # 8. STARTTLS Used Flag
        starttls_used = 1 if (session.starttls.outcome == "succeeded" or session.transportMode == "starttls") else 0

    return {
        "tls_version": tls_ver_code,
        "cipher_suite_code": cipher_code,
        "ja3_rarity_bucket": ja3_bucket,
        "cert_differs_from_baseline": cert_differs,
        "handshake_size_bucket": handshake_size_bucket,
        "resumed_flag": resumed_flag,
        "starttls_offered": starttls_offered,
        "starttls_used": starttls_used,
    }


FEATURE_NAMES = [
    "tls_version",
    "cipher_suite_code",
    "ja3_rarity_bucket",
    "cert_differs_from_baseline",
    "handshake_size_bucket",
    "resumed_flag",
    "starttls_offered",
    "starttls_used",
]


def session_to_feature_vector(
    session: SessionRecord,
    baseline_ja3_counts: Optional[Dict[str, int]] = None,
    baseline_server_certs: Optional[Dict[str, str]] = None,
) -> List[int]:
    """Convert SessionRecord into an integer feature vector according to FEATURE_NAMES."""
    feat_dict = extract_session_features(session, baseline_ja3_counts, baseline_server_certs)
    return [feat_dict[k] for k in FEATURE_NAMES]
