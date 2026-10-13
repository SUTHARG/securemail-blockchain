"""TLS negotiation analysis: cipher suites, key exchange, resumption, and JA3/JA3S fingerprinting."""
import hashlib
from typing import Any, Dict, Iterable, List, Optional, Union

from engine.smscope.models import TlsInfo
from engine.smscope.tls.ciphers_generated import CIPHER_SUITES
from engine.smscope.tls.handshake import ClientHello, ServerHello, TlsHandshake

# RFC 8701 GREASE values
GREASE_VALUES = {
    0x0A0A,
    0x1A1A,
    0x2A2A,
    0x3A3A,
    0x4A4A,
    0x5A5A,
    0x6A6A,
    0x7A7A,
    0x8A8A,
    0x9A9A,
    0xAAAA,
    0xBABA,
    0xCACA,
    0xDADA,
    0xEAEA,
    0xFAFA,
}

TLS_VERSION_NAMES: Dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

TLS_VERSION_HEX: Dict[int, str] = {
    0x0300: "0x0300",
    0x0301: "0x0301",
    0x0302: "0x0302",
    0x0303: "0x0303",
    0x0304: "0x0304",
}


def filter_grease(values: Iterable[int]) -> List[int]:
    """Filters out RFC 8701 GREASE values from an iterable of integers."""
    return [v for v in values if v not in GREASE_VALUES]


def compute_ja3_string(client_hello: ClientHello) -> str:
    """
    Computes JA3 string: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    with values joined by dashes in decimal, and GREASE values removed.
    """
    ver = str(client_hello.legacy_version)
    ciphers = "-".join(str(c) for c in filter_grease(client_hello.cipher_suites))
    extensions = "-".join(str(e) for e in filter_grease(client_hello.extension_types))
    curves = "-".join(
        str(g) for g in filter_grease(client_hello.extensions.get("supported_groups", []))
    )
    point_formats = "-".join(
        str(p) for p in filter_grease(client_hello.extensions.get("ec_point_formats", []))
    )
    return f"{ver},{ciphers},{extensions},{curves},{point_formats}"


def compute_ja3(client_hello: Optional[ClientHello]) -> Optional[str]:
    """Computes MD5 hash of JA3 string, or None if client_hello is missing."""
    if client_hello is None:
        return None
    raw_str = compute_ja3_string(client_hello)
    return hashlib.md5(raw_str.encode("ascii")).hexdigest()


def compute_ja3s_string(server_hello: ServerHello) -> str:
    """
    Computes JA3S string: SSLVersion,Cipher,Extensions
    with values joined by dashes in decimal, and GREASE values removed.
    """
    ver = str(server_hello.version)
    cipher = "" if server_hello.cipher_suite in GREASE_VALUES else str(server_hello.cipher_suite)
    extensions = "-".join(str(e) for e in filter_grease(server_hello.extension_types))
    return f"{ver},{cipher},{extensions}"


def compute_ja3s(server_hello: Optional[ServerHello]) -> Optional[str]:
    """Computes MD5 hash of JA3S string, or None if server_hello is missing."""
    if server_hello is None:
        return None
    raw_str = compute_ja3s_string(server_hello)
    return hashlib.md5(raw_str.encode("ascii")).hexdigest()


def format_tls_version(version_code: Optional[int]) -> Optional[str]:
    """Returns human-readable TLS version string (e.g. 'TLS 1.2')."""
    if version_code is None:
        return None
    return TLS_VERSION_NAMES.get(version_code, f"0x{version_code:04x}")


def negotiate_tls(handshake: TlsHandshake) -> Optional[TlsInfo]:
    """
    Evaluates TLS handshake negotiation into a validated TlsInfo record.
    Returns None if no TLS handshake activity is present.
    """
    if handshake.client_hello is None and handshake.server_hello is None:
        return None

    ja3 = compute_ja3(handshake.client_hello)
    ja3s = compute_ja3s(handshake.server_hello)
    sni = handshake.sni

    if handshake.server_hello is None:
        return TlsInfo(
            version=None,
            cipherSuiteCode=None,
            cipherSuiteName=None,
            kxType=None,
            kxGroupOrDhBits=None,
            forwardSecrecy=None,
            resumed=False,
            ja3=ja3,
            ja3s=None,
            sni=sni,
            certObservable=False,
            certNotObservableReason="handshake_incomplete",
        )

    # Negotiated Version
    version_code = handshake.negotiated_version or handshake.server_hello.version
    version_name = format_tls_version(version_code)
    is_tls13 = (version_code == 0x0304)

    # Resumption
    if is_tls13:
        resumed = "pre_shared_key" in handshake.server_hello.extensions
    else:
        resumed = bool(
            handshake.client_hello
            and handshake.client_hello.session_id
            and handshake.server_hello.session_id == handshake.client_hello.session_id
            and len(handshake.certificates) == 0
        )

    # Certificate Observability
    if is_tls13:
        cert_observable = False
        cert_reason = "tls13"
    elif resumed:
        cert_observable = False
        cert_reason = "resumed"
    else:
        cert_observable = True
        cert_reason = None

    # Cipher Suite and Key Exchange Properties
    cipher_code = handshake.server_hello.cipher_suite
    cipher_entry = CIPHER_SUITES.get(cipher_code)

    if cipher_entry:
        cipher_name = cipher_entry["name"]
        kx_type = cipher_entry["kxType"]
        fs = cipher_entry["forwardSecrecy"]
    else:
        cipher_name = f"UNKNOWN_CIPHER_0x{cipher_code:04X}"
        kx_type = "tls13" if is_tls13 else "other"
        fs = True if is_tls13 else None

    # TLS 1.3 overrides
    if is_tls13:
        kx_type = "tls13"
        fs = True

    # kxGroupOrDhBits
    if is_tls13:
        kx_group_or_dh_bits: Union[int, str] = handshake.server_hello.extensions.get(
            "key_share", {}
        ).get("group", 0)
    elif handshake.server_key_exchange:
        ske = handshake.server_key_exchange
        if ske.param_type == "ec_diffie_hellman":
            kx_group_or_dh_bits = ske.named_curve if ske.named_curve is not None else 0
        elif ske.param_type == "diffie_hellman":
            kx_group_or_dh_bits = ske.dh_p_bits if ske.dh_p_bits is not None else 0
        else:
            kx_group_or_dh_bits = 0
    else:
        kx_group_or_dh_bits = 0

    return TlsInfo(
        version=version_name,
        cipherSuiteCode=cipher_code,
        cipherSuiteName=cipher_name,
        kxType=kx_type,
        kxGroupOrDhBits=kx_group_or_dh_bits,
        forwardSecrecy=fs,
        resumed=resumed,
        ja3=ja3,
        ja3s=ja3s,
        sni=sni,
        certObservable=cert_observable,
        certNotObservableReason=cert_reason,
    )
