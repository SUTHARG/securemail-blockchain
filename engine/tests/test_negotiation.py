"""Tests for TLS cipher table, key exchange, resumption, and JA3/JA3S fingerprinting."""
import hashlib
import json
from pathlib import Path
import pytest

from engine.smscope.ingest.reassembly import reassemble_pcap
from engine.smscope.protocols.smtp import track_session
from engine.smscope.tls.ciphers_generated import CIPHER_SUITES
from engine.smscope.tls.handshake import (
    ClientHello,
    ServerHello,
    ServerKeyExchange,
    TlsHandshake,
    parse_tls_handshake,
)
from engine.smscope.tls.negotiation import (
    GREASE_VALUES,
    compute_ja3,
    compute_ja3_string,
    compute_ja3s,
    compute_ja3s_string,
    filter_grease,
    format_tls_version,
    negotiate_tls,
)

CAPTURES_DIR = Path(__file__).resolve().parents[2] / "lab" / "captures"
TRUTH_DIR = Path(__file__).resolve().parents[2] / "eval" / "truth"


def test_filter_grease():
    """Verify that RFC 8701 GREASE values are completely removed."""
    raw = [0x0A0A, 49199, 0x1A1A, 49195, 0xFAFA, 156]
    filtered = filter_grease(raw)
    assert filtered == [49199, 49195, 156]

    # All GREASE values must be filtered
    for g in GREASE_VALUES:
        assert filter_grease([g, 100, g]) == [100]


def test_hand_constructed_ja3():
    """Verify JA3 string formatting and MD5 hash against reference test vector."""
    # Standard example:
    # SSLVersion: 771 (0x0303)
    # Ciphers: 49199, 49195, 156 (with GREASE 0x1a1a)
    # Extensions: 0, 10, 11, 43 (with GREASE 0x2a2a)
    # Curves: 29, 23 (with GREASE 0x3a3a)
    # PointFormats: 0
    ch = ClientHello(
        legacy_version=771,
        random=b"\x00" * 32,
        session_id=b"",
        cipher_suites=[0x1A1A, 49199, 49195, 156],
        compression_methods=b"\x00",
        extensions={
            "supported_groups": [0x3A3A, 29, 23],
            "ec_point_formats": [0],
        },
        extension_types=[0, 0x2A2A, 10, 11, 43],
    )

    expected_str = "771,49199-49195-156,0-10-11-43,29-23,0"
    actual_str = compute_ja3_string(ch)
    assert actual_str == expected_str

    expected_md5 = hashlib.md5(expected_str.encode("ascii")).hexdigest()
    assert compute_ja3(ch) == expected_md5


def test_hand_constructed_ja3s():
    """Verify JA3S string formatting and MD5 hash against reference test vector."""
    sh = ServerHello(
        version=771,
        random=b"\x00" * 32,
        session_id=b"",
        cipher_suite=49199,
        compression_method=0,
        extensions={},
        extension_types=[0x0A0A, 43, 51],
    )

    expected_str = "771,49199,43-51"
    actual_str = compute_ja3s_string(sh)
    assert actual_str == expected_str

    expected_md5 = hashlib.md5(expected_str.encode("ascii")).hexdigest()
    assert compute_ja3s(sh) == expected_md5


def test_forward_secrecy_assertions():
    """Verify forwardSecrecy flag for required cipher suites per prompt specification."""
    # AES256-GCM-SHA384 (0x009D): static RSA -> forwardSecrecy False
    rsa_gcm = CIPHER_SUITES[0x009D]
    assert rsa_gcm["forwardSecrecy"] is False
    assert rsa_gcm["kxType"] == "RSA"

    # ECDHE-RSA-AES256-GCM-SHA384 (0xC030): ephemeral ECDHE -> forwardSecrecy True
    ecdhe_gcm = CIPHER_SUITES[0xC030]
    assert ecdhe_gcm["forwardSecrecy"] is True
    assert ecdhe_gcm["kxType"] == "ECDHE"

    # TLS_AES_128_GCM_SHA256 (0x1301): TLS 1.3 suite -> forwardSecrecy True
    tls13_gcm = CIPHER_SUITES[0x1301]
    assert tls13_gcm["forwardSecrecy"] is True
    assert tls13_gcm["kxType"] == "tls13"

    # Static 3DES (0x000A): static RSA -> forwardSecrecy False
    des3 = CIPHER_SUITES[0x000A]
    assert des3["forwardSecrecy"] is False
    assert des3["weakClass"] == "3DES"


def test_key_exchange_group_and_dh_bits():
    """Verify kxGroupOrDhBits extraction from ServerKeyExchange and TLS 1.3 key_share."""
    # 1. TLS 1.2 ECDHE with named curve 23 (secp256r1)
    hs_ecdhe = TlsHandshake(
        server_hello=ServerHello(
            version=0x0303,
            random=b"\x00" * 32,
            session_id=b"",
            cipher_suite=0xC02F,
            compression_method=0,
        ),
        server_key_exchange=ServerKeyExchange(
            param_type="ec_diffie_hellman",
            raw_bytes=b"",
            named_curve=23,
        ),
        negotiated_version=0x0303,
    )
    info_ecdhe = negotiate_tls(hs_ecdhe)
    assert info_ecdhe.kxGroupOrDhBits == 23

    # 2. TLS 1.2 DHE with 2048-bit modulus
    hs_dhe = TlsHandshake(
        server_hello=ServerHello(
            version=0x0303,
            random=b"\x00" * 32,
            session_id=b"",
            cipher_suite=0x009E,  # DHE-RSA-AES128-GCM-SHA256
            compression_method=0,
        ),
        server_key_exchange=ServerKeyExchange(
            param_type="diffie_hellman",
            raw_bytes=b"",
            dh_p_bits=2048,
        ),
        negotiated_version=0x0303,
    )
    info_dhe = negotiate_tls(hs_dhe)
    assert info_dhe.kxGroupOrDhBits == 2048

    # 3. TLS 1.3 with key_share group 29 (x25519)
    hs_tls13 = TlsHandshake(
        server_hello=ServerHello(
            version=0x0303,
            random=b"\x00" * 32,
            session_id=b"",
            cipher_suite=0x1301,
            compression_method=0,
            extensions={"key_share": {"group": 29, "key_exchange": b""}},
        ),
        negotiated_version=0x0304,
    )
    info_tls13 = negotiate_tls(hs_tls13)
    assert info_tls13.kxGroupOrDhBits == 29

    # 4. Static RSA -> 0
    hs_rsa = TlsHandshake(
        server_hello=ServerHello(
            version=0x0303,
            random=b"\x00" * 32,
            session_id=b"",
            cipher_suite=0x009D,
            compression_method=0,
        ),
        negotiated_version=0x0303,
    )
    info_rsa = negotiate_tls(hs_rsa)
    assert info_rsa.kxGroupOrDhBits == 0


def test_acceptance_s01a():
    """Acceptance on S01a: Valid STARTTLS, TLS 1.2 with ECDHE."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S01a.pcap")
    sess = track_session(streams[0])
    hs = parse_tls_handshake(streams[0], sess.clientTlsStartOffset, sess.serverTlsStartOffset)
    tls_info = negotiate_tls(hs)

    truth = json.loads((TRUTH_DIR / "S01a.json").read_text(encoding="utf-8"))
    truth_tls = list(truth["connections"].values())[0]["tls"]

    assert tls_info.version == "TLS 1.2"
    assert tls_info.cipherSuiteCode == 0xC02F
    assert tls_info.cipherSuiteName == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert tls_info.forwardSecrecy is True
    assert tls_info.resumed is False
    assert tls_info.certObservable is True
    assert tls_info.certNotObservableReason is None
    assert tls_info.sni == truth_tls["sni"]
    assert tls_info.ja3 == truth_tls["ja3"]
    assert tls_info.ja3s == truth_tls["ja3s"]


def test_acceptance_s01b():
    """Acceptance on S01b: TLS 1.3, cert not observable (reason tls13)."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S01b.pcap")
    sess = track_session(streams[0])
    hs = parse_tls_handshake(streams[0], sess.clientTlsStartOffset, sess.serverTlsStartOffset)
    tls_info = negotiate_tls(hs)

    truth = json.loads((TRUTH_DIR / "S01b.json").read_text(encoding="utf-8"))
    truth_tls = list(truth["connections"].values())[0]["tls"]

    assert tls_info.version == "TLS 1.3"
    assert tls_info.cipherSuiteCode == 0x1301
    assert tls_info.cipherSuiteName == "TLS_AES_128_GCM_SHA256"
    assert tls_info.forwardSecrecy is True
    assert tls_info.kxGroupOrDhBits == 29
    assert tls_info.resumed is False
    assert tls_info.certObservable is False
    assert tls_info.certNotObservableReason == "tls13"
    assert tls_info.ja3 == truth_tls["ja3"]
    assert tls_info.ja3s == truth_tls["ja3s"]


def test_acceptance_s02():
    """Acceptance on S02: Deprecated TLS 1.0 negotiated."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S02.pcap")
    sess = track_session(streams[0])
    hs = parse_tls_handshake(streams[0], sess.clientTlsStartOffset, sess.serverTlsStartOffset)
    tls_info = negotiate_tls(hs)

    truth = json.loads((TRUTH_DIR / "S02.json").read_text(encoding="utf-8"))
    truth_tls = list(truth["connections"].values())[0]["tls"]

    assert tls_info.version == "TLS 1.0"
    assert tls_info.cipherSuiteCode == 0x002F
    assert tls_info.forwardSecrecy is False
    assert tls_info.resumed is False
    assert tls_info.certObservable is True


def test_acceptance_s03():
    """Acceptance on S03: 3DES cipher negotiated."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S03.pcap")
    sess = track_session(streams[0])
    hs = parse_tls_handshake(streams[0], sess.clientTlsStartOffset, sess.serverTlsStartOffset)
    tls_info = negotiate_tls(hs)

    assert tls_info.version == "TLS 1.2"
    assert tls_info.cipherSuiteCode == 0x000A
    assert tls_info.forwardSecrecy is False
    assert tls_info.certObservable is True


def test_acceptance_s07():
    """Acceptance on S07: Static RSA suite AES256-GCM-SHA384 (no forward secrecy)."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S07.pcap")
    sess = track_session(streams[0])
    hs = parse_tls_handshake(streams[0], sess.clientTlsStartOffset, sess.serverTlsStartOffset)
    tls_info = negotiate_tls(hs)

    assert tls_info.version == "TLS 1.2"
    assert tls_info.cipherSuiteCode == 0x009D
    assert tls_info.kxType == "RSA"
    assert tls_info.kxGroupOrDhBits == 0
    assert tls_info.forwardSecrecy is False
    assert tls_info.certObservable is True


def test_acceptance_s12():
    """Acceptance on S12: Resumed TLS 1.2 session (no certificate on wire)."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S12.pcap")
    sess = track_session(streams[0])
    hs = parse_tls_handshake(streams[0], sess.clientTlsStartOffset, sess.serverTlsStartOffset)
    tls_info = negotiate_tls(hs)

    assert tls_info.version == "TLS 1.2"
    assert tls_info.resumed is True
    assert tls_info.certObservable is False
    assert tls_info.certNotObservableReason == "resumed"


def test_negotiate_tls_empty_handshake():
    """Verify that an empty handshake returns None."""
    hs = TlsHandshake()
    assert negotiate_tls(hs) is None


def test_negotiate_tls_incomplete_handshake():
    """Verify handling when client sent ClientHello but connection dropped before ServerHello."""
    ch = ClientHello(
        legacy_version=771,
        random=b"\x00" * 32,
        session_id=b"",
        cipher_suites=[49199],
        compression_methods=b"\x00",
        extensions={"server_name": "mail.lab.local"},
        extension_types=[0],
    )
    hs = TlsHandshake(client_hello=ch)
    info = negotiate_tls(hs)
    assert info is not None
    assert info.sni == "mail.lab.local"
    assert info.ja3 is not None
    assert info.ja3s is None
    assert info.certObservable is False
    assert info.certNotObservableReason == "handshake_incomplete"
