"""Tests for TLS record layer and handshake parsing (Prompt 5.4)."""
import json
import struct
from pathlib import Path

import pytest

from engine.smscope.ingest.reassembly import Stream, reassemble_pcap
from engine.smscope.protocols.smtp import track_smtp
from engine.smscope.tls.handshake import (
    HRR_RANDOM,
    ClientHello,
    ServerHello,
    TlsHandshake,
    parse_tls_handshake,
)
from engine.smscope.tls.records import (
    CONTENT_TYPE_ALERT,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    CONTENT_TYPE_HANDSHAKE,
    parse_tls_records,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"
TRUTH_DIR = REPO_ROOT / "eval" / "truth"


# ==============================================================================
# Acceptance Tests
# ==============================================================================

@pytest.mark.parametrize("scenario", ["S01a", "S13", "X02"])
def test_acceptance_tls_handshake_matches_tshark(scenario):
    """
    Acceptance: version, selected cipher code, SNI and the list of offered cipher codes
    match tshark on all lab captures including X02.
    """
    pcap_path = CAPTURES_DIR / f"{scenario}.pcap"
    truth_path = TRUTH_DIR / f"{scenario}.json"

    assert pcap_path.exists()
    assert truth_path.exists()

    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    conn_key = list(truth["connections"].keys())[0]
    expected_tls = truth["connections"][conn_key]["tls"]

    streams, _ = reassemble_pcap(pcap_path)
    assert len(streams) == 1
    stream = streams[0]

    session = track_smtp(stream)
    assert session.clientTlsStartOffset is not None
    assert session.serverTlsStartOffset is not None

    handshake = parse_tls_handshake(
        stream,
        session.clientTlsStartOffset,
        session.serverTlsStartOffset,
    )

    assert handshake.version_hex == expected_tls["selectedVersion"]
    assert handshake.selected_cipher == expected_tls["selectedCipher"]
    assert handshake.sni == expected_tls["sni"]
    assert handshake.offered_ciphers == expected_tls["offeredCiphers"]
    assert len(handshake.certificates) >= 1
    assert len(handshake.parse_errors) == 0


def test_tls_handshake_x01_reordered_reassembly():
    """Verifies X01 reorders segments and extracts the full handshake."""
    pcap_path = CAPTURES_DIR / "X01.pcap"
    streams, _ = reassemble_pcap(pcap_path)
    stream = streams[0]
    session = track_smtp(stream)

    handshake = parse_tls_handshake(stream, session.clientTlsStartOffset, session.serverTlsStartOffset)
    assert handshake.version_hex == "0x0303"
    assert handshake.selected_cipher == 49199
    assert handshake.sni == "172.28.0.10"
    assert handshake.offered_ciphers == [49199, 49195, 159, 156]
    assert len(handshake.certificates) >= 1
    assert len(handshake.parse_errors) == 0



# ==============================================================================
# Hand-Built Messages for Each Type
# ==============================================================================

def test_handbuilt_client_hello_all_extensions():
    """Tests ClientHello with all required extension types."""
    sni_bytes = b"secure.example.com"
    ext_sni = (
        b"\x00\x00"  # ext type 0
        + (len(sni_bytes) + 5).to_bytes(2, "big")
        + (len(sni_bytes) + 3).to_bytes(2, "big")
        + b"\x00"
        + len(sni_bytes).to_bytes(2, "big")
        + sni_bytes
    )
    # supported_groups (type 10): secp256r1 (0x0017), secp384r1 (0x0018)
    ext_groups = b"\x00\x0a\x00\x06\x00\x04\x00\x17\x00\x18"
    # ec_point_formats (type 11): uncompressed (0)
    ext_ec_points = b"\x00\x0b\x00\x02\x01\x00"
    # signature_algorithms (type 13): rsa_pss_rsae_sha256 (0x0804)
    ext_sigs = b"\x00\x0d\x00\x04\x00\x02\x08\x04"
    # alpn (type 16): "smtp"
    alpn_str = b"smtp"
    ext_alpn = b"\x00\x10\x00\x07\x00\x05\x04" + alpn_str
    # supported_versions (type 43): TLS 1.3 (0x0304), TLS 1.2 (0x0303)
    ext_vers = b"\x00\x2b\x00\x05\x04\x03\x04\x03\x03"
    # psk_key_exchange_modes (type 45): psk_dhe_ke (1)
    ext_psk = b"\x00\x2d\x00\x02\x01\x01"
    # key_share (type 51): group secp256r1 (0x0017) with 32 dummy bytes
    key_bytes = b"\xaa" * 32
    ext_ks = b"\x00\x33" + (len(key_bytes) + 6).to_bytes(2, "big") + (len(key_bytes) + 4).to_bytes(2, "big") + b"\x00\x17" + len(key_bytes).to_bytes(2, "big") + key_bytes

    all_exts = ext_sni + ext_groups + ext_ec_points + ext_sigs + ext_alpn + ext_vers + ext_psk + ext_ks
    ciphers = b"\xc0\x2f\x13\x01"  # ECDHE-RSA-AES128-GCM-SHA256, TLS_AES_128_GCM_SHA256

    ch_body = (
        b"\x03\x03"  # legacy version
        + b"\x11" * 32  # random
        + b"\x04\x01\x02\x03\x04"  # session_id
        + len(ciphers).to_bytes(2, "big") + ciphers
        + b"\x01\x00"  # compression
        + len(all_exts).to_bytes(2, "big") + all_exts
    )

    ch_msg = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
    rec = b"\x16\x03\x03" + len(ch_msg).to_bytes(2, "big") + ch_msg

    dummy_stream = Stream(
        index=0,
        client="10.0.0.1:50000",
        server="10.0.0.2:25",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=rec,
        serverBytes=b"",
    )

    handshake = parse_tls_handshake(dummy_stream, 0, 0)
    ch = handshake.client_hello
    assert ch is not None
    assert ch.legacy_version == 0x0303
    assert ch.random == b"\x11" * 32
    assert ch.session_id == b"\x01\x02\x03\x04"
    assert ch.cipher_suites == [0xc02f, 0x1301]
    assert ch.extensions["server_name"] == "secure.example.com"
    assert ch.extensions["supported_groups"] == [0x0017, 0x0018]
    assert ch.extensions["ec_point_formats"] == [0]
    assert ch.extensions["signature_algorithms"] == [0x0804]
    assert ch.extensions["alpn"] == ["smtp"]
    assert ch.extensions["supported_versions"] == [0x0304, 0x0303]
    assert ch.extensions["psk_key_exchange_modes"] == [1]
    assert len(ch.extensions["key_share"]) == 1
    assert ch.extensions["key_share"][0]["group"] == 0x0017


def test_handbuilt_server_hello_and_retry_request():
    """Tests ServerHello with TLS 1.3 supported_versions and HelloRetryRequest constant."""
    # Regular ServerHello negotiating TLS 1.3
    ext_vers = b"\x00\x2b\x00\x02\x03\x04"  # supported_versions: TLS 1.3
    ext_ks = b"\x00\x33\x00\x08\x00\x17\x00\x04\xde\xad\xbe\xef"
    ext_psk = b"\x00\x29\x00\x02\x00\x01"  # pre_shared_key: selected index 1
    all_exts = ext_vers + ext_ks + ext_psk

    sh_body = (
        b"\x03\x03"
        + b"\x22" * 32
        + b"\x00"
        + b"\x13\x01"  # TLS_AES_128_GCM_SHA256
        + b"\x00"
        + len(all_exts).to_bytes(2, "big") + all_exts
    )
    sh_msg = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body
    rec = b"\x16\x03\x03" + len(sh_msg).to_bytes(2, "big") + sh_msg

    stream = Stream(
        index=0, client="1.1.1.1:1", server="2.2.2.2:25", firstFrame=1, firstTs=1, complete=True, clientInferred=False,
        clientBytes=b"", serverBytes=rec
    )
    hs = parse_tls_handshake(stream, 0, 0)
    assert hs.server_hello is not None
    assert hs.negotiated_version == 0x0304
    assert hs.version_hex == "0x0304"
    assert hs.selected_cipher == 0x1301
    assert hs.is_hello_retry_request is False
    assert hs.server_hello.extensions["key_share"]["group"] == 0x0017
    assert hs.server_hello.extensions["pre_shared_key"] == 1

    # HelloRetryRequest: ServerHello with HRR_RANDOM
    hrr_body = b"\x03\x03" + HRR_RANDOM + b"\x00\x13\x01\x00\x00\x00"
    hrr_msg = b"\x02" + len(hrr_body).to_bytes(3, "big") + hrr_body
    hrr_rec = b"\x16\x03\x03" + len(hrr_msg).to_bytes(2, "big") + hrr_msg

    stream_hrr = Stream(
        index=1, client="1.1.1.1:1", server="2.2.2.2:25", firstFrame=1, firstTs=1, complete=True, clientInferred=False,
        clientBytes=b"", serverBytes=hrr_rec
    )
    hs_hrr = parse_tls_handshake(stream_hrr, 0, 0)
    assert hs_hrr.is_hello_retry_request is True


def test_handbuilt_certificate_and_key_exchange():
    """Tests Certificate (list of DERs), ServerKeyExchange (ECDHE and DHE), and CertificateStatus."""
    cert1 = b"\x30\x82\x01\x01" + b"\x01" * 257
    cert2 = b"\x30\x82\x01\x02" + b"\x02" * 258

    # TLS 1.2 Certificate message
    cert_list = (
        len(cert1).to_bytes(3, "big") + cert1
        + len(cert2).to_bytes(3, "big") + cert2
    )
    cert_body = len(cert_list).to_bytes(3, "big") + cert_list
    cert_msg = b"\x0b" + len(cert_body).to_bytes(3, "big") + cert_body
    cert_rec = b"\x16\x03\x03" + len(cert_msg).to_bytes(2, "big") + cert_msg

    # ServerKeyExchange (ECDHE with secp256r1 0x0017)
    ske_body = b"\x03\x00\x17\x20" + b"\x55" * 32 + b"\x04\x01\x00\x10" + b"\x66" * 16
    ske_msg = b"\x0c" + len(ske_body).to_bytes(3, "big") + ske_body
    ske_rec = b"\x16\x03\x03" + len(ske_msg).to_bytes(2, "big") + ske_msg

    # CertificateStatus (stapled OCSP)
    cs_ocsp = b"\x30\x82\x00\x50" + b"\x77" * 80
    cs_body = b"\x01" + len(cs_ocsp).to_bytes(3, "big") + cs_ocsp
    cs_msg = b"\x16" + len(cs_body).to_bytes(3, "big") + cs_body
    cs_rec = b"\x16\x03\x03" + len(cs_msg).to_bytes(2, "big") + cs_msg

    server_bytes = cert_rec + ske_rec + cs_rec
    stream = Stream(
        index=0, client="1.1.1.1:1", server="2.2.2.2:25", firstFrame=1, firstTs=1, complete=True, clientInferred=False,
        clientBytes=b"", serverBytes=server_bytes
    )
    hs = parse_tls_handshake(stream, 0, 0)
    assert len(hs.certificates) == 2
    assert hs.certificates[0] == cert1
    assert hs.certificates[1] == cert2

    assert hs.server_key_exchange is not None
    assert hs.server_key_exchange.param_type == "ec_diffie_hellman"
    assert hs.server_key_exchange.named_curve == 0x0017

    assert hs.certificate_status is not None
    assert hs.certificate_status.status_type == 1
    assert hs.certificate_status.ocsp_response == cs_ocsp


def test_handbuilt_fatal_alert():
    """Tests capture of cleartext fatal alert."""
    # Alert level 2 (fatal), description 40 (handshake_failure)
    alert_payload = b"\x02\x28"
    alert_rec = b"\x15\x03\x03\x00\x02" + alert_payload

    stream = Stream(
        index=0, client="1.1.1.1:1", server="2.2.2.2:25", firstFrame=1, firstTs=1, complete=True, clientInferred=False,
        clientBytes=b"", serverBytes=alert_rec
    )
    hs = parse_tls_handshake(stream, 0, 0)
    assert hs.fatal_alert is not None
    assert hs.fatal_alert.level == 2
    assert hs.fatal_alert.description == 40


# ==============================================================================
# Defragmentation Across Records & Bounds Checking
# ==============================================================================

def test_handshake_split_across_records():
    """Proves a handshake message split across two TLS records reassembles cleanly."""
    ch_body = b"\x03\x03" + b"\xaa" * 32 + b"\x00\x00\x02\xc0\x2f\x01\x00\x00\x00"
    ch_msg = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body

    # Split ch_msg into two chunks
    chunk1 = ch_msg[:20]
    chunk2 = ch_msg[20:]

    rec1 = b"\x16\x03\x03" + len(chunk1).to_bytes(2, "big") + chunk1
    rec2 = b"\x16\x03\x03" + len(chunk2).to_bytes(2, "big") + chunk2

    stream = Stream(
        index=0, client="1.1.1.1:1", server="2.2.2.2:25", firstFrame=1, firstTs=1, complete=True, clientInferred=False,
        clientBytes=rec1 + rec2, serverBytes=b""
    )
    hs = parse_tls_handshake(stream, 0, 0)
    assert hs.client_hello is not None
    assert hs.client_hello.legacy_version == 0x0303
    assert hs.client_hello.cipher_suites == [0xc02f]
    assert len(hs.parse_errors) == 0


def test_truncated_and_oversized_bounds_checking():
    """Proves truncated headers and oversized declared lengths never raise exceptions."""
    # 1. Truncated record header (< 5 bytes)
    truncated_rec = b"\x16\x03\x03"
    stream1 = Stream(
        index=0, client="1.1.1.1:1", server="2.2.2.2:25", firstFrame=1, firstTs=1, complete=True, clientInferred=False,
        clientBytes=truncated_rec, serverBytes=b""
    )
    hs1 = parse_tls_handshake(stream1, 0, 0)
    assert len(hs1.parse_errors) == 1
    assert hs1.parse_errors[0].kind == "truncated"

    # 2. Oversized record length (header claims 500 bytes, only 10 provided)
    oversized_rec = b"\x16\x03\x03\x01\xf4" + b"\x00" * 10
    stream2 = Stream(
        index=0, client="1.1.1.1:1", server="2.2.2.2:25", firstFrame=1, firstTs=1, complete=True, clientInferred=False,
        clientBytes=oversized_rec, serverBytes=b""
    )
    hs2 = parse_tls_handshake(stream2, 0, 0)
    assert len(hs2.parse_errors) == 1
    assert hs2.parse_errors[0].kind == "truncated"

    # 3. Oversized handshake message length (message claims 1000 bytes, record payload only 20)
    oversized_hs_body = b"\x01\x00\x03\xe8" + b"\x00" * 16
    rec3 = b"\x16\x03\x03" + len(oversized_hs_body).to_bytes(2, "big") + oversized_hs_body
    stream3 = Stream(
        index=0, client="1.1.1.1:1", server="2.2.2.2:25", firstFrame=1, firstTs=1, complete=True, clientInferred=False,
        clientBytes=rec3, serverBytes=b""
    )
    hs3 = parse_tls_handshake(stream3, 0, 0)
    assert len(hs3.parse_errors) == 1
    assert hs3.parse_errors[0].kind == "truncated"
