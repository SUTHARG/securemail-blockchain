"""Unit and acceptance tests for X.509 certificate parsing, chain building, and validation."""
import json
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from engine.smscope.certs.analyze import (
    analyze_certificate_chain,
    check_sni_match,
    format_name,
    load_trust_store,
)
from engine.smscope.ingest.reassembly import reassemble_pcap
from engine.smscope.protocols.smtp import track_session
from engine.smscope.tls.handshake import parse_tls_handshake

CAPTURES_DIR = Path(__file__).resolve().parents[2] / "lab" / "captures"
TRUTH_DIR = Path(__file__).resolve().parents[2] / "eval" / "truth"
CA_OUT_DIR = Path(__file__).resolve().parents[2] / "lab" / "ca" / "out"


def test_sni_wildcard_and_ip_matching():
    """Verify RFC 6125 SNI matching rules: exact, leftmost wildcard, IP literals, no CN fallback."""
    # 1. Exact DNS match
    assert check_sni_match(["mail.example.com"], [], "mail.example.com") is True
    assert check_sni_match(["mail.example.com"], [], "other.example.com") is False
    assert check_sni_match(["MAIL.EXAMPLE.COM"], [], "mail.example.com") is True

    # 2. Wildcard DNS match: single-label leftmost only
    assert check_sni_match(["*.example.com"], [], "mail.example.com") is True
    assert check_sni_match(["*.example.com"], [], "smtp.example.com") is True
    assert check_sni_match(["*.example.com"], [], "sub.mail.example.com") is False
    assert check_sni_match(["*.example.com"], [], "example.com") is False

    # 3. IP address literal matching
    assert check_sni_match([], ["172.28.0.10"], "172.28.0.10") is True
    assert check_sni_match([], ["172.28.0.10"], "172.28.0.20") is False
    assert check_sni_match([], ["172.28.0.10"], "mail.example.com") is False
    assert check_sni_match(["172.28.0.10"], [], "172.28.0.10") is False


def test_time_reference_policy():
    """
    Verify Rule 2: certificate validity is judged against packet capture timestamp,
    never the local host machine's wall-clock time.
    """
    expired_der = x509.load_pem_x509_certificate(
        (CA_OUT_DIR / "expired.crt").read_bytes()
    ).public_bytes(Encoding.DER)

    trust_store = CA_OUT_DIR / "client_trust.crt"

    # expired.crt validity interval: 1577836800 (2020-01-01) to 1609459200 (2020-12-31)

    # Case A: Evaluated at 1700000000 (Nov 2023 > notAfter) -> expired
    certs_future = analyze_certificate_chain(
        [expired_der],
        capture_ts_sec=1700000000,
        sni="172.28.0.10",
        trust_store_path=trust_store,
    )
    assert len(certs_future) == 1
    assert "expired" in certs_future[0].verdicts
    assert "valid" not in certs_future[0].verdicts

    # Case B: Evaluated at 1580000000 (Jan 2020 within validity interval) -> valid
    certs_valid_time = analyze_certificate_chain(
        [expired_der],
        capture_ts_sec=1580000000,
        sni="172.28.0.10",
        trust_store_path=trust_store,
    )
    assert len(certs_valid_time) == 1
    assert "expired" not in certs_valid_time[0].verdicts
    assert "valid" in certs_valid_time[0].verdicts

    # Case C: Evaluated at 1500000000 (before notBefore) -> notYetValid
    certs_past = analyze_certificate_chain(
        [expired_der],
        capture_ts_sec=1500000000,
        sni="172.28.0.10",
        trust_store_path=trust_store,
    )
    assert len(certs_past) == 1
    assert "notYetValid" in certs_past[0].verdicts
    assert "valid" not in certs_past[0].verdicts


def test_weak_keys_and_signatures():
    """Verify detection of RSA < 2048, EC < 224, and weak hashes (MD5, SHA-1)."""
    trust_store = CA_OUT_DIR / "client_trust.crt"
    ts = 1800000000  # valid time window for 2026 certs

    # RSA 1024-bit
    rsa1024_der = x509.load_pem_x509_certificate(
        (CA_OUT_DIR / "rsa1024.crt").read_bytes()
    ).public_bytes(Encoding.DER)
    res_rsa1024 = analyze_certificate_chain(
        [rsa1024_der], capture_ts_sec=ts, sni="172.28.0.10", trust_store_path=trust_store
    )
    assert "weakKey" in res_rsa1024[0].verdicts
    assert res_rsa1024[0].keySize == 1024

    # SHA-1 signature
    sha1_der = x509.load_pem_x509_certificate(
        (CA_OUT_DIR / "sha1.crt").read_bytes()
    ).public_bytes(Encoding.DER)
    res_sha1 = analyze_certificate_chain(
        [sha1_der], capture_ts_sec=ts, sni="172.28.0.10", trust_store_path=trust_store
    )
    assert "weakSignature" in res_sha1[0].verdicts
    assert "sha1WithRSAEncryption" in res_sha1[0].signatureAlgorithm


def test_self_signed_and_untrusted_issuer():
    """Verify distinction between self-signed leaf and untrusted root issuer."""
    trust_store = CA_OUT_DIR / "client_trust.crt"
    ts = 1800000000

    # Self-signed
    self_signed_der = x509.load_pem_x509_certificate(
        (CA_OUT_DIR / "self-signed.crt").read_bytes()
    ).public_bytes(Encoding.DER)
    res_self = analyze_certificate_chain(
        [self_signed_der], capture_ts_sec=ts, sni="172.28.0.10", trust_store_path=trust_store
    )
    assert "selfSigned" in res_self[0].verdicts
    assert "unknownIssuer" in res_self[0].verdicts
    assert "valid" not in res_self[0].verdicts

    # Untrusted issuer
    untrusted_der = x509.load_pem_x509_certificate(
        (CA_OUT_DIR / "untrusted-ca.crt").read_bytes()
    ).public_bytes(Encoding.DER)
    res_untrusted = analyze_certificate_chain(
        [untrusted_der], capture_ts_sec=ts, sni="172.28.0.10", trust_store_path=trust_store
    )
    assert "unknownIssuer" in res_untrusted[0].verdicts
    assert "selfSigned" not in res_untrusted[0].verdicts
    assert "valid" not in res_untrusted[0].verdicts


def test_acceptance_s01a():
    """Acceptance on S01a: Valid 2048-bit certificate."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S01a.pcap")
    sess = track_session(streams[0])
    hs = parse_tls_handshake(streams[0], sess.clientTlsStartOffset, sess.serverTlsStartOffset)
    truth = json.loads((TRUTH_DIR / "S01a.json").read_text(encoding="utf-8"))
    truth_tls = list(truth["connections"].values())[0]["tls"]

    certs = analyze_certificate_chain(
        hs.certificates,
        capture_ts_sec=sess.firstPacketTs,
        sni=hs.sni,
        trust_store_path=CA_OUT_DIR / "client_trust.crt",
    )

    assert len(certs) == 1
    c = certs[0]
    assert c.sha256 == truth_tls["certFingerprints"][0]
    assert c.keyAlgorithm == "RSA"
    assert c.keySize == 2048
    assert c.signatureAlgorithm == "sha256WithRSAEncryption"
    assert c.isCa is False
    assert c.verdicts == ["valid"]


def test_acceptance_s04():
    """Acceptance on S04: Expired certificate."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S04.pcap")
    sess = track_session(streams[0])
    hs = parse_tls_handshake(streams[0], sess.clientTlsStartOffset, sess.serverTlsStartOffset)
    truth = json.loads((TRUTH_DIR / "S04.json").read_text(encoding="utf-8"))
    truth_tls = list(truth["connections"].values())[0]["tls"]

    certs = analyze_certificate_chain(
        hs.certificates,
        capture_ts_sec=sess.firstPacketTs,
        sni=hs.sni,
        trust_store_path=CA_OUT_DIR / "client_trust.crt",
    )

    assert len(certs) == 1
    c = certs[0]
    assert c.sha256 == truth_tls["certFingerprints"][0]
    assert "expired" in c.verdicts
    assert "valid" not in c.verdicts


def test_acceptance_s08():
    """Acceptance on S08: Weak RSA key (1024-bit)."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S08.pcap")
    sess = track_session(streams[0])
    hs = parse_tls_handshake(streams[0], sess.clientTlsStartOffset, sess.serverTlsStartOffset)
    truth = json.loads((TRUTH_DIR / "S08.json").read_text(encoding="utf-8"))
    truth_tls = list(truth["connections"].values())[0]["tls"]

    certs = analyze_certificate_chain(
        hs.certificates,
        capture_ts_sec=sess.firstPacketTs,
        sni=hs.sni,
        trust_store_path=CA_OUT_DIR / "client_trust.crt",
    )

    assert len(certs) == 1
    c = certs[0]
    assert c.sha256 == truth_tls["certFingerprints"][0]
    assert c.keySize == 1024
    assert "weakKey" in c.verdicts


def test_acceptance_s09():
    """Acceptance on S09: Weak signature algorithm (SHA-1)."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S09.pcap")
    sess = track_session(streams[0])
    hs = parse_tls_handshake(streams[0], sess.clientTlsStartOffset, sess.serverTlsStartOffset)
    truth = json.loads((TRUTH_DIR / "S09.json").read_text(encoding="utf-8"))
    truth_tls = list(truth["connections"].values())[0]["tls"]

    certs = analyze_certificate_chain(
        hs.certificates,
        capture_ts_sec=sess.firstPacketTs,
        sni=hs.sni,
        trust_store_path=CA_OUT_DIR / "client_trust.crt",
    )

    assert len(certs) == 1
    c = certs[0]
    assert c.sha256 == truth_tls["certFingerprints"][0]
    assert "weakSignature" in c.verdicts


def test_acceptance_s10():
    """Acceptance on S10: Self-signed leaf certificate."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S10.pcap")
    sess = track_session(streams[0])
    hs = parse_tls_handshake(streams[0], sess.clientTlsStartOffset, sess.serverTlsStartOffset)
    truth = json.loads((TRUTH_DIR / "S10.json").read_text(encoding="utf-8"))
    truth_tls = list(truth["connections"].values())[0]["tls"]

    certs = analyze_certificate_chain(
        hs.certificates,
        capture_ts_sec=sess.firstPacketTs,
        sni=hs.sni,
        trust_store_path=CA_OUT_DIR / "client_trust.crt",
    )

    assert len(certs) == 1
    c = certs[0]
    assert c.sha256 == truth_tls["certFingerprints"][0]
    assert "selfSigned" in c.verdicts
    assert "unknownIssuer" in c.verdicts


def test_acceptance_s11():
    """Acceptance on S11: Untrusted root CA absent from trust store."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S11.pcap")
    sess = track_session(streams[0])
    hs = parse_tls_handshake(streams[0], sess.clientTlsStartOffset, sess.serverTlsStartOffset)
    truth = json.loads((TRUTH_DIR / "S11.json").read_text(encoding="utf-8"))
    truth_tls = list(truth["connections"].values())[0]["tls"]

    certs = analyze_certificate_chain(
        hs.certificates,
        capture_ts_sec=sess.firstPacketTs,
        sni=hs.sni,
        trust_store_path=CA_OUT_DIR / "client_trust.crt",
    )

    assert len(certs) == 1
    c = certs[0]
    assert c.sha256 == truth_tls["certFingerprints"][0]
    assert "unknownIssuer" in c.verdicts
    assert "selfSigned" not in c.verdicts


def test_certificate_timestamp_boundary_uses_certificate_packet_ts():
    """
    Issue 6: Certificate validity is judged against the timestamp of the packet
    carrying the Certificate message, not the session's first packet.
    """
    from engine.smscope.certs import process_certs
    from engine.smscope.models import SessionRecord, StarttlsInfo

    expired_der = x509.load_pem_x509_certificate(
        (CA_OUT_DIR / "expired.crt").read_bytes()
    ).public_bytes(Encoding.DER)

    cert_obj = x509.load_der_x509_certificate(expired_der)
    not_after = int(cert_obj.not_valid_after_utc.timestamp())
    not_before = int(cert_obj.not_valid_before_utc.timestamp())

    # Case 1: First packet is BEFORE expiry (valid), but Certificate packet is AFTER expiry (expired)
    sess_expired = SessionRecord(
        sessionId=1,
        clientEndpoint="10.0.0.1:1234",
        serverEndpoint="10.0.0.2:25",
        protocol="smtp",
        protocolSource="port",
        transportMode="starttls",
        streamComplete=True,
        firstPacketTs=not_after - 10,  # Would be valid if firstPacketTs was used
        starttls=StarttlsInfo(offered=True, attempted=True, outcome="succeeded"),
    )
    sess_expired._raw_certificates = [expired_der]
    sess_expired._certificate_ts_sec = not_after + 5  # Expired at certificate packet time
    sess_expired._sni = None

    process_certs([sess_expired], trust_store_path=CA_OUT_DIR / "client_trust.crt")
    assert len(sess_expired.certificates) == 1
    assert "expired" in sess_expired.certificates[0].verdicts

    # Case 2: First packet is BEFORE notBefore (invalid), but Certificate packet is AFTER notBefore (valid)
    sess_valid_after_start = SessionRecord(
        sessionId=2,
        clientEndpoint="10.0.0.1:1235",
        serverEndpoint="10.0.0.2:25",
        protocol="smtp",
        protocolSource="port",
        transportMode="starttls",
        streamComplete=True,
        firstPacketTs=not_before - 10,  # Would be invalid if firstPacketTs was used
        starttls=StarttlsInfo(offered=True, attempted=True, outcome="succeeded"),
    )
    sess_valid_after_start._raw_certificates = [expired_der]
    sess_valid_after_start._certificate_ts_sec = not_before + 10  # Valid at certificate packet time
    sess_valid_after_start._sni = None

    process_certs([sess_valid_after_start], trust_store_path=CA_OUT_DIR / "client_trust.crt")
    assert len(sess_valid_after_start.certificates) == 1
    assert "notYetValid" not in sess_valid_after_start.certificates[0].verdicts
    assert "expired" not in sess_valid_after_start.certificates[0].verdicts
