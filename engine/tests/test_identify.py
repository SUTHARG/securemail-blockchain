"""Tests for protocol identification (Prompt 5.2)."""
from pathlib import Path

import pytest

from engine.smscope.ingest.reassembly import Stream, reassemble_pcap
from engine.smscope.protocols.identify import ProtocolIdentification, identify

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"


def make_dummy_stream(
    server_port: int,
    client_bytes: bytes = b"",
    server_bytes: bytes = b"",
    client_ip: str = "172.28.0.20",
    server_ip: str = "172.28.0.10",
) -> Stream:
    """Creates a minimal Stream object for table-driven testing."""
    return Stream(
        index=0,
        client=f"{client_ip}:45000",
        server=f"{server_ip}:{server_port}",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=client_bytes,
        serverBytes=server_bytes,
    )


# ==============================================================================
# Acceptance Tests
# ==============================================================================

def test_acceptance_s01a_s05_s13():
    """Acceptance: S01a, S05 and S13 identify as smtp with sources content, content and port."""
    # S01a: Plaintext 220 greeting and EHLO followed by STARTTLS
    s01a_streams, _ = reassemble_pcap(CAPTURES_DIR / "S01a.pcap")
    assert len(s01a_streams) == 1
    res_s01a = identify(s01a_streams[0])
    assert res_s01a.protocol == "smtp"
    assert res_s01a.source == "content"
    assert res_s01a.transport_hint == "plaintext"

    # S05: Plaintext 220 greeting and EHLO without STARTTLS
    s05_streams, _ = reassemble_pcap(CAPTURES_DIR / "S05.pcap")
    assert len(s05_streams) == 1
    res_s05 = identify(s05_streams[0])
    assert res_s05.protocol == "smtp"
    assert res_s05.source == "content"
    assert res_s05.transport_hint == "plaintext"

    # S13: Implicit TLS on port 465
    s13_streams, _ = reassemble_pcap(CAPTURES_DIR / "S13.pcap")
    assert len(s13_streams) == 1
    res_s13 = identify(s13_streams[0])
    assert res_s13.protocol == "smtp"
    assert res_s13.source == "port"
    assert res_s13.transport_hint == "implicitTls"


def test_stress_captures_identification():
    """Verifies X01, X02, X03 identify as smtp with source content."""
    for cap_name in ("X01.pcap", "X02.pcap", "X03.pcap"):
        streams, _ = reassemble_pcap(CAPTURES_DIR / cap_name)
        assert len(streams) == 1
        res = identify(streams[0])
        assert res.protocol == "smtp"
        assert res.source == "content"


# ==============================================================================
# Table-Driven Tests (hand-written first lines, malformed, empty)
# ==============================================================================

TABLE_DRIVEN_CASES = [
    # (name, port, client_bytes, server_bytes, expected_proto, expected_src, expected_transport)
    # SMTP via content
    (
        "smtp_standard_ehlo",
        25,
        b"EHLO client.local\r\n",
        b"220 mail.example.com ESMTP Postfix\r\n",
        "smtp",
        "content",
        "plaintext",
    ),
    (
        "smtp_standard_helo",
        25,
        b"helo client.local\r\n",
        b"220 mail.example.com ESMTP\r\n",
        "smtp",
        "content",
        "plaintext",
    ),
    (
        "smtp_multiline_banner",
        587,
        b"EHLO client.local\r\n",
        b"220-mail.example.com ESMTP\r\n220-banner\r\n220 Ready\r\n",
        "smtp",
        "content",
        "plaintext",
    ),
    (
        "smtp_non_standard_port_content_decides",
        2525,
        b"EHLO client.local\r\n",
        b"220 custom.mail.local\r\n",
        "smtp",
        "content",
        "plaintext",
    ),
    # IMAP via content
    (
        "imap_ok_greeting",
        143,
        b"a001 CAPABILITY\r\n",
        b"* OK [CAPABILITY IMAP4rev1] Server ready\r\n",
        "imap",
        "content",
        "plaintext",
    ),
    (
        "imap_non_standard_port",
        8143,
        b"",
        b"* OK Dovecot ready\r\n",
        "imap",
        "content",
        "plaintext",
    ),
    # POP3 via content
    (
        "pop3_ok_greeting",
        110,
        b"USER alice\r\n",
        b"+OK Dovecot ready\r\n",
        "pop3",
        "content",
        "plaintext",
    ),
    (
        "pop3_non_standard_port",
        8110,
        b"",
        b"+OK POP3 server ready <1234@server>\r\n",
        "pop3",
        "content",
        "plaintext",
    ),
    # Implicit TLS
    (
        "implicit_tls_smtp_465",
        465,
        b"\x16\x03\x01\x00\x50\x01...",
        b"\x16\x03\x03...",
        "smtp",
        "port",
        "implicitTls",
    ),
    (
        "implicit_tls_imap_993",
        993,
        b"\x16\x03\x03\x00\x60...",
        b"",
        "imap",
        "port",
        "implicitTls",
    ),
    (
        "implicit_tls_pop3_995",
        995,
        b"\x16\x03\x03\x00\x60...",
        b"",
        "pop3",
        "port",
        "implicitTls",
    ),
    (
        "implicit_tls_unknown_port",
        8443,
        b"\x16\x03\x03\x00\x50...",
        b"",
        "unknown",
        "port",
        "implicitTls",
    ),
    # Port hints (content absent or ambiguous)
    (
        "empty_content_port_25",
        25,
        b"",
        b"",
        "smtp",
        "port",
        "plaintext",
    ),
    (
        "empty_content_port_587",
        587,
        b"",
        b"",
        "smtp",
        "port",
        "plaintext",
    ),
    (
        "empty_content_port_143",
        143,
        b"",
        b"",
        "imap",
        "port",
        "plaintext",
    ),
    (
        "empty_content_port_110",
        110,
        b"",
        b"",
        "pop3",
        "port",
        "plaintext",
    ),
    (
        "ambiguous_greeting_220_no_client_hello_on_port_25",
        25,
        b"",
        b"220 mail.local\r\n",
        "smtp",
        "port",
        "plaintext",
    ),
    # Unknown / non-mail traffic
    (
        "http_traffic_on_port_80",
        80,
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"HTTP/1.1 200 OK\r\n",
        "unknown",
        "port",
        "plaintext",
    ),
    (
        "empty_stream_unknown_port",
        8080,
        b"",
        b"",
        "unknown",
        "port",
        "plaintext",
    ),
    (
        "garbage_bytes_unknown_port",
        9999,
        b"\xff\xfe\x00\x01\x02\x03",
        b"\x00\x00\x00\x00",
        "unknown",
        "port",
        "plaintext",
    ),
]


@pytest.mark.parametrize(
    "name, port, client_bytes, server_bytes, expected_proto, expected_src, expected_transport",
    TABLE_DRIVEN_CASES,
)
def test_table_driven_protocol_identification(
    name, port, client_bytes, server_bytes, expected_proto, expected_src, expected_transport
):
    stream = make_dummy_stream(server_port=port, client_bytes=client_bytes, server_bytes=server_bytes)
    result = identify(stream)

    assert result.protocol == expected_proto, f"Case '{name}' failed protocol check"
    assert result.source == expected_src, f"Case '{name}' failed source check"
    assert result.transport_hint == expected_transport, f"Case '{name}' failed transport_hint check"
    assert result.transportHint == expected_transport

    # Test tuple unpacking
    proto, src, hint = result
    assert proto == expected_proto
    assert src == expected_src
    assert hint == expected_transport
