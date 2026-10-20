"""Regression test for truncated/malformed TLS Hello messages (Issue 11).

Verifies that truncated ClientHello (<35 bytes) and ServerHello (<38 bytes)
do not raise IndexError or unhandled exceptions, and are recorded cleanly
in handshake.parse_errors.
"""
from dataclasses import dataclass
from typing import List, Optional
import struct
import pytest

from engine.smscope.tls.handshake import (
    parse_tls_handshake,
    HANDSHAKE_TYPE_CLIENT_HELLO,
    HANDSHAKE_TYPE_SERVER_HELLO,
)
from engine.smscope.ingest.reassembly import Stream


def create_tls_record(content_type: int, payload: bytes) -> bytes:
    """Create a TLS record (5-byte header + payload)."""
    # content_type (1 byte), version 0x0303 (2 bytes), length (2 bytes)
    hdr = struct.pack("!BHH", content_type, 0x0303, len(payload))
    return hdr + payload


def create_handshake_message(msg_type: int, body: bytes) -> bytes:
    """Create a TLS handshake message (4-byte header: type + 3-byte len + body)."""
    msg_len = len(body)
    hdr = bytes([msg_type, (msg_len >> 16) & 0xFF, (msg_len >> 8) & 0xFF, msg_len & 0xFF])
    return hdr + body


def test_truncated_client_hello_does_not_crash():
    """ClientHello with body shorter than 35 bytes must not raise IndexError."""
    # 34-byte body (less than minimum 35 bytes: 2 version + 32 random + 1 sess_id_len)
    truncated_body = b"\x03\x03" + (b"\xaa" * 32)  # exactly 34 bytes
    assert len(truncated_body) == 34

    hs_msg = create_handshake_message(HANDSHAKE_TYPE_CLIENT_HELLO, truncated_body)
    record = create_tls_record(22, hs_msg)  # 22 = Handshake

    stream = Stream(
        index=1,
        client="10.0.0.1:12345",
        server="10.0.0.2:465",
        firstFrame=1,
        firstTs=1600000000,
        complete=True,
        clientInferred=False,
        clientBytes=record,
        serverBytes=b"",
        clientOffsets=[(0, len(record), 1, 1600000000)],
        serverOffsets=[],
    )

    hs = parse_tls_handshake(stream, client_tls_offset=0, server_tls_offset=0)
    assert hs is not None
    assert hs.client_hello is None
    assert any(err.kind in ("malformed", "truncated") for err in hs.parse_errors)


def test_truncated_server_hello_does_not_crash():
    """ServerHello with body shorter than 38 bytes must not raise IndexError."""
    # 37-byte body (less than minimum 38 bytes: 2 ver + 32 random + 1 sess_len + 2 cs + 1 comp)
    truncated_body = b"\x03\x03" + (b"\xbb" * 32) + b"\x00\x00\x01"  # exactly 37 bytes
    assert len(truncated_body) == 37

    hs_msg = create_handshake_message(HANDSHAKE_TYPE_SERVER_HELLO, truncated_body)
    record = create_tls_record(22, hs_msg)

    stream = Stream(
        index=1,
        client="10.0.0.1:12345",
        server="10.0.0.2:465",
        firstFrame=1,
        firstTs=1600000000,
        complete=True,
        clientInferred=False,
        clientBytes=b"",
        serverBytes=record,
        clientOffsets=[],
        serverOffsets=[(0, len(record), 2, 1600000000)],
    )

    hs = parse_tls_handshake(stream, client_tls_offset=0, server_tls_offset=0)
    assert hs is not None
    assert hs.server_hello is None
    assert any(err.kind in ("malformed", "truncated") for err in hs.parse_errors)
