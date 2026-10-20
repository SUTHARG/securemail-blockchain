"""Regression tests for TLS parser nested length handling (Requirement 11).

Verifies that truncated nested fields in TLS records:
1. Truncated session ID declared length.
2. Truncated cipher suites length.
3. Truncated compression methods length.
4. Truncated extensions container length.
5. Truncated certificate list length in Certificate handshake.
6. Truncated individual certificate length.
7. Valid boundary cases parse correctly without crashes or partial corrupt objects.
"""
import struct
import pytest

from engine.smscope.tls.handshake import (
    parse_tls_handshake,
    HANDSHAKE_TYPE_CLIENT_HELLO,
    HANDSHAKE_TYPE_SERVER_HELLO,
    HANDSHAKE_TYPE_CERTIFICATE,
)
from engine.smscope.ingest.reassembly import Stream


def _create_tls_record(content_type: int, payload: bytes) -> bytes:
    hdr = struct.pack("!BHH", content_type, 0x0303, len(payload))
    return hdr + payload


def _create_handshake_message(msg_type: int, body: bytes) -> bytes:
    msg_len = len(body)
    hdr = bytes([msg_type, (msg_len >> 16) & 0xFF, (msg_len >> 8) & 0xFF, msg_len & 0xFF])
    return hdr + body


def _make_stream(client_bytes: bytes = b"", server_bytes: bytes = b"") -> Stream:
    c_offsets = [(0, len(client_bytes), 1, 1600000000)] if client_bytes else []
    s_offsets = [(0, len(server_bytes), 2, 1600000001)] if server_bytes else []
    return Stream(
        index=1,
        client="10.0.0.1:12345",
        server="10.0.0.2:465",
        firstFrame=1,
        firstTs=1600000000,
        complete=True,
        clientInferred=False,
        clientBytes=client_bytes,
        serverBytes=server_bytes,
        clientOffsets=c_offsets,
        serverOffsets=s_offsets,
    )


def test_client_hello_valid_boundary():
    """Valid minimal ClientHello parses cleanly."""
    body = bytearray(b"\x03\x03" + b"\x00" * 32)  # Version + Random
    body.append(0)  # Session ID length 0
    body.extend(b"\x00\x02\x00\x2f")  # Cipher suites: 2 bytes len, 1 cipher suite
    body.extend(b"\x01\x00")  # Compression: 1 byte len, null compression

    hs_msg = _create_handshake_message(HANDSHAKE_TYPE_CLIENT_HELLO, bytes(body))
    record = _create_tls_record(22, hs_msg)
    stream = _make_stream(client_bytes=record)

    hs = parse_tls_handshake(stream, 0, 0)
    assert hs.client_hello is not None
    assert hs.client_hello.legacy_version == 0x0303
    assert hs.client_hello.cipher_suites == [0x002f]
    assert len(hs.parse_errors) == 0


def test_client_hello_truncated_session_id():
    """Session ID length declaring more bytes than available is recorded as error."""
    body = bytearray(b"\x03\x03" + b"\x00" * 32)
    body.append(32)  # Declares 32 bytes of session ID
    body.extend(b"\x01\x02\x03\x04")  # Only 4 bytes available

    hs_msg = _create_handshake_message(HANDSHAKE_TYPE_CLIENT_HELLO, bytes(body))
    record = _create_tls_record(22, hs_msg)
    stream = _make_stream(client_bytes=record)

    hs = parse_tls_handshake(stream, 0, 0)
    assert hs.client_hello is None
    assert any(err.kind in ("truncated", "malformed") for err in hs.parse_errors)


def test_client_hello_truncated_cipher_suites():
    """Cipher suites declaring more bytes than available is recorded as error."""
    body = bytearray(b"\x03\x03" + b"\x00" * 32)
    body.append(0)  # Session ID len 0
    body.extend((100).to_bytes(2, "big"))  # Declared cipher suites len 100
    body.extend(b"\x00\x2f")  # Only 2 bytes available

    hs_msg = _create_handshake_message(HANDSHAKE_TYPE_CLIENT_HELLO, bytes(body))
    record = _create_tls_record(22, hs_msg)
    stream = _make_stream(client_bytes=record)

    hs = parse_tls_handshake(stream, 0, 0)
    assert hs.client_hello is None
    assert any(err.kind in ("truncated", "malformed") for err in hs.parse_errors)


def test_client_hello_truncated_compression_methods():
    """Compression methods declaring more bytes than available is recorded as error."""
    body = bytearray(b"\x03\x03" + b"\x00" * 32)
    body.append(0)  # Session ID len 0
    body.extend(b"\x00\x02\x00\x2f")  # 1 cipher suite (2 bytes)
    body.append(50)  # Declared compression len 50
    body.append(0)   # Only 1 byte available

    hs_msg = _create_handshake_message(HANDSHAKE_TYPE_CLIENT_HELLO, bytes(body))
    record = _create_tls_record(22, hs_msg)
    stream = _make_stream(client_bytes=record)

    hs = parse_tls_handshake(stream, 0, 0)
    assert hs.client_hello is None
    assert any(err.kind in ("truncated", "malformed") for err in hs.parse_errors)


def test_client_hello_truncated_extensions():
    """Extensions container declaring more bytes than available is recorded as error."""
    body = bytearray(b"\x03\x03" + b"\x00" * 32)
    body.append(0)  # Session ID len 0
    body.extend(b"\x00\x02\x00\x2f")  # 1 cipher suite
    body.append(1)  # Compression len 1
    body.append(0)  # null compression
    # Extensions: declares 200 bytes, supplies 4 bytes
    body.extend((200).to_bytes(2, "big"))
    body.extend(b"\x00\x00\x00\x00")

    hs_msg = _create_handshake_message(HANDSHAKE_TYPE_CLIENT_HELLO, bytes(body))
    record = _create_tls_record(22, hs_msg)
    stream = _make_stream(client_bytes=record)

    hs = parse_tls_handshake(stream, 0, 0)
    assert hs.client_hello is None
    assert any(err.kind in ("truncated", "malformed") for err in hs.parse_errors)


def test_certificate_handshake_truncated_list_length():
    """Certificate message declaring list length longer than payload is recorded as error."""
    # 3-byte total certs length: declares 1000 bytes, provides 10 bytes
    payload = (1000).to_bytes(3, "big") + b"\x00" * 10
    hs_msg = _create_handshake_message(HANDSHAKE_TYPE_CERTIFICATE, payload)
    record = _create_tls_record(22, hs_msg)
    stream = _make_stream(server_bytes=record)

    hs = parse_tls_handshake(stream, 0, 0)
    assert len(hs.certificates) == 0
    assert any(err.kind in ("truncated", "malformed") for err in hs.parse_errors)


def test_certificate_handshake_truncated_individual_cert():
    """Individual certificate length declaring more bytes than remaining in list is recorded as error."""
    # Total certs length = 20
    # First cert declares 50 bytes, but only 17 bytes follow
    payload = (20).to_bytes(3, "big") + (50).to_bytes(3, "big") + b"\x00" * 17
    hs_msg = _create_handshake_message(HANDSHAKE_TYPE_CERTIFICATE, payload)
    record = _create_tls_record(22, hs_msg)
    stream = _make_stream(server_bytes=record)

    hs = parse_tls_handshake(stream, 0, 0)
    assert len(hs.certificates) == 0
    assert any(err.kind in ("truncated", "malformed") for err in hs.parse_errors)
