"""Regression tests for AUTH evidence detection in SMTP, IMAP, and POP3 (Requirement 9).

Verifies:
1. Inline credentials detected correctly.
2. Valid challenge-response credentials detected.
3. Empty or cancelled authentication exchange ('*') does NOT produce credential exposure.
4. Later unrelated commands after AUTH do NOT falsely trigger credential detection.
5. Truncated captures without client responses do NOT falsely report credential exposure.
6. Zero credential contents (passwords/tokens) are stored or retained in CleartextAuth models.
"""
from dataclasses import asdict
from engine.smscope.ingest.reassembly import Stream
from engine.smscope.protocols.smtp import track_smtp
from engine.smscope.protocols.imap import track_imap
from engine.smscope.protocols.pop3 import track_pop3


def _make_stream(client_bytes: bytes, server_bytes: bytes, s_port: int = 25) -> Stream:
    c_offsets = [(0, len(client_bytes), 1, 1000)] if client_bytes else []
    s_offsets = [(0, len(server_bytes), 2, 1000)] if server_bytes else []
    return Stream(
        index=1,
        client="10.0.0.1:12345",
        server=f"10.0.0.2:{s_port}",
        firstFrame=1,
        firstTs=1000,
        complete=True,
        clientInferred=False,
        clientBytes=client_bytes,
        serverBytes=server_bytes,
        clientOffsets=c_offsets,
        serverOffsets=s_offsets,
    )


# --- SMTP Tests ---

def test_smtp_inline_auth_plain():
    """SMTP AUTH PLAIN with inline credentials records cleartextAuth without credential contents."""
    stream = _make_stream(
        client_bytes=b"EHLO client.test\r\nAUTH PLAIN AHVzZXIAcGFzc3dvcmQ=\r\nQUIT\r\n",
        server_bytes=b"220 mail.test ESMTP\r\n250-mail.test\r\n250 AUTH PLAIN\r\n235 2.7.0 Authentication successful\r\n221 Bye\r\n",
        s_port=25,
    )
    rec = track_smtp(stream)
    assert len(rec.cleartextAuth) == 1
    assert rec.cleartextAuth[0].mechanism == "PLAIN"
    # Ensure no credentials/passwords stored in object dict
    assert "AHVzZXIAcGFzc3dvcmQ=" not in str(asdict(rec.cleartextAuth[0]))
    assert "password" not in str(asdict(rec.cleartextAuth[0]))


def test_smtp_challenge_response_auth():
    """SMTP AUTH LOGIN with challenge-response sequence."""
    stream = _make_stream(
        client_bytes=b"EHLO test\r\nAUTH LOGIN\r\nYWxpY2U=\r\nc2VjcmV0\r\nQUIT\r\n",
        server_bytes=b"220 banner\r\n250 AUTH LOGIN\r\n334 VXNlcm5hbWU6\r\n334 UGFzc3dvcmQ6\r\n235 OK\r\n221 Bye\r\n",
        s_port=25,
    )
    rec = track_smtp(stream)
    assert len(rec.cleartextAuth) == 1
    assert rec.cleartextAuth[0].mechanism == "LOGIN"
    assert "c2VjcmV0" not in str(asdict(rec.cleartextAuth[0]))


def test_smtp_cancelled_auth_no_exposure():
    """SMTP client cancelling AUTH with '*' must NOT report credential exposure."""
    stream = _make_stream(
        client_bytes=b"EHLO test\r\nAUTH PLAIN\r\n*\r\nQUIT\r\n",
        server_bytes=b"220 banner\r\n250 AUTH PLAIN\r\n334 \r\n501 Authentication aborted\r\n221 Bye\r\n",
        s_port=25,
    )
    rec = track_smtp(stream)
    assert len(rec.cleartextAuth) == 0


def test_smtp_truncated_auth_no_exposure():
    """SMTP capture ending after challenge without client response must not report exposure."""
    stream = _make_stream(
        client_bytes=b"EHLO test\r\nAUTH PLAIN\r\n",
        server_bytes=b"220 banner\r\n250 AUTH PLAIN\r\n334 \r\n",
        s_port=25,
    )
    rec = track_smtp(stream)
    assert len(rec.cleartextAuth) == 0


# --- IMAP Tests ---

def test_imap_login_cleartext():
    """IMAP tag LOGIN user pass records mechanism LOGIN without credential contents."""
    stream = _make_stream(
        client_bytes=b"a001 LOGIN alice SuperSecretPassword\r\na002 LOGOUT\r\n",
        server_bytes=b"* OK IMAP4rev1 Service Ready\r\na001 OK LOGIN completed\r\n* BYE\r\na002 OK LOGOUT\r\n",
        s_port=143,
    )
    rec = track_imap(stream)
    assert len(rec.cleartextAuth) == 1
    assert rec.cleartextAuth[0].mechanism == "LOGIN"
    assert "SuperSecretPassword" not in str(asdict(rec.cleartextAuth[0]))


def test_imap_cancelled_authenticate_no_exposure():
    """IMAP client cancelling AUTHENTICATE with '*' must not report credential exposure."""
    stream = _make_stream(
        client_bytes=b"a001 AUTHENTICATE PLAIN\r\n*\r\na002 LOGOUT\r\n",
        server_bytes=b"* OK IMAP ready\r\n+ \r\na001 BAD aborted\r\na002 OK Bye\r\n",
        s_port=143,
    )
    rec = track_imap(stream)
    assert len(rec.cleartextAuth) == 0


def test_imap_truncated_authenticate_no_exposure():
    """IMAP session ending after server '+' challenge without client response."""
    stream = _make_stream(
        client_bytes=b"a001 AUTHENTICATE PLAIN\r\n",
        server_bytes=b"* OK IMAP ready\r\n+ \r\n",
        s_port=143,
    )
    rec = track_imap(stream)
    assert len(rec.cleartextAuth) == 0


# --- POP3 Tests ---

def test_pop3_user_pass_cleartext():
    """POP3 USER + PASS sequence records cleartextAuth without credential contents."""
    stream = _make_stream(
        client_bytes=b"USER bob\r\nPASS MySecret123\r\nQUIT\r\n",
        server_bytes=b"+OK POP3 server ready\r\n+OK user accepted\r\n+OK pass accepted\r\n+OK Bye\r\n",
        s_port=110,
    )
    rec = track_pop3(stream)
    assert len(rec.cleartextAuth) == 2
    assert rec.cleartextAuth[0].mechanism == "USER"
    assert rec.cleartextAuth[1].mechanism == "PASS"
    assert "MySecret123" not in str(asdict(rec.cleartextAuth[1]))


def test_pop3_auth_plain_inline():
    """POP3 AUTH PLAIN with inline credentials."""
    stream = _make_stream(
        client_bytes=b"CAPA\r\nAUTH PLAIN AGJvYgBteXBhc3M=\r\nQUIT\r\n",
        server_bytes=b"+OK POP3 ready\r\n+OK\r\nSASL PLAIN\r\n.\r\n+OK Logged in\r\n+OK Bye\r\n",
        s_port=110,
    )
    rec = track_pop3(stream)
    assert len(rec.cleartextAuth) == 1
    assert rec.cleartextAuth[0].mechanism == "PLAIN"
    assert "AGJvYgBteXBhc3M=" not in str(asdict(rec.cleartextAuth[0]))


def test_pop3_cancelled_auth_no_exposure():
    """POP3 client cancelling AUTH with '*' must not report credential exposure."""
    stream = _make_stream(
        client_bytes=b"AUTH PLAIN\r\n*\r\nQUIT\r\n",
        server_bytes=b"+OK POP3 ready\r\n+ \r\n-ERR auth aborted\r\n+OK Bye\r\n",
        s_port=110,
    )
    rec = track_pop3(stream)
    assert len(rec.cleartextAuth) == 0


def test_pop3_truncated_auth_no_exposure():
    """POP3 session ending after server '+' challenge without client response."""
    stream = _make_stream(
        client_bytes=b"AUTH PLAIN\r\n",
        server_bytes=b"+OK POP3 ready\r\n+ \r\n",
        s_port=110,
    )
    rec = track_pop3(stream)
    assert len(rec.cleartextAuth) == 0


def test_pop3_rejected_auth_with_ok_greeting_no_exposure():
    """POP3 +OK greeting followed by -ERR rejection must NOT treat subsequent command as auth response."""
    stream = _make_stream(
        client_bytes=b"AUTH PLAIN\r\nCAPA\r\nQUIT\r\n",
        server_bytes=b"+OK POP3 server ready\r\n-ERR Mechanism not supported\r\n+OK Capability list follows\r\n.\r\n+OK Bye\r\n",
        s_port=110,
    )
    rec = track_pop3(stream)
    assert len(rec.cleartextAuth) == 0


def test_imap_authenticate_rejected_without_continuation_no_exposure():
    """IMAP tag AUTHENTICATE rejected with tagged NO must not treat subsequent command as credential response."""
    stream = _make_stream(
        client_bytes=b"a001 AUTHENTICATE PLAIN\r\na002 NOOP\r\na003 LOGOUT\r\n",
        server_bytes=b"* OK IMAP ready\r\na001 NO Plaintext authentication disabled\r\na002 OK Completed\r\n* BYE\r\na003 OK Logged out\r\n",
        s_port=143,
    )
    rec = track_imap(stream)
    assert len(rec.cleartextAuth) == 0
