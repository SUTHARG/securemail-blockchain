"""Tests for SMTP session tracking state machine (Prompt 5.3)."""
import json
from pathlib import Path

import jsonschema
import pytest

from engine.smscope.ingest.pcap import RawPacket
from engine.smscope.ingest.reassembly import Stream, reassemble_pcap
from engine.smscope.models import SessionRecord
from engine.smscope.protocols.smtp import (
    track_imap,
    track_pop3,
    track_session,
    track_smtp,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"
SCHEMAS_DIR = REPO_ROOT / "spec" / "schemas"


@pytest.fixture(scope="module")
def session_schema():
    schema_file = SCHEMAS_DIR / "session_record.json"
    with open(schema_file, "r", encoding="utf-8") as f:
        return json.load(f)


# ==============================================================================
# Acceptance Tests: S01a, S05, S06, S13
# ==============================================================================

def test_s01a_session_record(session_schema):
    """S01a: Valid STARTTLS, TLS 1.2 upgraded session."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S01a.pcap")
    assert len(streams) == 1
    stream = streams[0]

    record = track_smtp(stream)
    rec_dict = record.to_dict()

    expected_dict = {
        "sessionId": 0,
        "clientEndpoint": "172.28.0.20:45000",
        "serverEndpoint": "172.28.0.10:25",
        "protocol": "smtp",
        "protocolSource": "content",
        "transportMode": "starttls",
        "streamComplete": True,
        "firstPacketTs": stream.firstTs,
        "starttls": {
            "offered": True,
            "attempted": True,
            "outcome": "succeeded",
        },
        "cleartextAuth": [],
        "tls": None,
        "certificates": [],
    }

    assert rec_dict == expected_dict
    jsonschema.validate(instance=rec_dict, schema=session_schema)

    # Verify TLS offsets
    assert record.clientTlsStartOffset == 31  # len("EHLO mail.lab.local\r\nSTARTTLS\r\n")
    assert record.serverTlsStartOffset == 135
    assert record.tlsStartOffset == 31


def test_s05_session_record(session_schema):
    """S05: Plaintext auth, no STARTTLS offered."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S05.pcap")
    assert len(streams) == 1
    stream = streams[0]

    record = track_smtp(stream)
    rec_dict = record.to_dict()

    expected_dict = {
        "sessionId": 0,
        "clientEndpoint": "172.28.0.20:45000",
        "serverEndpoint": "172.28.0.10:25",
        "protocol": "smtp",
        "protocolSource": "content",
        "transportMode": "plaintext",
        "streamComplete": True,
        "firstPacketTs": stream.firstTs,
        "starttls": {
            "offered": False,
            "attempted": False,
            "outcome": "notOffered",
        },
        "cleartextAuth": [
            {
                "mechanism": "PLAIN",
                "packetNumber": 7,
            }
        ],
        "tls": None,
        "certificates": [],
    }

    assert rec_dict == expected_dict
    jsonschema.validate(instance=rec_dict, schema=session_schema)
    assert record.clientTlsStartOffset is None
    assert record.serverTlsStartOffset is None


def test_s06_session_record(session_schema):
    """S06: STARTTLS offered but optional, client continues in plaintext without auth."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S06.pcap")
    assert len(streams) == 1
    stream = streams[0]

    record = track_smtp(stream)
    rec_dict = record.to_dict()

    expected_dict = {
        "sessionId": 0,
        "clientEndpoint": "172.28.0.20:45000",
        "serverEndpoint": "172.28.0.10:25",
        "protocol": "smtp",
        "protocolSource": "content",
        "transportMode": "plaintext",
        "streamComplete": True,
        "firstPacketTs": stream.firstTs,
        "starttls": {
            "offered": True,
            "attempted": False,
            "outcome": "ignored",
        },
        "cleartextAuth": [],
        "tls": None,
        "certificates": [],
    }

    assert rec_dict == expected_dict
    jsonschema.validate(instance=rec_dict, schema=session_schema)


def test_s13_session_record(session_schema):
    """S13: Implicit TLS on port 465."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S13.pcap")
    assert len(streams) == 1
    stream = streams[0]

    record = track_smtp(stream)
    rec_dict = record.to_dict()

    expected_dict = {
        "sessionId": 0,
        "clientEndpoint": "172.28.0.20:45000",
        "serverEndpoint": "172.28.0.10:465",
        "protocol": "smtp",
        "protocolSource": "port",
        "transportMode": "implicitTls",
        "streamComplete": True,
        "firstPacketTs": stream.firstTs,
        "starttls": {
            "offered": False,
            "attempted": False,
            "outcome": "notOffered",
        },
        "cleartextAuth": [],
        "tls": None,
        "certificates": [],
    }

    assert rec_dict == expected_dict
    jsonschema.validate(instance=rec_dict, schema=session_schema)
    assert record.clientTlsStartOffset == 0
    assert record.serverTlsStartOffset == 0


# ==============================================================================
# Planted Credential Test
# ==============================================================================

def test_planted_credentials_never_appear_in_output():
    """Proves planted lab credentials never appear in any string or dictionary output."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S05.pcap")
    record = track_smtp(streams[0])

    serialized_dict = json.dumps(record.to_dict())
    serialized_repr = repr(record)
    serialized_str = str(record)

    forbidden_tokens = ["labuser", "LabPass-123!", "AGxhYnVzZX"]
    for token in forbidden_tokens:
        assert token not in serialized_dict, f"Credential token '{token}' found in to_dict()"
        assert token not in serialized_repr, f"Credential token '{token}' found in repr()"
        assert token not in serialized_str, f"Credential token '{token}' found in str()"


# ==============================================================================
# Edge Cases
# ==============================================================================

def test_multiline_replies():
    """Tests complex multiline replies with mixed whitespace and continuation lines."""
    server_bytes = (
        b"220-mailserver.example.com ESMTP Postfix\r\n"
        b"220-First continuation\r\n"
        b"220 Final greeting\r\n"
        b"250-mailserver.example.com\r\n"
        b"250-PIPELINING\r\n"
        b"250-SIZE 10240000\r\n"
        b"250-STARTTLS\r\n"
        b"250 ENHANCEDSTATUSCODES\r\n"
    )
    client_bytes = b"EHLO client.local\r\nQUIT\r\n"

    stream = Stream(
        index=0,
        client="10.0.0.1:50000",
        server="10.0.0.2:25",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=client_bytes,
        serverBytes=server_bytes,
        clientOffsets=[(0, len(client_bytes), 1, 1700000000)],
        serverOffsets=[(0, len(server_bytes), 2, 1700000000)],
    )

    record = track_smtp(stream)
    assert record.starttls.offered is True
    assert record.starttls.attempted is False
    assert record.starttls.outcome == "ignored"
    assert record.transportMode == "plaintext"


def test_starttls_refused_with_454():
    """Tests STARTTLS attempted by client, but server replies with 454."""
    server_bytes = (
        b"220 mailserver.example.com ESMTP\r\n"
        b"250-STARTTLS\r\n"
        b"250 DSN\r\n"
        b"454 4.7.0 TLS not available due to temporary reason\r\n"
        b"221 2.0.0 Bye\r\n"
    )
    client_bytes = (
        b"EHLO client.local\r\n"
        b"STARTTLS\r\n"
        b"QUIT\r\n"
    )

    stream = Stream(
        index=1,
        client="10.0.0.1:50000",
        server="10.0.0.2:25",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=client_bytes,
        serverBytes=server_bytes,
        clientOffsets=[(0, len(client_bytes), 1, 1700000000)],
        serverOffsets=[(0, len(server_bytes), 2, 1700000000)],
    )

    record = track_smtp(stream)
    assert record.starttls.offered is True
    assert record.starttls.attempted is True
    assert record.starttls.outcome == "refused"
    assert record.transportMode == "plaintext"
    assert record.clientTlsStartOffset is None
    assert record.serverTlsStartOffset is None


def test_missing_ehlo():
    """Tests connection where client sends HELO or MAIL FROM directly without EHLO."""
    server_bytes = (
        b"220 mailserver.example.com ESMTP\r\n"
        b"250 Ok\r\n"
        b"221 Bye\r\n"
    )
    client_bytes = (
        b"HELO client.local\r\n"
        b"QUIT\r\n"
    )

    stream = Stream(
        index=2,
        client="10.0.0.1:50000",
        server="10.0.0.2:25",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=client_bytes,
        serverBytes=server_bytes,
        clientOffsets=[(0, len(client_bytes), 1, 1700000000)],
        serverOffsets=[(0, len(server_bytes), 2, 1700000000)],
    )

    record = track_smtp(stream)
    assert record.starttls.offered is False
    assert record.starttls.attempted is False
    assert record.starttls.outcome == "notOffered"
    assert record.transportMode == "plaintext"


def test_data_body_and_bdat_skipping():
    """Tests that message bodies under DATA and BDAT with fake command strings are not parsed."""
    server_bytes = (
        b"220 mailserver.example.com ESMTP\r\n"
        b"250 Ok\r\n"
        b"354 Enter mail, end with .\r\n"
        b"250 2.0.0 Ok: queued\r\n"
        b"250 2.0.0 BDAT ok\r\n"
        b"221 Bye\r\n"
    )
    # The message body deliberately contains "AUTH PLAIN" and "STARTTLS"
    client_bytes = (
        b"EHLO client.local\r\n"
        b"DATA\r\n"
        b"Subject: Test\r\n\r\n"
        b"AUTH PLAIN fake-credentials-in-body\r\n"
        b"STARTTLS in message body\r\n"
        b".\r\n"
        b"BDAT 35 LAST\r\n"
        b"AUTH LOGIN should-be-skipped-body!!\r\n"
        b"QUIT\r\n"
    )

    stream = Stream(
        index=3,
        client="10.0.0.1:50000",
        server="10.0.0.2:25",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=client_bytes,
        serverBytes=server_bytes,
        clientOffsets=[(0, len(client_bytes), 1, 1700000000)],
        serverOffsets=[(0, len(server_bytes), 2, 1700000000)],
    )

    record = track_smtp(stream)
    # The AUTH inside DATA/BDAT bodies must NOT be registered as cleartextAuth!
    assert len(record.cleartextAuth) == 0
    assert record.starttls.attempted is False


def test_imap_and_pop3_stubs_raise_not_implemented():
    stream = Stream(
        index=4,
        client="10.0.0.1:50000",
        server="10.0.0.2:143",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=b"",
        serverBytes=b"* OK IMAP ready\r\n",
    )

    rec = track_imap(stream)
    assert rec.protocol == "imap"

    pop3_stream = Stream(
        index=5,
        client="10.0.0.1:50000",
        server="10.0.0.2:110",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=b"",
        serverBytes=b"+OK POP3 ready\r\n",
    )

    pop_rec = track_pop3(pop3_stream)
    assert pop_rec.protocol == "pop3"

    session_rec = track_session(pop3_stream)
    assert session_rec.protocol == "pop3"
