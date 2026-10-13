"""Tests for POP3 session tracking state machine (Tier 2 / Prompt T2.2)."""
import json
from pathlib import Path

import jsonschema
import pytest

from engine.smscope.ingest.reassembly import Stream, reassemble_pcap
from engine.smscope.protocols.pop3 import track_pop3

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"
SCHEMAS_DIR = REPO_ROOT / "spec" / "schemas"


@pytest.fixture(scope="module")
def session_schema():
    schema_file = SCHEMAS_DIR / "session_record.json"
    if schema_file.exists():
        with open(schema_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def test_s23_pop3_stls(session_schema):
    """S23: Valid POP3 STLS upgraded session on port 110."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S23.pcap")
    assert len(streams) == 1
    stream = streams[0]

    record = track_pop3(stream)
    assert record.protocol == "pop3"
    assert record.transportMode == "starttls"
    assert record.starttls.offered is True
    assert record.starttls.attempted is True
    assert record.starttls.outcome == "succeeded"
    assert record.clientTlsStartOffset is not None
    assert record.serverTlsStartOffset is not None
    assert len(record.cleartextAuth) == 0

    if session_schema:
        jsonschema.validate(instance=record.to_dict(), schema=session_schema)


def test_s24_pop3_cleartext_user_pass(session_schema):
    """S24: POP3 cleartext USER and PASS session with no TLS on port 110."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S24.pcap")
    assert len(streams) == 1
    stream = streams[0]

    record = track_pop3(stream)
    assert record.protocol == "pop3"
    assert record.transportMode == "plaintext"
    assert record.starttls.offered is False
    assert record.starttls.attempted is False
    assert record.starttls.outcome == "notOffered"
    assert len(record.cleartextAuth) == 2
    assert record.cleartextAuth[0].mechanism == "USER"
    assert record.cleartextAuth[1].mechanism == "PASS"

    if session_schema:
        jsonschema.validate(instance=record.to_dict(), schema=session_schema)


def test_s25_pop3_implicit_tls(session_schema):
    """S25: POP3 implicit TLS session on port 995."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S25.pcap")
    assert len(streams) == 1
    stream = streams[0]

    record = track_pop3(stream)
    assert record.protocol == "pop3"
    assert record.transportMode == "implicitTls"
    assert record.starttls.offered is False
    assert record.starttls.attempted is False
    assert record.starttls.outcome == "notOffered"
    assert record.clientTlsStartOffset == 0
    assert record.serverTlsStartOffset == 0
    assert len(record.cleartextAuth) == 0

    if session_schema:
        jsonschema.validate(instance=record.to_dict(), schema=session_schema)


def test_pop3_zero_credential_leak():
    """Verify planted credential strings never leak into session records."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S24.pcap")
    record = track_pop3(streams[0])
    rec_json = json.dumps(record.to_dict())

    for forbidden in ["labuser", "LabPass-123!"]:
        assert forbidden not in rec_json


def test_pop3_auth_plain_extraction():
    """Synthetic stream testing AUTH PLAIN mechanism extraction."""
    client_data = b"CAPA\r\nAUTH PLAIN AGxhYnVzZXIAVmFiUGFzcy0xMjMh\r\n"
    server_data = b"+OK Dovecot ready.\r\n+OK Capability list follows\r\nSASL PLAIN\r\n.\r\n+OK Logged in\r\n"

    stream = Stream(
        index=88,
        client="10.0.0.1:50000",
        server="10.0.0.2:110",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=client_data,
        serverBytes=server_data,
    )

    record = track_pop3(stream)
    assert record.protocol == "pop3"
    assert len(record.cleartextAuth) == 1
    assert record.cleartextAuth[0].mechanism == "PLAIN"


def test_pop3_stls_refused():
    """Synthetic stream testing -ERR response resulting in refused STLS."""
    client_data = b"STLS\r\n"
    server_data = b"+OK Dovecot ready.\r\n-ERR TLS unavailable\r\n"

    stream = Stream(
        index=89,
        client="10.0.0.1:50000",
        server="10.0.0.2:110",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=client_data,
        serverBytes=server_data,
    )

    record = track_pop3(stream)
    assert record.starttls.attempted is True
    assert record.starttls.outcome == "refused"
    assert record.transportMode == "plaintext"
