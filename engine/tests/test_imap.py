"""Tests for IMAP session tracking state machine (Tier 2 / Prompt T2.1)."""
import json
from pathlib import Path

import jsonschema
import pytest

from engine.smscope.ingest.reassembly import Stream, reassemble_pcap
from engine.smscope.models import SessionRecord
from engine.smscope.protocols.imap import track_imap
from engine.smscope.protocols.identify import ProtocolIdentification

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


def test_s20_imap_starttls(session_schema):
    """S20: Valid IMAP STARTTLS upgraded session on port 143."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S20.pcap")
    assert len(streams) == 1
    stream = streams[0]

    record = track_imap(stream)
    assert record.protocol == "imap"
    assert record.transportMode == "starttls"
    assert record.starttls.offered is True
    assert record.starttls.attempted is True
    assert record.starttls.outcome == "succeeded"
    assert record.clientTlsStartOffset is not None
    assert record.serverTlsStartOffset is not None
    assert len(record.cleartextAuth) == 0

    if session_schema:
        jsonschema.validate(instance=record.to_dict(), schema=session_schema)


def test_s21_imap_cleartext_login(session_schema):
    """S21: IMAP cleartext LOGIN session with no TLS on port 143."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S21.pcap")
    assert len(streams) == 1
    stream = streams[0]

    record = track_imap(stream)
    assert record.protocol == "imap"
    assert record.transportMode == "plaintext"
    assert record.starttls.offered is False
    assert record.starttls.attempted is False
    assert record.starttls.outcome == "notOffered"
    assert len(record.cleartextAuth) == 1
    assert record.cleartextAuth[0].mechanism == "LOGIN"

    if session_schema:
        jsonschema.validate(instance=record.to_dict(), schema=session_schema)


def test_s22_imap_implicit_tls(session_schema):
    """S22: IMAP implicit TLS session on port 993."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S22.pcap")
    assert len(streams) == 1
    stream = streams[0]

    record = track_imap(stream)
    assert record.protocol == "imap"
    assert record.transportMode == "implicitTls"
    assert record.starttls.offered is False
    assert record.starttls.attempted is False
    assert record.starttls.outcome == "notOffered"
    assert record.clientTlsStartOffset == 0
    assert record.serverTlsStartOffset == 0
    assert len(record.cleartextAuth) == 0

    if session_schema:
        jsonschema.validate(instance=record.to_dict(), schema=session_schema)


def test_imap_zero_credential_leak():
    """Verify planted credential strings never leak into session records."""
    streams, _ = reassemble_pcap(CAPTURES_DIR / "S21.pcap")
    record = track_imap(streams[0])
    rec_json = json.dumps(record.to_dict())

    for forbidden in ["labuser", "LabPass-123!", "TGFiUGFzcy0xMjMh"]:
        assert forbidden not in rec_json


def test_imap_authenticate_plain():
    """Synthetic stream testing AUTHENTICATE PLAIN mechanism extraction."""
    client_data = b"A01 CAPABILITY\r\nA02 AUTHENTICATE PLAIN AGxhYnVzZXIAVmFiUGFzcy0xMjMh\r\n"
    server_data = b"* OK IMAP4rev1 Server ready\r\n* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\nA01 OK Completed\r\nA02 OK Logged in\r\n"

    stream = Stream(
        index=99,
        client="10.0.0.1:50000",
        server="10.0.0.2:143",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=client_data,
        serverBytes=server_data,
    )

    record = track_imap(stream)
    assert record.protocol == "imap"
    assert len(record.cleartextAuth) == 1
    assert record.cleartextAuth[0].mechanism == "PLAIN"


def test_imap_starttls_refused():
    """Synthetic stream testing tagged NO/BAD response resulting in refused STARTTLS."""
    client_data = b"A01 STARTTLS\r\n"
    server_data = b"* OK IMAP4rev1 ready\r\n* CAPABILITY IMAP4rev1 STARTTLS\r\nA01 NO TLS not available\r\n"

    stream = Stream(
        index=100,
        client="10.0.0.1:50000",
        server="10.0.0.2:143",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=client_data,
        serverBytes=server_data,
    )

    record = track_imap(stream)
    assert record.starttls.offered is True
    assert record.starttls.attempted is True
    assert record.starttls.outcome == "refused"
    assert record.transportMode == "plaintext"
