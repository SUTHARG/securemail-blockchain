"""Tests for Stream Completion Semantics in SecureMailScope.

Validates the distinct meanings of:
1. Contiguous payload: streamContiguous (no sequence gaps / drops observed)
2. Connection termination: streamTerminated (clean FIN handshake or RST observed)
3. Confirmed complete stream: confirmedComplete (contiguous AND properly terminated)
4. Useful partial payloads preserved from truncated captures (confirmedComplete=False, payload preserved)
5. Model serialization to JSON schema (both baseline and extended dicts)
6. Deserialization from JSON into SessionRecord
"""
import json
from pathlib import Path
import pytest
import jsonschema

from engine.smscope.models import SessionRecord, StarttlsInfo
from engine.smscope.ingest.reassembly import Stream


SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "spec" / "schemas"


def load_schema(name: str) -> dict:
    with open(SCHEMAS_DIR / f"{name}.json", "r", encoding="utf-8") as f:
        return json.load(f)


def test_complete_stream_semantics():
    """Stream with contiguous bytes and clean FIN/RST termination."""
    stream = Stream(
        index=1,
        client="10.0.0.1:50000",
        server="192.168.1.1:25",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=b"EHLO client.test\r\nQUIT\r\n",
        serverBytes=b"220 mail.test ESMTP\r\n221 2.0.0 Bye\r\n",
        contiguous=True,
        terminated=True,
        confirmed_complete=True,
    )
    rec = SessionRecord(
        sessionId=stream.index,
        clientEndpoint=stream.client,
        serverEndpoint=stream.server,
        protocol="smtp",
        protocolSource="content",
        transportMode="plaintext",
        streamComplete=stream.contiguous,
        firstPacketTs=stream.firstTs,
        starttls=StarttlsInfo(offered=False, attempted=False, outcome="notOffered"),
        stream=stream,
    )

    assert rec.streamContiguous is True
    assert rec.streamTerminated is True
    assert rec.confirmedComplete is True
    assert rec.streamComplete is True

    # Extended serialization
    ext = rec.to_extended_dict()
    assert ext["streamContiguous"] is True
    assert ext["streamTerminated"] is True
    assert ext["confirmedComplete"] is True
    assert ext["streamComplete"] is True

    # Schema validation
    schema = load_schema("session_record")
    jsonschema.validate(instance=ext, schema=schema)


def test_contiguous_stream_no_fin_semantics():
    """Stream with contiguous bytes but capture ended before connection termination (no FIN/RST)."""
    stream = Stream(
        index=2,
        client="10.0.0.1:50001",
        server="192.168.1.1:25",
        firstFrame=1,
        firstTs=1700000000,
        complete=True,
        clientInferred=False,
        clientBytes=b"EHLO client.test\r\nMAIL FROM:<alice@test>\r\n",
        serverBytes=b"220 mail.test ESMTP\r\n250-mail.test\r\n250 2.1.0 Ok\r\n",
        contiguous=True,
        terminated=False,
        confirmed_complete=False,
    )
    rec = SessionRecord(
        sessionId=stream.index,
        clientEndpoint=stream.client,
        serverEndpoint=stream.server,
        protocol="smtp",
        protocolSource="content",
        transportMode="plaintext",
        streamComplete=stream.contiguous,
        firstPacketTs=stream.firstTs,
        starttls=StarttlsInfo(offered=False, attempted=False, outcome="notOffered"),
        stream=stream,
    )

    # Contiguity is True (no lost packets), but connection termination was not observed
    assert rec.streamContiguous is True
    assert rec.streamTerminated is False
    assert rec.confirmedComplete is False
    assert rec.streamComplete is True

    ext = rec.to_extended_dict()
    assert ext["streamContiguous"] is True
    assert ext["streamTerminated"] is False
    assert ext["confirmedComplete"] is False
    schema = load_schema("session_record")
    jsonschema.validate(instance=ext, schema=schema)


def test_sequence_gaps_stream_semantics():
    """Stream with sequence gaps / lost packets."""
    stream = Stream(
        index=3,
        client="10.0.0.1:50002",
        server="192.168.1.1:25",
        firstFrame=1,
        firstTs=1700000000,
        complete=False,
        clientInferred=False,
        clientBytes=b"EHLO client.test\r\n",
        serverBytes=b"220 mail.test ESMTP\r\n",
        contiguous=False,
        terminated=True,  # FIN seen, but bytes had gaps
        confirmed_complete=False,
    )
    rec = SessionRecord(
        sessionId=stream.index,
        clientEndpoint=stream.client,
        serverEndpoint=stream.server,
        protocol="smtp",
        protocolSource="content",
        transportMode="plaintext",
        streamComplete=stream.contiguous,
        firstPacketTs=stream.firstTs,
        starttls=StarttlsInfo(offered=False, attempted=False, outcome="notOffered"),
        stream=stream,
    )

    assert rec.streamContiguous is False
    assert rec.streamTerminated is True
    assert rec.confirmedComplete is False
    assert rec.streamComplete is False

    ext = rec.to_extended_dict()
    assert ext["streamContiguous"] is False
    assert ext["streamTerminated"] is True
    assert ext["confirmedComplete"] is False
    schema = load_schema("session_record")
    jsonschema.validate(instance=ext, schema=schema)


def test_truncated_payload_preserved_semantics():
    """Stream truncated mid-session preserves available payload and metadata."""
    stream = Stream(
        index=4,
        client="10.0.0.1:50003",
        server="192.168.1.1:143",
        firstFrame=1,
        firstTs=1700000000,
        complete=False,
        clientInferred=False,
        clientBytes=b"a001 CAPABILITY\r\na002 STARTTLS\r\n",
        serverBytes=b"* OK IMAP4rev1 Service Ready\r\n* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\na001 OK Completed\r\n",
        contiguous=True,
        terminated=False,
        confirmed_complete=False,
    )
    # The payload is preserved and usable for protocol inspection
    assert len(stream.clientBytes) > 0
    assert b"STARTTLS" in stream.clientBytes
    assert len(stream.serverBytes) > 0

    rec = SessionRecord(
        sessionId=stream.index,
        clientEndpoint=stream.client,
        serverEndpoint=stream.server,
        protocol="imap",
        protocolSource="content",
        transportMode="plaintext",
        streamComplete=stream.contiguous,
        firstPacketTs=stream.firstTs,
        starttls=StarttlsInfo(offered=True, attempted=True, outcome="interrupted"),
        stream=stream,
    )

    assert rec.streamContiguous is True
    assert rec.streamTerminated is False
    assert rec.confirmedComplete is False
    # Payload analysis still works and is not discarded
    assert rec.starttls.offered is True
    assert rec.starttls.attempted is True


def test_serialization_and_deserialization():
    """Test round-trip serialization and backward compatibility."""
    rec = SessionRecord(
        sessionId=42,
        clientEndpoint="192.168.1.50:52123",
        serverEndpoint="10.0.0.5:993",
        protocol="imap",
        protocolSource="port",
        transportMode="implicitTls",
        streamComplete=True,
        firstPacketTs=1710000000,
        starttls=StarttlsInfo(offered=False, attempted=False, outcome="notOffered"),
        streamContiguous=True,
        streamTerminated=True,
        confirmedComplete=True,
    )

    # 1. Baseline serialization (golden compatible legacy mode)
    base_dict = rec.to_dict(include_extended=False)
    assert "streamContiguous" not in base_dict
    assert base_dict["streamComplete"] is True

    # 2. Extended serialization
    ext_dict = rec.to_extended_dict()
    assert ext_dict["streamContiguous"] is True
    assert ext_dict["streamTerminated"] is True
    assert ext_dict["confirmedComplete"] is True
    assert ext_dict["streamComplete"] is True

    # 3. Deserialization from extended dict
    rehydrated_ext = SessionRecord.from_dict(ext_dict)
    assert rehydrated_ext.streamContiguous is True
    assert rehydrated_ext.streamTerminated is True
    assert rehydrated_ext.confirmedComplete is True

    # 4. Deserialization from legacy baseline dict (no extended keys)
    rehydrated_base = SessionRecord.from_dict(base_dict)
    assert rehydrated_base.streamContiguous is True
    assert rehydrated_base.streamTerminated is False
    assert rehydrated_base.confirmedComplete is False
