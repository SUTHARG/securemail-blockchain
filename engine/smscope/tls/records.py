"""TLS record layer parsing and defragmentation."""
import struct
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple


# TLS Record Content Types (RFC 5246 / RFC 8446)
CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20
CONTENT_TYPE_ALERT = 21
CONTENT_TYPE_HANDSHAKE = 22
CONTENT_TYPE_APPLICATION_DATA = 23


@dataclass(frozen=True)
class TlsRecord:
    """Parsed TLS record."""
    content_type: int
    version: int
    length: int
    payload: bytes
    stream_offset: int  # Absolute byte offset in the underlying stream
    frame: int          # Frame number delivering the record header


@dataclass(frozen=True)
class TlsParseError:
    """Non-fatal parse error entry."""
    kind: str
    offset: int
    frame: int


@dataclass(frozen=True)
class TlsAlert:
    """Cleartext TLS alert."""
    level: int  # 1 = warning, 2 = fatal
    description: int
    offset: int
    frame: int


def parse_tls_records(
    stream_bytes: bytes,
    start_offset: int,
    frame_lookup: Callable[[int], int],
) -> Tuple[List[TlsRecord], List[TlsParseError], List[TlsAlert], int]:
    """
    Parses consecutive TLS records from a byte stream starting at start_offset.
    Returns: (records, parse_errors, alerts, encrypted_record_count).
    Parsing stops after ChangeCipherSpec (type 20).
    Malformed lengths produce TlsParseError entries and never raise exceptions.
    """
    records: List[TlsRecord] = []
    errors: List[TlsParseError] = []
    alerts: List[TlsAlert] = []
    encrypted_record_count = 0

    if start_offset is None or start_offset < 0:
        return (records, errors, alerts, 0)

    curr = start_offset
    total_len = len(stream_bytes)
    is_encrypted = False

    while curr < total_len:
        frame = frame_lookup(curr)

        if is_encrypted:
            # Beyond encryption point: count records without inspecting payloads
            if total_len - curr < 5:
                break
            rec_type, rec_ver, rec_len = struct.unpack("!BHH", stream_bytes[curr:curr + 5])
            from engine.smscope.limits import check_tls_record_length
            check_tls_record_length(rec_len)
            if total_len - curr < 5 + rec_len:
                encrypted_record_count += 1
                break
            encrypted_record_count += 1
            curr += 5 + rec_len
            continue

        # In cleartext phase
        if total_len - curr < 5:
            # Truncated record header
            errors.append(TlsParseError(kind="truncated", offset=curr, frame=frame))
            break

        rec_type, rec_ver, rec_len = struct.unpack("!BHH", stream_bytes[curr:curr + 5])
        from engine.smscope.limits import check_tls_record_length
        check_tls_record_length(rec_len)

        # Bounds check declared record length
        if total_len - curr < 5 + rec_len:
            errors.append(TlsParseError(kind="truncated", offset=curr, frame=frame))
            break

        payload = stream_bytes[curr + 5 : curr + 5 + rec_len]
        record = TlsRecord(
            content_type=rec_type,
            version=rec_ver,
            length=rec_len,
            payload=payload,
            stream_offset=curr,
            frame=frame,
        )
        records.append(record)

        # Inspect alerts
        if rec_type == CONTENT_TYPE_ALERT and len(payload) >= 2:
            alerts.append(TlsAlert(level=payload[0], description=payload[1], offset=curr, frame=frame))

        # ChangeCipherSpec marks transition to encrypted application/handshake data
        if rec_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC:
            is_encrypted = True

        curr += 5 + rec_len

    return records, errors, alerts, encrypted_record_count
