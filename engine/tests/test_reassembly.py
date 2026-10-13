"""Tests for PCAP parsing and TCP reassembly."""
import io
import json
import struct
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

from engine.smscope.ingest.pcap import (
    PcapFormatError,
    RawPacket,
    UnsupportedLinkTypeError,
    read_pcap_packets,
)
from engine.smscope.ingest.reassembly import (
    DirectionReassembler,
    Stream,
    format_endpoint,
    reassemble_packets,
    reassemble_pcap,
    seq_diff,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"
TRUTH_DIR = REPO_ROOT / "eval" / "truth"


def make_classic_pcap_bytes(magic=0xA1B2C3D4, link_type=1, records=None, endian="<"):
    """Helper to synthesize PCAP files in memory."""
    buf = io.BytesIO()
    # 24-byte global header
    buf.write(struct.pack(f"{endian}IHHiIII", magic, 2, 4, 0, 0, 65535, link_type))
    if records:
        for ts_sec, ts_usec, pkt_data in records:
            buf.write(struct.pack(f"{endian}IIII", ts_sec, ts_usec, len(pkt_data), len(pkt_data)))
            buf.write(pkt_data)
    return buf.getvalue()


# ==============================================================================
# PCAP Parser Tests
# ==============================================================================

def test_empty_pcap_file():
    buf = io.BytesIO(b"")
    with pytest.raises(PcapFormatError, match="Empty PCAP file"):
        list(read_pcap_packets(buf))


def test_truncated_global_header():
    buf = io.BytesIO(b"\xd4\xc3\xb2\xa1\x02\x00")
    with pytest.raises(PcapFormatError, match="Truncated PCAP global header"):
        list(read_pcap_packets(buf))


def test_pcapng_file_rejected():
    buf = io.BytesIO(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
    with pytest.raises(PcapFormatError, match="PCAPNG format"):
        list(read_pcap_packets(buf))


def test_unknown_magic_rejected():
    buf = io.BytesIO(b"\xaa\xbb\xcc\xdd" + b"\x00" * 20)
    with pytest.raises(PcapFormatError, match="Unsupported PCAP magic number"):
        list(read_pcap_packets(buf))


def test_unsupported_link_type():
    data = make_classic_pcap_bytes(link_type=12)  # Raw IP
    buf = io.BytesIO(data)
    with pytest.raises(UnsupportedLinkTypeError, match="Unsupported link type 12"):
        list(read_pcap_packets(buf))


def test_truncated_record_header():
    base = make_classic_pcap_bytes()
    truncated = base + b"\x01\x02\x03\x04"  # 4 bytes instead of 16
    with pytest.raises(PcapFormatError, match="Truncated PCAP record header"):
        list(read_pcap_packets(io.BytesIO(truncated)))


def test_truncated_packet_payload():
    base = make_classic_pcap_bytes()
    # Record header claiming 50 bytes, but only 10 bytes provided
    rec = struct.pack("<IIII", 1700000000, 0, 50, 50) + b"\x00" * 10
    with pytest.raises(PcapFormatError, match="Truncated PCAP packet data"):
        list(read_pcap_packets(io.BytesIO(base + rec)))


def test_nanosecond_and_big_endian_magics():
    # Big-endian nanosecond magic: 0xa1b23c4d
    data_be_nano = make_classic_pcap_bytes(magic=0xA1B23C4D, link_type=1, endian=">")
    pkts = list(read_pcap_packets(io.BytesIO(data_be_nano)))
    assert pkts == []

    # Little-endian nanosecond magic: 0xa1b23c4d
    data_le_nano = make_classic_pcap_bytes(magic=0xA1B23C4D, link_type=1, endian="<")
    pkts = list(read_pcap_packets(io.BytesIO(data_le_nano)))
    assert pkts == []


def test_format_endpoint_ipv4_and_ipv6():
    assert format_endpoint("192.168.1.1", 25) == "192.168.1.1:25"
    assert format_endpoint("2001:0db8:0000:0000:0000:0000:0000:0001", 587) == "[2001:db8::1]:587"


# ==============================================================================
# Ground-Truth Comparison Tests
# ==============================================================================

@pytest.mark.parametrize("scenario", ["S01a", "S05", "X01", "X02"])
def test_reassembly_matches_truth_captures(scenario):
    pcap_path = CAPTURES_DIR / f"{scenario}.pcap"
    truth_path = TRUTH_DIR / f"{scenario}.json"

    assert pcap_path.exists(), f"Missing {pcap_path}"
    assert truth_path.exists(), f"Missing {truth_path}"

    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    streams, stats = reassemble_pcap(pcap_path)

    assert len(streams) == 1, f"Expected 1 stream, got {len(streams)}"
    stream = streams[0]

    # Look up connection in truth
    conn_key = list(truth["connections"].keys())[0]
    expected_conn = truth["connections"][conn_key]

    assert stream.client == expected_conn["clientEndpoint"]
    assert stream.server == expected_conn["serverEndpoint"]
    assert stream.firstFrame == expected_conn["firstFrame"]
    assert stream.clientInferred == expected_conn["clientInferred"]
    assert stream.complete is True

    expected_client_bytes = bytes.fromhex(expected_conn["clientBytesHex"])
    expected_server_bytes = bytes.fromhex(expected_conn["serverBytesHex"])

    assert stream.clientBytes == expected_client_bytes
    assert stream.serverBytes == expected_server_bytes


def test_reassembly_x03_loss_contiguous_prefix():
    pcap_path = CAPTURES_DIR / "X03.pcap"
    truth_path = TRUTH_DIR / "X03.json"

    assert pcap_path.exists()
    assert truth_path.exists()

    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    streams, stats = reassemble_pcap(pcap_path)

    assert len(streams) == 1
    stream = streams[0]

    # In X03, client stream has packet loss, creating an unfillable gap
    assert stream.complete is False
    conn_key = list(truth["connections"].keys())[0]
    expected_conn = truth["connections"][conn_key]

    assert stream.client == expected_conn["clientEndpoint"]
    assert stream.server == expected_conn["serverEndpoint"]
    # Server had no loss
    assert stream.serverBytes == bytes.fromhex(expected_conn["serverBytesHex"])

    # Client delivered contiguous prefix before the 40-byte drop
    # In truth, wireshark put "[40 bytes missing in capture file]"
    # Hex of "[40 bytes missing in capture file]" is 5b3430...
    marker = b"[40 bytes missing in capture file]"
    raw_truth_client = bytes.fromhex(expected_conn["clientBytesHex"])
    prefix_expected = raw_truth_client.split(marker)[0]

    assert stream.clientBytes == prefix_expected


# ==============================================================================
# Frame and Offset Mapping Tests
# ==============================================================================

def test_frame_and_ts_for_offset():
    pcap_path = CAPTURES_DIR / "S01a.pcap"
    streams, _ = reassemble_pcap(pcap_path)
    stream = streams[0]

    # First byte of clientBytes should map to a valid frame and timestamp
    frame_0 = stream.frame_for_offset("client", 0)
    ts_0 = stream.ts_for_offset("client", 0)
    assert frame_0 >= 1
    assert ts_0 > 0

    # Last byte of clientBytes
    last_idx = len(stream.clientBytes) - 1
    frame_last = stream.frame_for_offset("client", last_idx)
    assert frame_last >= frame_0

    # Bounds check
    with pytest.raises(IndexError):
        stream.frame_for_offset("client", -1)
    with pytest.raises(IndexError):
        stream.frame_for_offset("client", len(stream.clientBytes))

    # Invalid direction
    with pytest.raises(ValueError):
        stream.frame_for_offset("invalid_dir", 0)


# ==============================================================================
# Sequence Wrap-Around Tests
# ==============================================================================

def test_sequence_wrap_around():
    reassembler = DirectionReassembler()
    # ISN close to 2^32 - 1
    isn = 0xFFFFFFF0
    reassembler.isn = isn
    reassembler.next_seq = isn

    p1 = RawPacket(1, 100, 0, "1.1.1.1", "2.2.2.2", 1000, 25, isn, 0, 0x10, b"ABCDEF")
    # Wrap-around across 0
    p2_seq = (isn + len(b"ABCDEF")) & 0xFFFFFFFF  # 0xFFFFFFF6
    p2 = RawPacket(2, 100, 0, "1.1.1.1", "2.2.2.2", 1000, 25, p2_seq, 0, 0x10, b"1234567890XYZ")
    p3_seq = (p2_seq + len(b"1234567890XYZ")) & 0xFFFFFFFF  # Wraps around past 0!
    p3 = RawPacket(3, 100, 0, "1.1.1.1", "2.2.2.2", 1000, 25, p3_seq, 0, 0x10, b"WRAPPED_PAYLOAD")

    # Feed out of order: p3, then p1, then p2
    reassembler.feed(p3)
    assert len(reassembler.delivered_bytes) == 0
    assert len(reassembler.buffered_segments) == 1

    reassembler.feed(p1)
    assert bytes(reassembler.delivered_bytes) == b"ABCDEF"

    reassembler.feed(p2)
    assert bytes(reassembler.delivered_bytes) == b"ABCDEF" + b"1234567890XYZ" + b"WRAPPED_PAYLOAD"
    assert reassembler.is_complete() is True


# ==============================================================================
# Hypothesis Property Tests (200 examples)
# ==============================================================================

@settings(max_examples=200)
@given(
    payload=st.binary(min_size=10, max_size=500),
    cuts=st.lists(st.integers(min_value=1, max_value=499), min_size=1, max_size=10),
    order=st.lists(st.integers(min_value=0, max_value=20), min_size=1, max_size=30),
    duplicate_chance=st.booleans(),
)
def test_hypothesis_shuffle_duplicate_split(payload, cuts, order, duplicate_chance):
    """
    Proves that arbitrary segment slicing, shuffling, and duplication
    deterministically produce the exact original payload with complete=True.
    """
    valid_cuts = sorted(list(set(c for c in cuts if 0 < c < len(payload))))
    chunks = []
    prev = 0
    for c in valid_cuts:
        chunks.append((prev, payload[prev:c]))
        prev = c
    chunks.append((prev, payload[prev:]))

    isn = 50000
    packets = []
    for idx, (offset, chunk_data) in enumerate(chunks):
        pkt_seq = (isn + offset) & 0xFFFFFFFF
        packets.append(RawPacket(
            frame_number=idx + 1,
            ts_sec=1700000000 + idx,
            ts_usec=0,
            src_ip="172.28.0.20",
            dst_ip="172.28.0.10",
            src_port=45000,
            dst_port=25,
            seq=pkt_seq,
            ack=1000,
            flags=0x10,
            payload=chunk_data,
        ))

    # Permute according to order indices
    shuffled_packets = []
    for o in order:
        chosen_pkt = packets[o % len(packets)]
        shuffled_packets.append(chosen_pkt)
    # Ensure all original packets appear at least once
    shuffled_packets.extend(packets)

    reassembler = DirectionReassembler()
    reassembler.isn = isn
    reassembler.next_seq = isn

    for pkt in shuffled_packets:
        reassembler.feed(pkt)

    assert bytes(reassembler.delivered_bytes) == payload
    assert reassembler.is_complete() is True
    # Verify continuous offset mapping
    assert len(reassembler.offsets) > 0
    total_mapped = sum(end - start for start, end, _, _ in reassembler.offsets)
    assert total_mapped == len(payload)
