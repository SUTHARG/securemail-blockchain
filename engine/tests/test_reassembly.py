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


# ==============================================================================
# Port Reuse, SYN Retransmission, Mid-Capture & Incomplete Stream Tests
# ==============================================================================

def test_port_reuse_creates_separate_streams():
    """Two separate connections reusing the exact same 5-tuple must produce distinct streams."""
    c_ip, s_ip = "192.168.1.50", "192.168.1.10"
    c_port, s_port = 54321, 25

    pkts = [
        # Connection 1: 3-way handshake + data + FIN/ACK
        RawPacket(1, 1000, 0, c_ip, s_ip, c_port, s_port, 100, 0, 0x02, b""),          # SYN
        RawPacket(2, 1001, 0, s_ip, c_ip, s_port, c_port, 500, 101, 0x12, b""),        # SYN-ACK
        RawPacket(3, 1002, 0, c_ip, s_ip, c_port, s_port, 101, 501, 0x10, b""),        # ACK
        RawPacket(4, 1003, 0, c_ip, s_ip, c_port, s_port, 101, 501, 0x18, b"HELO c1\r\n"), # Data
        RawPacket(5, 1004, 0, s_ip, c_ip, s_port, c_port, 501, 110, 0x18, b"250 ok\r\n"),  # Data
        RawPacket(6, 1005, 0, c_ip, s_ip, c_port, s_port, 110, 509, 0x11, b""),        # FIN-ACK
        RawPacket(7, 1006, 0, s_ip, c_ip, s_port, c_port, 509, 111, 0x11, b""),        # FIN-ACK
        RawPacket(8, 1007, 0, c_ip, s_ip, c_port, s_port, 111, 510, 0x10, b""),        # ACK

        # Connection 2: New connection on the same 5-tuple (new SYN with seq=2000)
        RawPacket(9, 2000, 0, c_ip, s_ip, c_port, s_port, 2000, 0, 0x02, b""),         # SYN
        RawPacket(10, 2001, 0, s_ip, c_ip, s_port, c_port, 9000, 2001, 0x12, b""),     # SYN-ACK
        RawPacket(11, 2002, 0, c_ip, s_ip, c_port, s_port, 2001, 9001, 0x10, b""),     # ACK
        RawPacket(12, 2003, 0, c_ip, s_ip, c_port, s_port, 2001, 9001, 0x18, b"HELO c2\r\n"), # Data
        RawPacket(13, 2004, 0, s_ip, c_ip, s_port, c_port, 9001, 2010, 0x18, b"250 ok\r\n"),  # Data
        RawPacket(14, 2005, 0, c_ip, s_ip, c_port, s_port, 2010, 9009, 0x14, b""),     # RST
    ]

    streams = reassemble_packets(pkts)
    assert len(streams) == 2, f"Expected 2 distinct streams for port reuse, got {len(streams)}"

    # Stream 0
    assert streams[0].index == 0
    assert streams[0].firstFrame == 1
    assert streams[0].clientBytes == b"HELO c1\r\n"
    assert streams[0].serverBytes == b"250 ok\r\n"
    assert streams[0].complete is True

    # Stream 1
    assert streams[1].index == 1
    assert streams[1].firstFrame == 9
    assert streams[1].clientBytes == b"HELO c2\r\n"
    assert streams[1].serverBytes == b"250 ok\r\n"
    assert streams[1].complete is True


def test_retransmitted_syn_does_not_create_duplicate_stream():
    """SYN retransmissions must not create duplicate streams."""
    c_ip, s_ip = "192.168.1.50", "192.168.1.10"
    c_port, s_port = 54322, 25

    pkts = [
        # Client sends SYN, retransmits it 3 times before server replies
        RawPacket(1, 1000, 0, c_ip, s_ip, c_port, s_port, 500, 0, 0x02, b""),
        RawPacket(2, 1001, 0, c_ip, s_ip, c_port, s_port, 500, 0, 0x02, b""),
        RawPacket(3, 1002, 0, c_ip, s_ip, c_port, s_port, 500, 0, 0x02, b""),
        # Server replies SYN-ACK
        RawPacket(4, 1003, 0, s_ip, c_ip, s_port, c_port, 800, 501, 0x12, b""),
        RawPacket(5, 1004, 0, c_ip, s_ip, c_port, s_port, 501, 801, 0x10, b""),
        RawPacket(6, 1005, 0, c_ip, s_ip, c_port, s_port, 501, 801, 0x18, b"HELO single\r\n"),
    ]

    streams = reassemble_packets(pkts)
    assert len(streams) == 1
    assert streams[0].clientBytes == b"HELO single\r\n"
    assert streams[0].complete is True


def test_buffer_cap_overflow_marks_stream_incomplete():
    """When out-of-order buffer cap is reached, dropped packets must cause complete=False."""
    reassembler = DirectionReassembler(buffer_cap=2)
    isn = 1000
    reassembler.isn = isn
    reassembler.next_seq = isn

    # Expected next_seq is 1000.
    # Feed 3 out-of-order future packets with gaps.
    p1 = RawPacket(1, 100, 0, "1.1.1.1", "2.2.2.2", 1000, 25, 2000, 0, 0x10, b"GAP1")
    p2 = RawPacket(2, 100, 0, "1.1.1.1", "2.2.2.2", 1000, 25, 3000, 0, 0x10, b"GAP2")
    p3 = RawPacket(3, 100, 0, "1.1.1.1", "2.2.2.2", 1000, 25, 4000, 0, 0x10, b"GAP3")

    reassembler.feed(p1)  # Buffer has 1 item
    reassembler.feed(p2)  # Buffer has 2 items (cap reached)
    reassembler.feed(p3)  # Over cap! Must be dropped, not added

    assert reassembler.dropped_segments == 1
    assert reassembler.dropped_bytes == len(b"GAP3")
    assert reassembler.is_complete() is False

    # Now deliver the missing prefix (seq=1000..3000) so p1 and p2 can drain
    prefix = RawPacket(4, 100, 0, "1.1.1.1", "2.2.2.2", 1000, 25, 1000, 0, 0x10, b"A" * 1000)
    reassembler.feed(prefix)

    # Even if buffered_segments drained, dropped_segments remains > 0 -> must still be False!
    assert reassembler.is_complete() is False


def test_unresolved_gap_at_end_of_capture():
    """If segments remain in buffer at end of capture, stream is incomplete."""
    reassembler = DirectionReassembler(buffer_cap=10)
    isn = 1000
    reassembler.isn = isn
    reassembler.next_seq = isn

    # Missing seq 1000..1500, we only receive seq 1500..1510
    future = RawPacket(1, 100, 0, "1.1.1.1", "2.2.2.2", 1000, 25, 1500, 0, 0x10, b"FUTURE_DATA")
    reassembler.feed(future)

    assert len(reassembler.buffered_segments) == 1
    assert reassembler.is_complete() is False


def test_mid_capture_start_then_syn():
    """A flow that starts mid-capture without SYN, then receives a SYN, separates cleanly."""
    c_ip, s_ip = "10.0.0.1", "10.0.0.2"
    c_port, s_port = 40000, 25

    pkts = [
        # Mid-capture connection 1: starts directly with ACK and data (no SYN)
        RawPacket(1, 100, 0, c_ip, s_ip, c_port, s_port, 1000, 500, 0x18, b"MID_CAPTURE_1\r\n"),
        # New connection with SYN
        RawPacket(2, 200, 0, c_ip, s_ip, c_port, s_port, 50000, 0, 0x02, b""),
        RawPacket(3, 201, 0, s_ip, c_ip, s_port, c_port, 80000, 50001, 0x12, b""),
        RawPacket(4, 202, 0, c_ip, s_ip, c_port, s_port, 50001, 80001, 0x18, b"SECOND_CONN\r\n"),
    ]

    streams = reassemble_packets(pkts)
    assert len(streams) == 2
    assert streams[0].clientBytes == b"MID_CAPTURE_1\r\n"
    assert streams[1].clientBytes == b"SECOND_CONN\r\n"
