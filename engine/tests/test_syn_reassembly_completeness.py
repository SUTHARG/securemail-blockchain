"""Regression tests for TCP SYN retransmission and stream completeness (Requirement 8).

Verifies:
1. Retransmitted SYN before payload does not corrupt ISN / next_seq.
2. Retransmitted SYN after payload has begun must NOT reset next_seq or delivered bytes.
3. Tuple reuse creates a new connection generation without clobbering preceding stream.
4. FIN with missing preceding data leaves gap and marks stream incomplete.
5. RST packet records rst_seen and terminates flow.
6. Out-of-order gap reassembles cleanly once missing segment arrives.
7. Buffer-cap drops record dropped_segments and make stream incomplete.
8. Capture ending without FIN/RST: payload integrity without teardown.
"""
from engine.smscope.ingest.pcap import RawPacket
from engine.smscope.ingest.reassembly import DirectionReassembler, reassemble_packets, Stream


def _make_pkt(src_ip, src_port, dst_ip, dst_port, seq, ack, flags, payload=b"", frame=1, ts=1000):
    return RawPacket(
        frame_number=frame,
        ts_sec=ts,
        ts_usec=0,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        seq=seq,
        ack=ack,
        flags=flags,
        payload=payload,
    )


def test_retransmitted_syn_before_payload():
    """Retransmitted SYN before data packets are received maintains valid next_seq."""
    d = DirectionReassembler()
    # First SYN at seq 1000
    pkt1 = _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1000, ack=0, flags=0x02, frame=1)
    d.feed(pkt1)
    assert d.next_seq == 1001

    # Retransmitted SYN at seq 1000
    pkt2 = _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1000, ack=0, flags=0x02, frame=2)
    d.feed(pkt2)
    assert d.next_seq == 1001

    # Subsequent payload arrives at seq 1001
    pkt3 = _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1001, ack=0, flags=0x18, payload=b"EHLO test\r\n", frame=3)
    d.feed(pkt3)
    assert bytes(d.delivered_bytes) == b"EHLO test\r\n"
    assert d.next_seq == 1001 + len(b"EHLO test\r\n")


def test_retransmitted_syn_after_payload_does_not_reset():
    """Retransmitted SYN after data flow has started must NOT reset next_seq or delivered bytes."""
    d = DirectionReassembler()
    pkt1 = _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1000, ack=0, flags=0x02, frame=1)
    d.feed(pkt1)

    pkt2 = _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1001, ack=0, flags=0x18, payload=b"DATA-1", frame=2)
    d.feed(pkt2)
    assert bytes(d.delivered_bytes) == b"DATA-1"
    expected_next = 1001 + len(b"DATA-1")
    assert d.next_seq == expected_next

    # Spurious / late retransmitted SYN arrives now
    pkt_syn_late = _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1000, ack=0, flags=0x02, frame=3)
    d.feed(pkt_syn_late)
    # Delivered bytes and next_seq MUST NOT be reset!
    assert bytes(d.delivered_bytes) == b"DATA-1"
    assert d.next_seq == expected_next

    # Next data segment continues smoothly
    pkt3 = _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=expected_next, ack=0, flags=0x18, payload=b"DATA-2", frame=4)
    d.feed(pkt3)
    assert bytes(d.delivered_bytes) == b"DATA-1DATA-2"


def test_out_of_order_gap_and_drain():
    """Out-of-order segment is buffered and drains when gap is filled."""
    d = DirectionReassembler()
    d.next_seq = 1000

    # Segment 2 arrives first (gap between 1000 and 1010)
    pkt_future = _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1010, ack=0, flags=0x18, payload=b"WORLD", frame=1)
    d.feed(pkt_future)
    assert len(d.delivered_bytes) == 0
    assert len(d.buffered_segments) == 1

    # Segment 1 arrives filling the gap
    pkt_now = _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1000, ack=0, flags=0x18, payload=b"0123456789", frame=2)
    d.feed(pkt_now)
    assert bytes(d.delivered_bytes) == b"0123456789WORLD"
    assert len(d.buffered_segments) == 0


def test_buffer_cap_drops_and_incompleteness():
    """When out-of-order segments exceed buffer cap, drops are recorded and stream is incomplete."""
    d = DirectionReassembler(buffer_cap=2)
    d.next_seq = 1000

    # Add 2 future segments (fills buffer_cap)
    d.feed(_make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1050, ack=0, flags=0x18, payload=b"A" * 10, frame=1))
    d.feed(_make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1070, ack=0, flags=0x18, payload=b"B" * 10, frame=2))
    assert d.dropped_segments == 0

    # 3rd future segment exceeds cap -> dropped
    d.feed(_make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1090, ack=0, flags=0x18, payload=b"C" * 10, frame=3))
    assert d.dropped_segments == 1
    assert d.dropped_bytes == 10
    assert d.is_complete() is False


def test_fin_with_unresolved_gaps():
    """FIN observed while gap remains leaves stream incomplete."""
    d = DirectionReassembler()
    d.next_seq = 1000

    # Future data segment + FIN
    d.feed(_make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1050, ack=0, flags=0x19, payload=b"END", frame=1))
    assert d.fin_seen is True
    # Gap exists (1000 to 1050 missing)
    assert d.is_complete() is False


def test_rst_packet_records_rst_seen():
    """RST flag sets rst_seen flag on direction reassembler."""
    d = DirectionReassembler()
    pkt_rst = _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1000, ack=0, flags=0x04, frame=1)
    d.feed(pkt_rst)
    assert d.rst_seen is True


def test_tuple_reuse_creates_separate_streams():
    """Tuple reuse with new SYN after connection termination creates distinct streams."""
    pkts = [
        # Connection 1: SYN, Data, RST
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1000, ack=0, flags=0x02, frame=1),
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1001, ack=0, flags=0x18, payload=b"conn1", frame=2),
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1006, ack=0, flags=0x04, frame=3),
        # Connection 2: New SYN, Data
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=5000, ack=0, flags=0x02, frame=4),
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=5001, ack=0, flags=0x18, payload=b"conn2", frame=5),
    ]
    streams = reassemble_packets(pkts)
    assert len(streams) == 2
    assert streams[0].clientBytes == b"conn1"
    assert streams[1].clientBytes == b"conn2"


def test_capture_ending_without_fin_preserves_payload_and_marks_contiguous_not_complete():
    """Capture ending mid-flow without FIN/RST reassembles contiguous payload with contiguous=True, confirmed_complete=False."""
    pkts = [
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1000, ack=0, flags=0x02, frame=1),
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1001, ack=0, flags=0x18, payload=b"EHLO client\r\n", frame=2),
        _make_pkt("10.0.0.2", 25, "10.0.0.1", 1234, seq=2000, ack=1014, flags=0x18, payload=b"250 OK\r\n", frame=3),
    ]
    streams = reassemble_packets(pkts)
    assert len(streams) == 1
    s = streams[0]
    assert s.clientBytes == b"EHLO client\r\n"
    assert s.serverBytes == b"250 OK\r\n"
    # Contiguous sequence within capture window is contiguous, but NOT a confirmed complete stream
    assert s.contiguous is True
    assert s.terminated is False
    assert s.confirmed_complete is False


def test_stream_with_fin_teardown_is_complete():
    """Stream with graceful FIN teardown in both directions has contiguous=True, terminated=True, confirmed_complete=True."""
    pkts = [
        # Handshake
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1000, ack=0, flags=0x02, frame=1),
        _make_pkt("10.0.0.2", 25, "10.0.0.1", 1234, seq=2000, ack=1001, flags=0x12, frame=2),
        # Data
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1001, ack=2001, flags=0x18, payload=b"QUIT\r\n", frame=3),
        _make_pkt("10.0.0.2", 25, "10.0.0.1", 1234, seq=2001, ack=1007, flags=0x18, payload=b"221 Bye\r\n", frame=4),
        # Client FIN
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1007, ack=2010, flags=0x11, frame=5),
        # Server FIN
        _make_pkt("10.0.0.2", 25, "10.0.0.1", 1234, seq=2010, ack=1008, flags=0x11, frame=6),
    ]
    streams = reassemble_packets(pkts)
    assert len(streams) == 1
    s = streams[0]
    assert s.contiguous is True
    assert s.terminated is True
    assert s.confirmed_complete is True


def test_stream_with_rst_teardown_is_complete():
    """Stream terminated by RST packet has contiguous=True, terminated=True, confirmed_complete=True."""
    pkts = [
        # Handshake
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1000, ack=0, flags=0x02, frame=1),
        # Data
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1001, ack=0, flags=0x18, payload=b"DATA", frame=2),
        # Server resets connection
        _make_pkt("10.0.0.2", 25, "10.0.0.1", 1234, seq=2000, ack=1005, flags=0x04, frame=3),
    ]
    streams = reassemble_packets(pkts)
    assert len(streams) == 1
    s = streams[0]
    assert s.contiguous is True
    assert s.terminated is True
    assert s.confirmed_complete is True


def test_stream_with_unresolved_gaps_is_not_contiguous_or_complete():
    """Stream with missing sequence gaps is not contiguous and not complete even with FIN."""
    pkts = [
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1000, ack=0, flags=0x02, frame=1),
        # Gap: seq 1001..1019 missing! Only seq 1020 arrives
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1020, ack=0, flags=0x18, payload=b"FUTURE", frame=2),
        # FIN arrives
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1026, ack=0, flags=0x11, frame=3),
        _make_pkt("10.0.0.2", 25, "10.0.0.1", 1234, seq=2000, ack=0, flags=0x11, frame=4),
    ]
    streams = reassemble_packets(pkts)
    assert len(streams) == 1
    s = streams[0]
    assert s.contiguous is False
    assert s.confirmed_complete is False


def test_stream_with_buffer_cap_drops_is_not_contiguous_or_complete():
    """Stream where out-of-order packets exceeded buffer cap and were dropped is not contiguous or complete."""
    pkts = [
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1000, ack=0, flags=0x02, frame=1),
        # Future packets filling and exceeding buffer cap
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1050, ack=0, flags=0x18, payload=b"P1", frame=2),
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1060, ack=0, flags=0x18, payload=b"P2", frame=3),
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1070, ack=0, flags=0x18, payload=b"P3", frame=4),
        # RST arrives
        _make_pkt("10.0.0.2", 25, "10.0.0.1", 1234, seq=2000, ack=0, flags=0x04, frame=5),
    ]
    # Use buffer_cap=2 so 3rd future segment is dropped
    streams = reassemble_packets(pkts, buffer_cap=2)
    assert len(streams) == 1
    s = streams[0]
    assert s.contiguous is False
    assert s.confirmed_complete is False


def test_truncated_capture_without_teardown_is_not_complete():
    """Truncated capture cut off mid-session has contiguous=True, terminated=False, confirmed_complete=False."""
    pkts = [
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1000, ack=0, flags=0x02, frame=1),
        _make_pkt("10.0.0.2", 25, "10.0.0.1", 1234, seq=5000, ack=1001, flags=0x12, frame=2),
        _make_pkt("10.0.0.1", 1234, "10.0.0.2", 25, seq=1001, ack=5001, flags=0x10, frame=3),
        _make_pkt("10.0.0.2", 25, "10.0.0.1", 1234, seq=5001, ack=1001, flags=0x18, payload=b"220 server.local\r\n", frame=4),
        # Capture stops abruptly here
    ]
    streams = reassemble_packets(pkts)
    assert len(streams) == 1
    s = streams[0]
    assert s.serverBytes == b"220 server.local\r\n"
    assert s.contiguous is True
    assert s.terminated is False
    assert s.confirmed_complete is False
