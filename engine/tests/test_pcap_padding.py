"""Regression test for stripping Ethernet padding from TCP payloads (Issue 9).

Verifies that parse_pcap respects IP total_length / IPv6 payload_length
and strips trailing Ethernet padding (e.g. frames padded to 60/64 bytes)
so that non-protocol padding bytes never contaminate TCP stream reassembly.
"""
import io
import struct
import pytest

from engine.smscope.ingest.pcap import read_pcap_packets


def create_minimal_pcap_with_padding(payload_data: bytes, padding_len: int = 15) -> bytes:
    """Construct classic PCAP in memory with an IPv4 TCP packet containing trailing padding."""
    # PCAP Global Header (24 bytes, big-endian, magic 0xa1b2c3d4, snaplen 65535, link_type Ethernet=1)
    global_hdr = struct.pack(">IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    # 1. Ethernet Header (14 bytes): dest MAC (6), src MAC (6), EtherType IPv4=0x0800
    eth_hdr = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack("!H", 0x0800)

    # 2. IPv4 Header (20 bytes)
    # Total length = 20 (IPv4) + 20 (TCP) + len(payload_data)
    ip_total_len = 20 + 20 + len(payload_data)
    # ver_ihl=0x45, dscp_ecn=0, total_len, id=1, flags_frag=0, ttl=64, proto=6 (TCP), checksum=0, src=10.0.0.1, dst=10.0.0.2
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_len,
        1,
        0,
        64,
        6,
        0,
        bytes([10, 0, 0, 1]),
        bytes([10, 0, 0, 2]),
    )

    # 3. TCP Header (20 bytes)
    # sport=12345, dport=25, seq=1000, ack=0, data_offset=5 (20 bytes) -> 0x50, flags=0x18 (PSH, ACK), window=65535, checksum=0, urg=0
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        12345,
        25,
        1000,
        0,
        (5 << 4),
        0x18,
        65535,
        0,
        0,
    )

    # 4. Ethernet Padding (trailing bytes after IP packet)
    padding = b"\x00" * padding_len

    packet_data = eth_hdr + ip_hdr + tcp_hdr + payload_data + padding

    # PCAP Packet Record Header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
    incl_len = len(packet_data)
    record_hdr = struct.pack(">IIII", 1600000000, 0, incl_len, incl_len)

    return global_hdr + record_hdr + packet_data


def test_ethernet_padding_stripped_from_tcp_payload():
    """Verify that trailing Ethernet padding is completely stripped from packet.payload."""
    expected_payload = b"EHLO client.example.com\r\n"
    # Ethernet frame with 20 bytes of trailing padding
    pcap_bytes = create_minimal_pcap_with_padding(expected_payload, padding_len=20)

    f = io.BytesIO(pcap_bytes)
    packets = list(read_pcap_packets(f))

    assert len(packets) == 1
    pkt = packets[0]
    assert pkt.payload == expected_payload
    assert len(pkt.payload) == len(expected_payload)
    assert not pkt.payload.endswith(b"\x00")
