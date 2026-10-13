"""Streaming PCAP parser for classic PCAP format."""
import ipaddress
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Dict, Generator, Optional, Tuple, Union


class PcapError(Exception):
    """Base exception for PCAP parsing errors."""
    pass


class PcapFormatError(PcapError):
    """Raised when PCAP format or magic is invalid or unsupported (e.g. PCAPNG)."""
    pass


class UnsupportedLinkTypeError(PcapFormatError):
    """Raised when the link layer type is not Ethernet (1) or Linux SLL (113)."""
    pass


@dataclass(frozen=True)
class RawPacket:
    """Parsed packet record from PCAP."""
    frame_number: int  # 1-based frame number
    ts_sec: int  # Integer epoch seconds
    ts_usec: int  # Microsecond or nanosecond fraction
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    payload: bytes


def read_pcap_packets(
    source: Union[str, Path, BinaryIO],
    stats: Optional[Dict[str, int]] = None,
) -> Generator[RawPacket, None, None]:
    """
    Streams classic PCAP packets yielding RawPacket for TCP packets.
    Non-TCP packets and IP fragments are counted in stats and skipped.
    """
    if stats is None:
        stats = {}
    stats.setdefault("total_packets", 0)
    stats.setdefault("tcp_packets", 0)
    stats.setdefault("ip_fragments", 0)
    stats.setdefault("non_tcp_packets", 0)
    stats.setdefault("malformed_packets", 0)

    from engine.smscope.limits import check_pcap_size, check_runtime, start_runtime_timer

    start_runtime_timer()

    if isinstance(source, (str, Path)):
        p_path = Path(source)
        if p_path.exists():
            check_pcap_size(p_path.stat().st_size)
        f = open(source, "rb")
        should_close = True
    else:
        f = source
        should_close = False
        # If seekable, check size
        try:
            cur = f.tell()
            f.seek(0, 2)
            check_pcap_size(f.tell())
            f.seek(cur)
        except Exception:
            pass

    try:
        # Read 24-byte global header
        global_header = f.read(24)
        if len(global_header) == 0:
            raise PcapFormatError("Empty PCAP file: missing global header")
        if len(global_header) < 24:
            raise PcapFormatError(f"Truncated PCAP global header: expected 24 bytes, got {len(global_header)}")

        magic_bytes = global_header[:4]
        # Detect PCAPNG block type 0x0A0D0D0A
        if magic_bytes == b"\x0a\x0d\x0d\x0a":
            raise PcapFormatError("PCAPNG format (magic 0x0a0d0d0a) is not supported; classic PCAP required")

        if magic_bytes == b"\xa1\xb2\xc3\xd4":
            endian = ">"
            is_nano = False
        elif magic_bytes == b"\xd4\xc3\xb2\xa1":
            endian = "<"
            is_nano = False
        elif magic_bytes == b"\xa1\xb2\x3c\x4d":
            endian = ">"
            is_nano = True
        elif magic_bytes == b"\x4d\x3c\xb2\xa1":
            endian = "<"
            is_nano = True
        else:
            raise PcapFormatError(f"Unsupported PCAP magic number: 0x{magic_bytes.hex()}")

        magic, v_maj, v_min, thiszone, sigfigs, snaplen, link_type = struct.unpack(
            f"{endian}IHHiIII", global_header
        )

        if link_type not in (1, 113):
            raise UnsupportedLinkTypeError(
                f"Unsupported link type {link_type}; only Ethernet (1) and Linux cooked capture (113) supported"
            )

        frame_number = 0
        while True:
            rec_hdr = f.read(16)
            if not rec_hdr:
                break  # Clean EOF
            if len(rec_hdr) < 16:
                raise PcapFormatError(
                    f"Truncated PCAP record header at frame {frame_number + 1}: expected 16 bytes, got {len(rec_hdr)}"
                )

            frame_number += 1
            stats["total_packets"] += 1

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", rec_hdr)
            from engine.smscope.limits import check_pcap_size, check_runtime
            check_pcap_size(incl_len)
            if frame_number % 100 == 0:
                check_runtime()
            packet_data = f.read(incl_len)
            if len(packet_data) < incl_len:
                raise PcapFormatError(
                    f"Truncated PCAP packet data at frame {frame_number}: expected {incl_len} bytes, got {len(packet_data)}"
                )

            # Link layer parsing
            offset = 0
            if link_type == 1:
                # Ethernet II
                if len(packet_data) < 14:
                    stats["malformed_packets"] += 1
                    continue
                ethertype = struct.unpack("!H", packet_data[12:14])[0]
                offset = 14
                # Strip 802.1Q and 802.1ad (QinQ) VLAN tags
                while ethertype in (0x8100, 0x88A8):
                    if len(packet_data) < offset + 4:
                        break
                    ethertype = struct.unpack("!H", packet_data[offset + 2: offset + 4])[0]
                    offset += 4
            elif link_type == 113:
                # Linux Cooked Capture (SLL)
                if len(packet_data) < 16:
                    stats["malformed_packets"] += 1
                    continue
                ethertype = struct.unpack("!H", packet_data[14:16])[0]
                offset = 16

            # Network layer parsing
            if ethertype == 0x0800:
                # IPv4
                if len(packet_data) < offset + 20:
                    stats["malformed_packets"] += 1
                    continue
                ver_ihl = packet_data[offset]
                ver = ver_ihl >> 4
                ihl = (ver_ihl & 0x0F) * 4
                if ver != 4 or ihl < 20 or len(packet_data) < offset + ihl:
                    stats["malformed_packets"] += 1
                    continue

                flags_frag = struct.unpack("!H", packet_data[offset + 6: offset + 8])[0]
                frag_offset = flags_frag & 0x1FFF
                more_frags = bool(flags_frag & 0x2000)
                if frag_offset != 0 or more_frags:
                    stats["ip_fragments"] += 1
                    continue

                proto = packet_data[offset + 9]
                if proto != 6:  # TCP
                    stats["non_tcp_packets"] += 1
                    continue

                src_ip = socket.inet_ntoa(packet_data[offset + 12: offset + 16])
                dst_ip = socket.inet_ntoa(packet_data[offset + 16: offset + 20])
                tcp_offset = offset + ihl

            elif ethertype == 0x86DD:
                # IPv6
                if len(packet_data) < offset + 40:
                    stats["malformed_packets"] += 1
                    continue
                ver = packet_data[offset] >> 4
                if ver != 6:
                    stats["malformed_packets"] += 1
                    continue

                next_header = packet_data[offset + 6]
                src_ip = ipaddress.IPv6Address(packet_data[offset + 8: offset + 24]).compressed.lower()
                dst_ip = ipaddress.IPv6Address(packet_data[offset + 24: offset + 40]).compressed.lower()
                curr_offset = offset + 40

                # Walk extension headers
                is_frag = False
                while next_header in (0, 43, 44, 51, 60, 135):
                    if next_header == 44:  # Fragment header
                        if len(packet_data) < curr_offset + 8:
                            break
                        frag_off_flags = struct.unpack("!H", packet_data[curr_offset + 2: curr_offset + 4])[0]
                        frag_off = frag_off_flags >> 3
                        m_flag = packet_data[curr_offset + 3] & 1
                        if frag_off != 0 or m_flag:
                            is_frag = True
                        next_header = packet_data[curr_offset]
                        curr_offset += 8
                        if is_frag:
                            break
                    elif next_header == 51:  # AH header
                        if len(packet_data) < curr_offset + 8:
                            break
                        payload_len = packet_data[curr_offset + 1]
                        ext_len = (payload_len + 2) * 4
                        next_header = packet_data[curr_offset]
                        curr_offset += ext_len
                    else:  # Hop-by-Hop, Routing, Destination Options, Mobility
                        if len(packet_data) < curr_offset + 8:
                            break
                        hdr_ext_len = packet_data[curr_offset + 1]
                        ext_len = (hdr_ext_len + 1) * 8
                        next_header = packet_data[curr_offset]
                        curr_offset += ext_len

                if is_frag:
                    stats["ip_fragments"] += 1
                    continue
                if next_header != 6:  # Not TCP
                    stats["non_tcp_packets"] += 1
                    continue

                tcp_offset = curr_offset

            else:
                # Non-IP packet (ARP, etc.)
                stats["non_tcp_packets"] += 1
                continue

            # Transport layer (TCP)
            if len(packet_data) < tcp_offset + 20:
                stats["malformed_packets"] += 1
                continue

            sport, dport, seq, ack, data_offset_byte, flags, window, checksum, urg_ptr = struct.unpack(
                "!HHIIBBHHH", packet_data[tcp_offset: tcp_offset + 20]
            )
            data_offset = ((data_offset_byte >> 4) & 0x0F) * 4
            if data_offset < 20 or len(packet_data) < tcp_offset + data_offset:
                stats["malformed_packets"] += 1
                continue

            payload = packet_data[tcp_offset + data_offset:]
            stats["tcp_packets"] += 1

            yield RawPacket(
                frame_number=frame_number,
                ts_sec=ts_sec,
                ts_usec=ts_usec,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
                seq=seq,
                ack=ack,
                flags=flags,
                payload=payload,
            )
    finally:
        if should_close:
            f.close()
