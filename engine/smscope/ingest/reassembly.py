"""TCP stream reassembly engine."""
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Union

from engine.smscope.ingest.pcap import RawPacket, read_pcap_packets


def format_endpoint(ip: str, port: int) -> str:
    """Formats IP and port into endpoint string per docs/decisions/001-hashing-and-ids.md."""
    if ":" in ip:
        compressed = ipaddress.IPv6Address(ip).compressed.lower()
        return f"[{compressed}]:{port}"
    return f"{ip}:{port}"


def seq_diff(a: int, b: int) -> int:
    """Computes signed difference (a - b) modulo 2^32 handling sequence wrap-around."""
    return ((a - b + 0x80000000) & 0xFFFFFFFF) - 0x80000000


@dataclass
class BufferedSegment:
    seq: int
    data: bytes
    frame: int
    ts: int


class DirectionReassembler:
    """Reassembles TCP payload stream in a single direction."""

    def __init__(self, buffer_cap: int = 1000):
        self.buffer_cap = buffer_cap
        self.isn: Optional[int] = None
        self.next_seq: Optional[int] = None
        self.delivered_bytes: bytearray = bytearray()
        self.offsets: List[Tuple[int, int, int, int]] = []  # (start, end, frame, ts_sec)
        self.buffered_segments: List[BufferedSegment] = []

    def feed(self, packet: RawPacket) -> None:
        """Processes an incoming TCP packet."""
        is_syn = bool(packet.flags & 0x02)
        if is_syn:
            self.isn = (packet.seq + 1) & 0xFFFFFFFF
            self.next_seq = self.isn

        payload = packet.payload
        if not payload:
            return

        if self.next_seq is None:
            self.isn = packet.seq
            self.next_seq = packet.seq

        p_seq = packet.seq
        diff = seq_diff(p_seq, self.next_seq)

        if diff <= 0:
            # Starts at or before next_seq
            past = -diff
            if past >= len(payload):
                # Exact retransmission or already seen data: drop
                return
            new_data = payload[past:]
            start_off = len(self.delivered_bytes)
            self.delivered_bytes.extend(new_data)
            from engine.smscope.limits import check_stream_buffered_bytes
            check_stream_buffered_bytes(len(self.delivered_bytes))
            end_off = len(self.delivered_bytes)
            self.offsets.append((start_off, end_off, packet.frame_number, packet.ts_sec))
            self.next_seq = (self.next_seq + len(new_data)) & 0xFFFFFFFF
            self._drain_buffer()
        else:
            # Future segment (out-of-order gap)
            if len(self.buffered_segments) < self.buffer_cap:
                self._add_to_buffer(p_seq, payload, packet.frame_number, packet.ts_sec)

    def _add_to_buffer(self, seq: int, data: bytes, frame: int, ts: int) -> None:
        """Adds segment to out-of-order buffer preserving first-seen bytes on overlaps."""
        # Check against existing buffered segments to discard already-seen bytes
        pieces_to_add: List[Tuple[int, bytes]] = [(seq, data)]

        for existing in self.buffered_segments:
            next_pieces: List[Tuple[int, bytes]] = []
            e_start = existing.seq
            e_len = len(existing.data)

            for p_start, p_data in pieces_to_add:
                p_len = len(p_data)
                diff_start = seq_diff(p_start, e_start)

                if diff_start >= e_len or seq_diff(e_start, p_start) >= p_len:
                    # Disjoint
                    next_pieces.append((p_start, p_data))
                    continue

                # Overlap exists; existing has priority (first-seen). Keep non-overlapping parts.
                if diff_start < 0:
                    # p starts before e
                    prefix_len = -diff_start
                    next_pieces.append((p_start, p_data[:prefix_len]))

                p_end_diff = seq_diff((p_start + p_len) & 0xFFFFFFFF, (e_start + e_len) & 0xFFFFFFFF)
                if p_end_diff > 0:
                    # p extends after e
                    suffix_offset = p_len - p_end_diff
                    suffix_start = (p_start + suffix_offset) & 0xFFFFFFFF
                    next_pieces.append((suffix_start, p_data[suffix_offset:]))

            pieces_to_add = next_pieces
            if not pieces_to_add:
                break

        for p_start, p_data in pieces_to_add:
            if p_data:
                from engine.smscope.limits import check_stream_buffered_bytes
                total_buf = len(self.delivered_bytes) + sum(len(s.data) for s in self.buffered_segments) + len(p_data)
                check_stream_buffered_bytes(total_buf)
                self.buffered_segments.append(
                    BufferedSegment(seq=p_start, data=p_data, frame=frame, ts=ts)
                )

    def _drain_buffer(self) -> None:
        """Drains any buffered segments that can now be delivered."""
        while self.buffered_segments:
            # Sort by sequence distance from next_seq
            self.buffered_segments.sort(key=lambda s: seq_diff(s.seq, self.next_seq))
            cand = self.buffered_segments[0]
            diff = seq_diff(cand.seq, self.next_seq)
            if diff <= 0:
                past = -diff
                if past < len(cand.data):
                    new_data = cand.data[past:]
                    start_off = len(self.delivered_bytes)
                    self.delivered_bytes.extend(new_data)
                    from engine.smscope.limits import check_stream_buffered_bytes
                    check_stream_buffered_bytes(len(self.delivered_bytes))
                    end_off = len(self.delivered_bytes)
                    self.offsets.append((start_off, end_off, cand.frame, cand.ts))
                    self.next_seq = (self.next_seq + len(new_data)) & 0xFFFFFFFF
                self.buffered_segments.pop(0)
            else:
                # Still a gap
                break

    def is_complete(self) -> bool:
        """Returns True if no undelivered out-of-order segments remain (no gaps)."""
        return len(self.buffered_segments) == 0


@dataclass
class Stream:
    """Reassembled TCP stream."""
    index: int
    client: str
    server: str
    firstFrame: int
    firstTs: int
    complete: bool
    clientInferred: bool
    clientBytes: bytes
    serverBytes: bytes
    clientOffsets: List[Tuple[int, int, int, int]] = field(default_factory=list)
    serverOffsets: List[Tuple[int, int, int, int]] = field(default_factory=list)

    def frame_for_offset(self, direction: str, offset: int) -> int:
        """Returns 1-based frame number delivering byte at offset."""
        dir_lower = direction.lower()
        if dir_lower in ("client", "c2s"):
            offsets = self.clientOffsets
            total_len = len(self.clientBytes)
        elif dir_lower in ("server", "s2c"):
            offsets = self.serverOffsets
            total_len = len(self.serverBytes)
        else:
            raise ValueError(f"Unknown direction '{direction}'; must be 'client' or 'server'")

        if offset < 0 or offset >= total_len:
            raise IndexError(f"Offset {offset} is out of bounds for direction '{direction}' (length {total_len})")

        left, right = 0, len(offsets) - 1
        while left <= right:
            mid = (left + right) // 2
            start, end, frame, ts = offsets[mid]
            if offset < start:
                right = mid - 1
            elif offset >= end:
                left = mid + 1
            else:
                return frame

        raise IndexError(f"Offset {offset} not found in offset map")

    def ts_for_offset(self, direction: str, offset: int) -> int:
        """Returns integer epoch seconds of packet delivering byte at offset."""
        dir_lower = direction.lower()
        if dir_lower in ("client", "c2s"):
            offsets = self.clientOffsets
            total_len = len(self.clientBytes)
        elif dir_lower in ("server", "s2c"):
            offsets = self.serverOffsets
            total_len = len(self.serverBytes)
        else:
            raise ValueError(f"Unknown direction '{direction}'; must be 'client' or 'server'")

        if offset < 0 or offset >= total_len:
            raise IndexError(f"Offset {offset} is out of bounds for direction '{direction}' (length {total_len})")

        left, right = 0, len(offsets) - 1
        while left <= right:
            mid = (left + right) // 2
            start, end, frame, ts = offsets[mid]
            if offset < start:
                right = mid - 1
            elif offset >= end:
                left = mid + 1
            else:
                return ts

        raise IndexError(f"Offset {offset} not found in offset map")


class FlowTracker:
    """Tracks state and reassembly for both directions of a TCP flow."""

    def __init__(self, index: int, packet: RawPacket, ep1: str, ep2: str, buffer_cap: int = 1000):
        self.index = index
        self.first_frame = packet.frame_number
        self.first_ts = packet.ts_sec
        self.first_sender = format_endpoint(packet.src_ip, packet.src_port)
        self.first_receiver = format_endpoint(packet.dst_ip, packet.dst_port)
        self.ep1 = ep1
        self.ep2 = ep2
        self.syn_client: Optional[str] = None
        self.syn_server: Optional[str] = None
        self.dir_ep1_to_ep2 = DirectionReassembler(buffer_cap=buffer_cap)
        self.dir_ep2_to_ep1 = DirectionReassembler(buffer_cap=buffer_cap)

    def process_packet(self, packet: RawPacket) -> None:
        src_ep = format_endpoint(packet.src_ip, packet.src_port)
        dst_ep = format_endpoint(packet.dst_ip, packet.dst_port)

        is_syn = bool(packet.flags & 0x02)
        is_ack = bool(packet.flags & 0x10)

        # First SYN without ACK identifies client
        if is_syn and not is_ack and self.syn_client is None:
            self.syn_client = src_ep
            self.syn_server = dst_ep

        if src_ep == self.ep1:
            self.dir_ep1_to_ep2.feed(packet)
        else:
            self.dir_ep2_to_ep1.feed(packet)

    def to_stream(self) -> Stream:
        if self.syn_client is not None:
            client = self.syn_client
            server = self.syn_server
            client_inferred = False
        else:
            client = self.first_sender
            server = self.first_receiver
            client_inferred = True

        if client == self.ep1:
            client_bytes = bytes(self.dir_ep1_to_ep2.delivered_bytes)
            server_bytes = bytes(self.dir_ep2_to_ep1.delivered_bytes)
            client_offsets = self.dir_ep1_to_ep2.offsets
            server_offsets = self.dir_ep2_to_ep1.offsets
            complete = self.dir_ep1_to_ep2.is_complete() and self.dir_ep2_to_ep1.is_complete()
        else:
            client_bytes = bytes(self.dir_ep2_to_ep1.delivered_bytes)
            server_bytes = bytes(self.dir_ep1_to_ep2.delivered_bytes)
            client_offsets = self.dir_ep2_to_ep1.offsets
            server_offsets = self.dir_ep1_to_ep2.offsets
            complete = self.dir_ep2_to_ep1.is_complete() and self.dir_ep1_to_ep2.is_complete()

        return Stream(
            index=self.index,
            client=client,
            server=server,
            firstFrame=self.first_frame,
            firstTs=self.first_ts,
            complete=complete,
            clientInferred=client_inferred,
            clientBytes=client_bytes,
            serverBytes=server_bytes,
            clientOffsets=client_offsets,
            serverOffsets=server_offsets,
        )


def reassemble_packets(
    packets: Iterable[RawPacket],
    buffer_cap: int = 1000,
) -> List[Stream]:
    """Reassembles a stream of RawPackets into complete TCP streams."""
    flows: Dict[Tuple[str, str, str], FlowTracker] = {}

    for pkt in packets:
        ep_src = format_endpoint(pkt.src_ip, pkt.src_port)
        ep_dst = format_endpoint(pkt.dst_ip, pkt.dst_port)
        ep_pair = tuple(sorted([ep_src, ep_dst]))
        flow_key = (ep_pair[0], ep_pair[1], "tcp")

        if flow_key not in flows:
            from engine.smscope.limits import check_stream_count
            check_stream_count(len(flows) + 1)
            flows[flow_key] = FlowTracker(
                index=len(flows),
                packet=pkt,
                ep1=ep_pair[0],
                ep2=ep_pair[1],
                buffer_cap=buffer_cap,
            )

        flows[flow_key].process_packet(pkt)

    return [tracker.to_stream() for tracker in flows.values()]


def reassemble_pcap(
    pcap_path: Union[str, Path],
    buffer_cap: int = 1000,
) -> Tuple[List[Stream], Dict[str, int]]:
    """Reassembles all TCP streams in a classic PCAP file."""
    stats: Dict[str, int] = {}
    packets = read_pcap_packets(pcap_path, stats=stats)
    streams = reassemble_packets(packets, buffer_cap=buffer_cap)
    return streams, stats
