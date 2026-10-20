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
        self.dropped_segments: int = 0
        self.dropped_bytes: int = 0
        self.fin_seen: bool = False
        self.fin_seq: Optional[int] = None
        self.rst_seen: bool = False

    def feed(self, packet: RawPacket) -> None:
        """Processes an incoming TCP packet."""
        is_syn = bool(packet.flags & 0x02)
        is_fin = bool(packet.flags & 0x01)
        is_rst = bool(packet.flags & 0x04)

        if is_rst:
            self.rst_seen = True

        if is_syn:
            if self.isn is None:
                self.isn = (packet.seq + 1) & 0xFFFFFFFF
                self.next_seq = self.isn
            elif len(self.delivered_bytes) == 0 and len(self.buffered_segments) == 0:
                self.isn = (packet.seq + 1) & 0xFFFFFFFF
                self.next_seq = self.isn

        payload = packet.payload
        p_seq = packet.seq
        p_len = len(payload)

        if is_fin:
            self.fin_seen = True
            self.fin_seq = (p_seq + p_len) & 0xFFFFFFFF

        if not payload:
            return

        if self.next_seq is None:
            self.isn = p_seq
            self.next_seq = p_seq

        diff = seq_diff(p_seq, self.next_seq)

        if diff <= 0:
            # Starts at or before next_seq
            past = -diff
            if past >= p_len:
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
            else:
                self.dropped_segments += 1
                self.dropped_bytes += p_len

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

    def is_contiguous(self) -> bool:
        """Returns True if no observed reassembly gaps, undelivered segments, or dropped bytes exist."""
        if len(self.buffered_segments) > 0 or self.dropped_segments > 0 or self.dropped_bytes > 0:
            return False
        if self.fin_seen and self.fin_seq is not None and self.next_seq is not None:
            if seq_diff(self.next_seq, self.fin_seq) < 0:
                return False
        return True

    def is_terminated(self) -> bool:
        """Returns True if capture contains evidence that the stream ended (FIN delivered or RST seen)."""
        if self.rst_seen:
            return True
        if self.fin_seen and self.fin_seq is not None and self.next_seq is not None:
            return seq_diff(self.next_seq, self.fin_seq) >= 0
        return False

    def is_complete(self) -> bool:
        """Compatibility wrapper: returns True if no observed reassembly gaps or drops."""
        return self.is_contiguous()

    def is_confirmed_complete(self) -> bool:
        """Returns True only if both contiguous (no gaps/drops) and terminated (FIN/RST observed)."""
        return self.is_contiguous() and self.is_terminated()


@dataclass
class Stream:
    """Reassembled TCP stream.

    Attributes:
        index: Sequential stream identifier.
        client: Client endpoint "IP:port".
        server: Server endpoint "IP:port".
        firstFrame: First observed frame number in stream.
        firstTs: Timestamp of first packet in stream (seconds).
        complete: Backwards-compatible indicator of payload reassembly contiguity
            (no missing sequence gaps or dropped out-of-order packets). For confirmed
            stream completion including termination teardown, use `confirmed_complete`.
        clientInferred: True if client/server direction was inferred from initial packet
            rather than observed SYN handshake.
        clientBytes: Contiguous reassembled client payload.
        serverBytes: Contiguous reassembled server payload.
        contiguous: True if no reassembly gaps or dropped packets were observed.
        terminated: True if capture contains evidence of connection termination (FIN or RST).
        confirmed_complete: True if stream is both contiguous and cleanly terminated.
        clientOffsets: Mapping of byte ranges to source frames and timestamps.
        serverOffsets: Mapping of byte ranges to source frames and timestamps.
    """
    index: int
    client: str
    server: str
    firstFrame: int
    firstTs: int
    complete: bool
    clientInferred: bool
    clientBytes: bytes
    serverBytes: bytes
    contiguous: bool = True
    terminated: bool = False
    confirmed_complete: bool = False
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
        self.initial_syn_seq: Optional[int] = None
        self.dir_ep1_to_ep2 = DirectionReassembler(buffer_cap=buffer_cap)
        self.dir_ep2_to_ep1 = DirectionReassembler(buffer_cap=buffer_cap)
        self.packets_seen: int = 0
        self.is_closed: bool = False

    def is_new_connection(self, packet: RawPacket) -> bool:
        """Determines if packet belongs to a new TCP connection on the same 5-tuple."""
        is_syn = bool(packet.flags & 0x02)
        is_ack = bool(packet.flags & 0x10)
        src_ep = format_endpoint(packet.src_ip, packet.src_port)

        # A new TCP connection on an existing tuple begins with a pure SYN
        if is_syn and not is_ack:
            if self.syn_client is None:
                # Mid-capture connection that already saw packets
                if self.packets_seen > 0:
                    return True
                return False
            # Retransmitted SYN: same client endpoint and same sequence number
            if src_ep == self.syn_client and packet.seq == self.initial_syn_seq:
                return False
            return True

        # If previous connection was terminated (RST or FIN) and a SYN arrives
        if self.is_closed and is_syn:
            return True

        return False

    def process_packet(self, packet: RawPacket) -> None:
        self.packets_seen += 1
        src_ep = format_endpoint(packet.src_ip, packet.src_port)
        dst_ep = format_endpoint(packet.dst_ip, packet.dst_port)

        is_syn = bool(packet.flags & 0x02)
        is_ack = bool(packet.flags & 0x10)
        is_rst = bool(packet.flags & 0x04)

        # First SYN without ACK identifies client
        if is_syn and not is_ack and self.syn_client is None:
            self.syn_client = src_ep
            self.syn_server = dst_ep
            self.initial_syn_seq = packet.seq

        if src_ep == self.ep1:
            self.dir_ep1_to_ep2.feed(packet)
        else:
            self.dir_ep2_to_ep1.feed(packet)

        # Update connection closure state
        if is_rst or self.dir_ep1_to_ep2.rst_seen or self.dir_ep2_to_ep1.rst_seen:
            self.is_closed = True
        elif self.dir_ep1_to_ep2.fin_seen and self.dir_ep2_to_ep1.fin_seen:
            if self.dir_ep1_to_ep2.is_complete() and self.dir_ep2_to_ep1.is_complete():
                self.is_closed = True

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
            c_dir = self.dir_ep1_to_ep2
            s_dir = self.dir_ep2_to_ep1
        else:
            client_bytes = bytes(self.dir_ep2_to_ep1.delivered_bytes)
            server_bytes = bytes(self.dir_ep1_to_ep2.delivered_bytes)
            client_offsets = self.dir_ep2_to_ep1.offsets
            server_offsets = self.dir_ep1_to_ep2.offsets
            c_dir = self.dir_ep2_to_ep1
            s_dir = self.dir_ep1_to_ep2

        contiguous = c_dir.is_contiguous() and s_dir.is_contiguous()
        terminated = c_dir.rst_seen or s_dir.rst_seen or (c_dir.is_terminated() and s_dir.is_terminated())
        confirmed_complete = contiguous and terminated

        return Stream(
            index=self.index,
            client=client,
            server=server,
            firstFrame=self.first_frame,
            firstTs=self.first_ts,
            complete=contiguous,
            clientInferred=client_inferred,
            clientBytes=client_bytes,
            serverBytes=server_bytes,
            contiguous=contiguous,
            terminated=terminated,
            confirmed_complete=confirmed_complete,
            clientOffsets=client_offsets,
            serverOffsets=server_offsets,
        )


def reassemble_packets(
    packets: Iterable[RawPacket],
    buffer_cap: int = 1000,
) -> List[Stream]:
    """Reassembles a stream of RawPackets into complete TCP streams."""
    active_flows: Dict[Tuple[str, str, str], FlowTracker] = {}
    completed_streams: List[Stream] = []
    stream_counter = 0

    for pkt in packets:
        ep_src = format_endpoint(pkt.src_ip, pkt.src_port)
        ep_dst = format_endpoint(pkt.dst_ip, pkt.dst_port)
        ep_pair = tuple(sorted([ep_src, ep_dst]))
        flow_key = (ep_pair[0], ep_pair[1], "tcp")

        if flow_key in active_flows:
            tracker = active_flows[flow_key]
            if tracker.is_new_connection(pkt):
                completed_streams.append(tracker.to_stream())
                del active_flows[flow_key]

        if flow_key not in active_flows:
            from engine.smscope.limits import check_stream_count
            check_stream_count(stream_counter + 1)
            tracker = FlowTracker(
                index=stream_counter,
                packet=pkt,
                ep1=ep_pair[0],
                ep2=ep_pair[1],
                buffer_cap=buffer_cap,
            )
            stream_counter += 1
            active_flows[flow_key] = tracker

        active_flows[flow_key].process_packet(pkt)

    for tracker in active_flows.values():
        completed_streams.append(tracker.to_stream())

    completed_streams.sort(key=lambda s: s.index)
    return completed_streams


def reassemble_pcap(
    pcap_path: Union[str, Path],
    buffer_cap: int = 1000,
) -> Tuple[List[Stream], Dict[str, int]]:
    """Reassembles all TCP streams in a classic PCAP file."""
    stats: Dict[str, int] = {}
    packets = read_pcap_packets(pcap_path, stats=stats)
    streams = reassemble_packets(packets, buffer_cap=buffer_cap)
    return streams, stats
