# Decision 007: TCP Ingestion, Reassembly, Overlap Resolution, and Gap Policies

## Status
Accepted

## Context
SecureMailScope passively analyzes email traffic from PCAP network captures. Network packet traces may contain packets arriving out of order, exact retransmissions, overlapping TCP segments, sequence number wrap-around, or missing packets due to network loss. To satisfy `AGENT_RULES.md` and `docs/ARCHITECTURE.md` section 4.1, the ingestion and TCP reassembly engine must produce byte-identical, deterministic results across all validator platforms without relying on floating-point arithmetic or non-deterministic data structures.

## Decisions

1. **PCAP Format & Integer Epoch Timestamps**:
   - Only classic PCAP files are supported: magic `0xa1b2c3d4` (microsecond resolution) and `0xa1b23c4d` (nanosecond resolution), supporting both big-endian and little-endian byte orders.
   - PCAPNG files (magic `0x0a0d0d0a`) and any other file formats are rejected immediately with `PcapFormatError`.
   - Timestamps are extracted directly from the 16-byte PCAP packet record headers as integer epoch seconds (`ts_sec`), preserving strict integer-only arithmetic.
   - Streaming reader: files are read frame-by-frame via generators and never loaded entirely into memory.

2. **Link Types, Encapsulation, and Filtering**:
   - Supported link types: Ethernet (`1`) and Linux cooked capture (`113`, SLL). Other link types raise `UnsupportedLinkTypeError`.
   - 802.1Q and 802.1ad (QinQ) VLAN tags (`0x8100`, `0x88a8`) are cleanly stripped.
   - IPv4 and IPv6 network layers are parsed; IPv6 extension headers (Hop-by-Hop, Routing, Fragment, Destination Options, AH, Mobility) are traversed to reach TCP.
   - IPv4 fragments (`flags_frag & 0x3FFF != 0`), IPv6 fragment packets, and non-TCP packets are counted in an ingestion statistics dictionary and skipped.
   - Frame numbering is 1-based, matching Wireshark/tshark conventions.

3. **Flow Table and Client Inference**:
   - The flow key is a normalized 5-tuple: `(min_endpoint, max_endpoint, "tcp")` with endpoints formatted per `docs/decisions/001-hashing-and-ids.md`. Both directions of a TCP connection map to the identical flow key.
   - Client determination: The sender of the first SYN packet without ACK (`SYN=1, ACK=0`) is established as the client. If no SYN packet without ACK was captured in the flow (e.g. capture started mid-connection), the sender of the flow's first captured packet is treated as the client, and `clientInferred` is set to `True`.
   - Stream `index` is the 0-based ordinal index of the flow in the capture file (reflecting the order of each flow's first appearance). `firstFrame` records the 1-based frame number of the flow's first packet.

4. **Sequence Numbers & 32-Bit Wrap-Around**:
   - Per direction, the Initial Sequence Number (ISN) is established as `(syn_seq + 1) mod 2^32` if a SYN was seen in that direction; otherwise from the sequence number of the first segment with payload in that direction.
   - 32-bit sequence wrap-around is handled using modulo $2^{32}$ signed difference arithmetic: `diff = (seq - next_seq) mod 2^32`. If `diff < 0x80000000`, the segment is in the forward sequence space; if `diff >= 0x80000000`, the segment is in the past.

5. **Overlap Resolution Policy (First-Seen Priority)**:
   - Exact retransmissions (segments whose payload sequence range is fully within already-delivered bytes) are dropped.
   - Overlapping segments: When incoming segment data overlaps already delivered bytes or buffered out-of-order bytes, the first-seen bytes are strictly preserved. Arriving segments only contribute newly observed contiguous bytes starting at `next_seq`.

6. **Out-of-Order Buffering & Cap**:
   - Out-of-order segments (where `p_seq > next_seq`) are held in a per-direction out-of-order buffer up to a configurable cap (default 1000 segments). If the cap is exceeded, excess segments are dropped.

7. **Gap Policy**:
   - If an unfillable sequence gap occurs (e.g. packet loss in scenario X03 where packets are permanently missing), the engine delivers ONLY the contiguous prefix up to the gap.
   - Buffered segments beyond the unfillable gap are not delivered.
   - The stream is marked `complete = False`. If all segments across both directions were contiguous, `complete = True`.

8. **Offset-to-Frame and Timestamp Mapping**:
   - Every delivered segment records a contiguous byte interval `(start_offset, end_offset, frame_number, ts_sec)` relative to that direction's delivered stream.
   - The stream exposes `frame_for_offset(direction, offset)` returning the 1-based frame number, and `ts_for_offset(direction, offset)` returning the integer capture epoch second.

## Consequences
- Guarantees byte-identical reassembly across operating systems matching standard TCP dissectors (tshark/Wireshark).
- Prevents TCP desynchronization attacks and ambiguity by enforcing a deterministic first-seen overlap policy.
- Flags incomplete captures reliably for downstream protocol and cryptographic analysis.
