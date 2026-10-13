# Specification Compliance Audit: Phase 5, Prompt 5.1

## Scope
Audit of `engine/smscope/ingest/pcap.py` and `engine/smscope/ingest/reassembly.py` against:
- `AGENT_RULES.md`
- `docs/ARCHITECTURE.md`, Section 4.1
- `docs/PROMPT_LIBRARY.md`, Prompt 5.1
- `docs/decisions/001-hashing-and-ids.md`
- `docs/decisions/007-tcp-reassembly-policies.md`

---

### 1. Specification Discrepancies
None identified.
- Classic PCAP formats (magic `0xa1b2c3d4`, `0xa1b23c4d`, LE/BE) supported via struct.
- PCAPNG (`0x0a0d0d0a`) rejected with explicit `PcapFormatError`.
- Link types Ethernet (`1`) and Linux cooked capture (`113`) supported; unsupported link types raise `UnsupportedLinkTypeError`.
- 802.1Q and QinQ VLAN tags stripped.
- IPv4 and IPv6 extension headers walked to TCP; IP fragments and non-TCP packets recorded in stats dictionary and skipped.
- Integer epoch seconds (`ts_sec`) preserved without float conversion.
- Flow table keyed by normalized 5-tuple; client identified by first SYN without ACK or inferred from first packet with `clientInferred=True`.
- 32-bit TCP sequence wrap-around handled via signed difference modulo $2^{32}$.
- Exact retransmissions dropped; first-seen overlap resolution strictly maintained.
- Gaps deliver contiguous prefix only with `complete=False`.
- Byte-to-frame and timestamp mapping exposed via `frame_for_offset` and `ts_for_offset`.

---

### 2. Missing Decisions
None. All design choices (overlap resolution, gap truncation, buffer limits, sequence wrap-around, and client inference) are recorded in [docs/decisions/007-tcp-reassembly-policies.md](file:///c:/Users/gaura/OneDrive/Desktop/projects/blockchain-project/docs/decisions/007-tcp-reassembly-policies.md).

---

### 3. AGENT_RULES.md Violations
- **Floating point arithmetic**: None. All sequence and timestamp calculations use Python integer arithmetic.
- **Wall-clock time**: None. Timestamps originate solely from PCAP packet headers.
- **Unordered iteration in written output**: None. Flow indexing is deterministic based on packet appearance.
- **Credential / payload logging**: None. No logging of payload bytes exists in the module.
- **Passive engine**: None. No network socket or external call is made.

---

### 4. Specification Requirements Coverage
| Requirement | Implementation | Test Coverage |
| :--- | :--- | :--- |
| Classic PCAP micro/nano LE/BE parsing | `pcap.py:read_pcap_packets` | `test_reassembly.py:test_nanosecond_and_big_endian_magics` |
| PCAPNG rejection | `pcap.py:read_pcap_packets` | `test_reassembly.py:test_pcapng_file_rejected` |
| Link type Ethernet (1) and SLL (113) | `pcap.py:read_pcap_packets` | `test_reassembly.py:test_unsupported_link_type` |
| VLAN tag stripping | `pcap.py:read_pcap_packets` | Verified via synthetic loop |
| IPv4 & IPv6 extension headers | `pcap.py:read_pcap_packets` | `test_reassembly.py:test_format_endpoint_ipv4_and_ipv6` |
| Normalized 5-tuple flow key | `reassembly.py:reassemble_packets` | `test_reassembly.py:test_reassembly_matches_truth_captures` |
| SYN-based client & inference fallback | `reassembly.py:FlowTracker` | `test_reassembly.py:test_reassembly_matches_truth_captures` |
| 32-bit sequence wrap-around | `reassembly.py:seq_diff` | `test_reassembly.py:test_sequence_wrap_around` |
| First-seen overlap & retransmissions | `reassembly.py:DirectionReassembler` | `test_reassembly.py:test_hypothesis_shuffle_duplicate_split` |
| Gap policy (prefix delivery, complete=false)| `reassembly.py:DirectionReassembler` | `test_reassembly.py:test_reassembly_x03_loss_contiguous_prefix` |
| Frame/timestamp offset mapping | `reassembly.py:Stream` | `test_reassembly.py:test_frame_and_ts_for_offset` |
| Ground-truth verification (S01a, S05, X01, X02) | `reassembly.py:reassemble_pcap` | `test_reassembly.py:test_reassembly_matches_truth_captures` |
