# Spec-Compliance Audit: Tier 2 - Prompt T2.6 (Limits, Fuzzing, Sandbox Check)

## Scope Audited
- `engine/smscope/limits.py`
- `engine/smscope/cli.py`
- `engine/smscope/ingest/pcap.py`
- `engine/smscope/ingest/reassembly.py`
- `engine/smscope/tls/records.py`
- `engine/smscope/tls/handshake.py`
- `engine/smscope/certs/analyze.py`
- `scripts/fuzz_engine.py`
- `scripts/sandbox_check.py`
- `scripts/sandbox_check.sh`
- `engine/tests/test_limits.py`
- `engine/tests/test_fuzz_regression.py`
- `engine/tests/test_sandbox.py`

---

## 1. Differences from Specification
None. All requirements of Prompt T2.6 and sections 4.1 to 4.5 and 9 are satisfied:
- Hard limits configured for PCAP size (100MB), streams (10,000), buffered bytes per stream (10MB), TLS record length (18,432), certificate length (65,536), handshake message length (131,072), and runtime (60s).
- Any limit breach raises `LimitExceededError` and causes CLI to exit immediately with exit code 3, printing the breached limit to stderr.
- Fuzz testing tool applies seeded random byte mutations, truncations, and length corruptions in-process, verifying zero crashes, zero hangs, and runtime strictly under limits.
- Sandbox check verifies passive operation (no outbound network access), non-root privileges, read-only root filesystem, and output directory writability.

---

## 2. Undefined Choices Missing from `docs/decisions/`
None. Configurable environment variables for limits (`SMSCOPE_MAX_PCAP_SIZE`, etc.) provide standard override capabilities while maintaining deterministic defaults.

---

## 3. AGENT_RULES.md Violations
- Floats in Merkle tree/consensus outputs: **Zero**.
- Wall-clock time in hashed outputs: **Zero** (timestamps derived from integer PCAP epoch seconds; runtime watchdog timer is non-hashed operational safety only).
- Unordered iterations in written output: **Zero**.
- Credential / payload logging: **Zero**.
- Network calls inside the engine: **Zero**.

---

## 4. Test Coverage Verification
| Component / Requirement | Test Suite | Result |
|---|---|---|
| PCAP size limit (>100MB) | `engine/tests/test_limits.py::test_pcap_size_limit` | PASS |
| Stream count limit (>10,000) | `engine/tests/test_limits.py::test_stream_count_limit` | PASS |
| Buffered bytes limit (>10MB) | `engine/tests/test_limits.py::test_stream_buffered_bytes_limit` | PASS |
| TLS record length limit (>18,432) | `engine/tests/test_limits.py::test_tls_record_length_limit` | PASS |
| Handshake message length (>131,072) | `engine/tests/test_limits.py::test_handshake_message_length_limit` | PASS |
| Certificate length (>65,536) | `engine/tests/test_limits.py::test_certificate_length_limit` | PASS |
| Runtime watchdog (>60s) | `engine/tests/test_limits.py::test_runtime_limit` | PASS |
| CLI exit code 3 on limit breach | `engine/tests/test_limits.py::test_cli_exit_code_3_on_breach` | PASS |
| Fuzzing regression: None offset | `engine/tests/test_fuzz_regression.py::test_regression_parse_tls_records_none_offset` | PASS |
| Fuzzing regression: Corrupt DER ASN.1 | `engine/tests/test_fuzz_regression.py::test_regression_analyze_certificate_chain_invalid_asn1` | PASS |
| Sandbox network isolation | `engine/tests/test_sandbox.py::test_sandbox_network_isolated` | PASS |
| Sandbox non-root check | `engine/tests/test_sandbox.py::test_sandbox_non_root` | PASS |
| Sandbox filesystem read-only | `engine/tests/test_sandbox.py::test_sandbox_filesystem_read_only` | PASS |
| Full engine test suite | 245 test cases | 245/245 PASS |
| Full backend test suite | 33 test cases | 33/33 PASS |
| Evaluation ground truth | `eval/compare_labels.py` (29 scenarios) | 29/29 PASS |

**Audit Status:** PASS.
