# Specification Compliance Audit: Phase 5, Prompt 5.6

## Scope
Audit of `engine/smscope/certs/analyze.py`, `engine/tests/test_certs.py`, and related configurations against:
- `AGENT_RULES.md`
- `docs/ARCHITECTURE.md`, Section 4.5
- `docs/PROMPT_LIBRARY.md`, Prompt 5.6
- `docs/decisions/012-certificate-validation-policies.md`

---

### 1. Specification Discrepancies
None identified.
- Certificate extraction:
  - Loads each DER certificate from TLS `Certificate` handshake message.
  - Extracts `sha256` lowercase hex fingerprint, `subject`, `issuer`, `notBefore` and `notAfter` (integer epoch seconds), `keyAlgorithm` (`RSA`, `EC`, `Ed25519`, `Ed448`, `DSA`), `keySize` in bits, `signatureAlgorithm`, `san` (dNSName and iPAddress lists), `isCa` boolean, and `verdicts` (lexicographically sorted strings).
- Validity interval evaluation:
  - Strictly evaluated against the capture timestamp (integer seconds) of the packet carrying the `Certificate` message, never the host machine's wall clock.
  - Emits `"expired"` if `capture_ts > notAfter`; `"notYetValid"` if `capture_ts < notBefore`.
- Weak key & signature evaluation:
  - Emits `"weakKey"` if RSA key $< 2048$ bits or EC key $< 224$ bits.
  - Emits `"weakSignature"` if MD5 or SHA-1 is used in signature algorithm on a non-root certificate.
- Deterministic chain construction & anchoring:
  - Anchors in configurable trust store directory/file (`trustStorePath`, default `lab/ca/out/client_trust.crt`) reading files in deterministic sorted filename order.
  - Verifies signature at each link using the issuer's public key and enforces `isCa = True` on issuer certificates.
  - Emits `"valid"` when path anchors to trusted root and not expired/notYetValid.
  - Emits `"unknownIssuer"` when chain is incomplete or anchor is absent from trust store; strictly distinguishes `unknownIssuer` from invalid/corrupt certificates.
  - Emits `"selfSigned"` when subject equals issuer and self-signature validates.
- SNI name matching (RFC 6125):
  - Compares SNI strictly against Subject Alternative Names (`san`).
  - Supports exact DNS match and single-label leftmost wildcard (`*.example.com`).
  - Supports IP address matching against `iPAddress` SANs.
  - Strictly prohibits fallback to Subject Common Name (`CN`).
  - If SNI is omitted in ClientHello, name check is marked not evaluable (no mismatch verdict generated).
  - If SNI is present and fails to match any SAN, records `"hostnameMismatch"`.
- Output:
  - Emits `List[CertificateInfo]` with sorted verdicts list matching `spec/schemas/session_record.json`.

---

### 2. Missing Decisions
None. All parsing, validation, time reference, trust store loading, and name matching rules are formally documented in [docs/decisions/012-certificate-validation-policies.md](file:///c:/Users/gaura/OneDrive/Desktop/projects/blockchain-project/docs/decisions/012-certificate-validation-policies.md).

---

### 3. AGENT_RULES.md Violations
- **Floating point arithmetic**: None.
- **Wall-clock time**: None. All temporal comparisons use integer `capture_ts_sec`.
- **Unordered iteration in written output**: None. Verdicts, SANs, and certificate lists are deterministically sorted.
- **Credential / payload logging**: None.
- **Passive engine**: None. Engine runs 100% offline with local trust store.

---

### 4. Specification Requirements Coverage
| Requirement | Implementation | Test Coverage |
| :--- | :--- | :--- |
| DER certificate extraction & properties | `analyze.py:analyze_certificate_chain` | `test_certs.py:test_acceptance_s01a` |
| Time-reference policy (capture timestamp) | `analyze.py:analyze_certificate_chain` | `test_certs.py:test_time_reference_policy` |
| RFC 6125 SNI matching (wildcard & IP SANs) | `analyze.py:check_sni_match` | `test_certs.py:test_sni_wildcard_and_ip_matching` |
| Weak key detection (RSA < 2048, EC < 224) | `analyze.py:analyze_certificate_chain` | `test_certs.py:test_weak_keys_and_signatures` |
| Weak signature detection (MD5, SHA-1) | `analyze.py:analyze_certificate_chain` | `test_certs.py:test_weak_keys_and_signatures` |
| Self-signed vs unknown issuer | `analyze.py:analyze_certificate_chain` | `test_certs.py:test_self_signed_and_untrusted_issuer` |
| Acceptance S01a (Valid TLS 1.2 certificate) | `analyze.py:analyze_certificate_chain` | `test_certs.py:test_acceptance_s01a` |
| Acceptance S04 (Expired certificate) | `analyze.py:analyze_certificate_chain` | `test_certs.py:test_acceptance_s04` |
| Acceptance S08 (RSA 1024-bit key) | `analyze.py:analyze_certificate_chain` | `test_certs.py:test_acceptance_s08` |
| Acceptance S09 (SHA-1 signature) | `analyze.py:analyze_certificate_chain` | `test_certs.py:test_acceptance_s09` |
| Acceptance S10 (Self-signed certificate) | `analyze.py:analyze_certificate_chain` | `test_certs.py:test_acceptance_s10` |
| Acceptance S11 (Untrusted issuer) | `analyze.py:analyze_certificate_chain` | `test_certs.py:test_acceptance_s11` |
