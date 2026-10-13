# Specification Compliance Audit: Phase 5, Prompt 5.5

## Scope
Audit of `scripts/gen_cipher_table.py`, `engine/smscope/tls/ciphers_generated.py`, `engine/smscope/tls/negotiation.py`, and `engine/tests/test_negotiation.py` against:
- `AGENT_RULES.md`
- `docs/ARCHITECTURE.md`, Sections 4.4 and 4.6
- `docs/PROMPT_LIBRARY.md`, Prompt 5.5
- `docs/decisions/011-cipher-suite-and-ja3.md`

---

### 1. Specification Discrepancies
None identified.
- `scripts/gen_cipher_table.py`:
  - Fetches official IANA TLS Cipher Suites registry in CSV form (`https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv`).
  - Records source URL and UTC retrieval timestamp in header.
  - Generates `engine/smscope/tls/ciphers_generated.py` containing 356 validated cipher suites mapping code to metadata (`name`, `kxType`, `authentication`, `bulkCipher`, `macOrAead`, `forwardSecrecy`, `weakClass`).
  - Analysis engine operates purely offline with committed `ciphers_generated.py` (Rule 5 compliance).
- `engine/smscope/tls/negotiation.py`:
  - Produces `TlsInfo` matching `spec/schemas/session_record.json`:
    - `version`: human-readable version string (`TLS 1.2`, `TLS 1.3`, `TLS 1.0`, etc.) resolved from `negotiated_version`.
    - `cipherSuiteCode`: 16-bit integer code.
    - `cipherSuiteName`: standard IANA cipher suite name.
    - `kxType`: key exchange classification (`RSA`, `DHE`, `ECDHE`, `tls13`, etc.).
    - `kxGroupOrDhBits`:
      - TLS 1.3: selected `key_share` group integer code.
      - TLS 1.2 ECDHE: named curve code from `ServerKeyExchange`.
      - TLS 1.2 DHE: bit length of prime modulus $p$ from `ServerKeyExchange`.
      - Otherwise: `0`.
    - `forwardSecrecy`: `True` for ephemeral suites (`ECDHE`, `DHE`, `tls13`), `False` for static suites (`RSA`, `DH`, `PSK`).
    - `resumed`:
      - TLS 1.2: `True` when `ServerHello` echoes client non-empty session ID and no `Certificate` follows.
      - TLS 1.3: `True` when `ServerHello` carries `pre_shared_key`.
      - Otherwise: `False`.
    - `ja3`: MD5 of standard JA3 string representation (`SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`), lowercase hex.
    - `ja3s`: MD5 of standard JA3S string representation (`SSLVersion,Cipher,Extensions`), lowercase hex.
    - `sni`: Server Name Indication hostname.
    - `certObservable`: `False` with reason `"tls13"` for TLS 1.3, `False` with reason `"resumed"` for resumed sessions, `True` with reason `None` when observable.
- JA3 / JA3S standards compliance:
  - RFC 8701 GREASE values filtered out from ciphers, extensions, curves, and point formats.
  - MD5 used strictly as standardized fingerprint representation format without security reliance.
- Synthesized and ground-truthed scenario coverage:
  - `S01a`: Valid STARTTLS, TLS 1.2, ECDHE, forward secrecy True, observable certificates.
  - `S01b`: Valid STARTTLS, TLS 1.3, forward secrecy True, certObservable False (reason `tls13`).
  - `S02`: TLS 1.0 negotiated, forward secrecy False.
  - `S03`: 3DES negotiated, forward secrecy False.
  - `S07`: Static RSA without forward secrecy (AES256-GCM-SHA384).
  - `S12`: Resumed TLS 1.2 session, certObservable False (reason `resumed`).

---

### 2. Missing Decisions
None. All cipher taxonomy, forward secrecy criteria, key exchange bit/group extraction, resumption checks, and JA3 fingerprinting rules are formally documented in [docs/decisions/011-cipher-suite-and-ja3.md](file:///c:/Users/gaura/OneDrive/Desktop/projects/blockchain-project/docs/decisions/011-cipher-suite-and-ja3.md).

---

### 3. AGENT_RULES.md Violations
- **Floating point arithmetic**: None.
- **Wall-clock time**: None at runtime. (Timestamps in generated file headers are purely declarative metadata).
- **Unordered iteration in written output**: None. Extension lists preserve raw packet sequence order.
- **Credential / payload logging**: None.
- **Passive engine**: None. Engine runs 100% offline; generator script is explicitly a separate build-time maintenance tool.

---

### 4. Specification Requirements Coverage
| Requirement | Implementation | Test Coverage |
| :--- | :--- | :--- |
| IANA Cipher Table Generation | `scripts/gen_cipher_table.py` -> `ciphers_generated.py` | `test_negotiation.py:test_forward_secrecy_assertions` |
| GREASE filtering | `negotiation.py:filter_grease` | `test_negotiation.py:test_filter_grease` |
| JA3 string & MD5 calculation | `negotiation.py:compute_ja3`, `compute_ja3_string` | `test_negotiation.py:test_hand_constructed_ja3` |
| JA3S string & MD5 calculation | `negotiation.py:compute_ja3s`, `compute_ja3s_string` | `test_negotiation.py:test_hand_constructed_ja3s` |
| Forward secrecy assertions | `negotiation.py:negotiate_tls`, `ciphers_generated.py` | `test_negotiation.py:test_forward_secrecy_assertions` |
| `kxGroupOrDhBits` (ECDHE, DHE, TLS 1.3, RSA) | `negotiation.py:negotiate_tls` | `test_negotiation.py:test_key_exchange_group_and_dh_bits` |
| Acceptance S01a (TLS 1.2 ECDHE clean) | `negotiation.py:negotiate_tls` | `test_negotiation.py:test_acceptance_s01a` |
| Acceptance S01b (TLS 1.3 unobservable) | `negotiation.py:negotiate_tls` | `test_negotiation.py:test_acceptance_s01b` |
| Acceptance S02 (TLS 1.0) | `negotiation.py:negotiate_tls` | `test_negotiation.py:test_acceptance_s02` |
| Acceptance S03 (3DES cipher) | `negotiation.py:negotiate_tls` | `test_negotiation.py:test_acceptance_s03` |
| Acceptance S07 (Static RSA no FS) | `negotiation.py:negotiate_tls` | `test_negotiation.py:test_acceptance_s07` |
| Acceptance S12 (Resumed session) | `negotiation.py:negotiate_tls` | `test_negotiation.py:test_acceptance_s12` |
| Incomplete handshake resilience | `negotiation.py:negotiate_tls` | `test_negotiation.py:test_negotiate_tls_incomplete_handshake` |
