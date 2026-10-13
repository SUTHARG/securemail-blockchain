# Experiment E3: Baseline Comparison (Zeek vs. SecureMailScope)

**Baseline Tool:** Zeek 6.0.3 LTS (Reference Baseline)
**Loaded Policies:** `policy/protocols/ssl/weak-keys`, `policy/protocols/ssl/validate-certs`

### Detection Coverage Matrix

| Scenario | Labeled Findings | Flagged by Both | Flagged Only by SecureMailScope | Zeek Notice Generated |
|---|---|---|---|---|
| S01a | (none) | (none) | (none) | (none) |
| S01b | R19 | (none) | R19 | (none) |
| S02 | R06, R09 | (none) | R06, R09 | (none) |
| S03 | R08, R09 | R08 | R09 | R08 (SSL::Weak_Cipher) |
| S04 | R11 | R11 | (none) | R11 (SSL::Invalid_Server_Cert) |
| S05 | R01, R02 | (none) | R01, R02 | (none) |
| S06 | R03 | (none) | R03 | (none) |
| S07 | R09 | (none) | R09 | (none) |
| S08 | R12 | R12 | (none) | R12 (SSL::Weak_Key) |
| S09 | R13 | (none) | R13 | (none) |
| S10 | R16 | R16 | (none) | R16 (SSL::Invalid_Server_Cert) |
| S11 | R15 | R15 | (none) | R15 (SSL::Invalid_Server_Cert) |
| S12 | R19 | (none) | R19 | (none) |
| S13 | (none) | (none) | (none) | (none) |
| S20 | (none) | (none) | (none) | (none) |
| S21 | R01, R02 | (none) | R01, R02 | (none) |
| S22 | (none) | (none) | (none) | (none) |
| S23 | (none) | (none) | (none) | (none) |
| S24 | R01, R02 | (none) | R01, R02 | (none) |
| S25 | (none) | (none) | (none) | (none) |
| S30 | R04 | (none) | R04 | (none) |
| S31 | R05, R07 | (none) | R05, R07 | (none) |
| S32 | R10 | (none) | R10 | (none) |
| S33 | R14 | (none) | R14 | (none) |
| S34 | R02, R17 | (none) | R02, R17 | (none) |
| S35 | R18 | (none) | R18 | (none) |
| X01 | (none) | (none) | (none) | (none) |
| X02 | (none) | (none) | (none) | (none) |
| X03 | (none) | (none) | (none) | (none) |

### Key Observations

1. **Transport Layer Parity:** Both Zeek and SecureMailScope successfully detect generic TLS issues: weak 3DES ciphers (R08), expired certs (R11), small RSA keys (R12), untrusted CAs (R15), and self-signed certificates (R16).
2. **Mail-Specific Protocol Blind Spots in Baseline:** Standard Zeek SSL policies do not correlate SMTP protocol state transitions, leaving critical mail attack vectors unflagged:
   - **R01**: Cleartext SMTP password transmission (`AUTH PLAIN` / `AUTH LOGIN`).
   - **R02**: Cleartext SMTP delivery without STARTTLS capability advertised.
   - **R03**: Active STARTTLS stripping (STARTTLS offered in EHLO but bypassed by client).
   - **R09**: Static RSA key exchange without Forward Secrecy.
   - **R19**: Visibility boundary declaration for TLS 1.3 / session resumption.
3. **Cryptographic Accountability:** Zeek produces unstructured log lines without deterministic canonical hashing, Merkle posture trees, or Byzantine quorum attestation.
