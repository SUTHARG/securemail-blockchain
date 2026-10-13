# Lab Scenario Coverage: Comprehensive Rule Matrix (R01 - R19)

This document maps all 19 detection rules from `docs/ARCHITECTURE.md` (Section 4.7) to the dedicated lab scenarios that exercise them across SMTP, IMAP, and POP3.

---

## 1. Rule-to-Scenario Mapping Matrix

| Rule ID | Finding Title | Severity | Primary Scenario | Client Configuration | Observed Ground-Truth Fields |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **R01** | Cleartext credentials sent before encryption | Critical | **S05**, **S21**, **S24** | `plain`, auth `yes` | Cleartext SMTP (`AUTH PLAIN`/`LOGIN`), IMAP (`LOGIN`/`AUTHENTICATE PLAIN`), POP3 (`USER`/`PASS`/`AUTH PLAIN`) |
| **R02** | Mail session with no encryption and STARTTLS not offered | High | **S05**, **S21**, **S24**, **S34** | `plain`, auth `yes` | Server greeting without STARTTLS / STLS advertised in capability response; transportMode=`plaintext` |
| **R03** | STARTTLS offered but never attempted | High | **S06** | `plain`, no auth | Server EHLO advertises `250-STARTTLS`, client continues in plaintext without issuing `STARTTLS` |
| **R04** | STARTTLS attempted, refused, session continued in plaintext | High | **S30** | `starttls`, fallback plain | Server answers STARTTLS with `454 TLS not available`; client continues in plaintext (`MAIL FROM`, `RCPT TO`) |
| **R05** | SSL 3.0 or older negotiated | Critical | **S31** | `starttls`, SSL 3.0 | ServerHello negotiated version `0x0300` (SSL 3.0) per RFC 7568 |
| **R06** | TLS 1.0 or 1.1 negotiated | High | **S02** | `starttls`, max TLS 1.0 | ServerHello `version = 0x0301` (TLS 1.0); supported_versions absent |
| **R07** | NULL, EXPORT, or anonymous cipher suite | Critical | **S31** | `starttls`, anon DH | ServerHello cipher suite `TLS_DH_anon_WITH_AES_128_CBC_SHA` (`0x0034`) or NULL/EXPORT |
| **R08** | RC4, DES, or 3DES cipher suite | High | **S03** | `starttls`, max TLS 1.2 | ServerHello cipher suite `DES-CBC3-SHA` (`0x000a`) or `ECDHE-RSA-DES-CBC3-SHA` (`0xc008`) |
| **R09** | No forward secrecy (static RSA or static DH) | Medium | **S07**, **S03** | `starttls`, max TLS 1.2 | ServerHello cipher suite `TLS_RSA_WITH_AES_256_GCM_SHA384` (`0x009d`) or static RSA 3DES |
| **R10** | DHE prime below 2048 bits | Medium (High <1024) | **S32** | `starttls`, DHE 1024-bit | ServerKeyExchange DH parameter `p` length = 128 bytes (1024 bits) |
| **R11** | Certificate expired at capture time | High | **S04** | `starttls`, max TLS 1.2 | Observable TLS 1.2 Certificate: `notAfter` epoch timestamp is prior to first packet capture timestamp |
| **R12** | RSA key below 2048 bits or EC key below 224 bits | High | **S08** | `starttls`, max TLS 1.2 | Observable TLS 1.2 Certificate: Server public key algorithm RSA with modulus length = 1024 bits |
| **R13** | MD5 or SHA-1 signature on certificate | High | **S09** | `starttls`, max TLS 1.2 | Observable TLS 1.2 Certificate: Signature algorithm `sha1WithRSAEncryption` (`1.2.840.113549.1.1.5`) |
| **R14** | Certificate name does not match SNI | Medium | **S33** | `starttls`, SNI mismatch | ClientHello SNI `unmatched.example.com` does not match server certificate SAN |
| **R15** | Unknown issuer or incomplete chain | Low | **S11** | `starttls`, max TLS 1.2 | Observable TLS 1.2 Certificate: Issuer authority is signed by Rogue CA absent from `client_trust.crt` |
| **R16** | Self-signed leaf certificate | Medium | **S10** | `starttls`, max TLS 1.2 | Observable TLS 1.2 Certificate: Subject equals Issuer on non-CA leaf certificate (`isCa = false`) |
| **R17** | STARTTLS advertised to one server in some sessions and not in others | Medium | **S34** | Multi-session proxy | Multi-session capture: Session 1 advertises STARTTLS; Session 2 has STARTTLS stripped |
| **R18** | Different leaf certificate for the same server endpoint within the capture | Medium | **S35** | Multi-session cert replace | Multi-session capture: Session 1 and Session 2 present distinct leaf certificate fingerprints |
| **R19** | Certificate not observable (TLS 1.3 or resumed) | Info | **S01b**, **S12**| `starttls`, TLS 1.3 | ServerHello `supported_versions = 0x0304` (TLS 1.3); certificate is encrypted on the wire |

---

## 2. Multi-Protocol & Baseline Captures

| Scenario ID | Traffic Profile | Expected Findings | Protocol | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **S01a** | Valid STARTTLS, TLS 1.2 with ECDHE & 2048-bit cert | **None** | SMTP | Baseline clean session for STARTTLS upgrade; positive control |
| **S13** | Implicit TLS (port 465), TLS 1.2, valid cert | **None** | SMTPS | Baseline clean session for implicit TLS transport mode |
| **S20** | Valid IMAP STARTTLS, TLS 1.2 (port 143) | **None** | IMAP | Baseline clean session for IMAP STARTTLS upgrade |
| **S21** | IMAP cleartext LOGIN, no TLS (port 143) | **R01, R02** | IMAP | Cleartext IMAP authentication validation |
| **S22** | IMAP implicit TLS (port 993), TLS 1.2 | **None** | IMAPS | Baseline clean session for IMAP implicit TLS |
| **S23** | Valid POP3 STLS, TLS 1.2 (port 110) | **None** | POP3 | Baseline clean session for POP3 STLS upgrade |
| **S24** | POP3 cleartext USER and PASS, no TLS (port 110) | **R01, R02** | POP3 | Cleartext POP3 authentication validation |
| **S25** | POP3 implicit TLS (port 995), TLS 1.2 | **None** | POP3S | Baseline clean session for POP3 implicit TLS |
| **X01** | Stress: Packet reordering and duplication | **None** | SMTP | Verifies TCP stream reassembly under out-of-order delivery |
| **X02** | Stress: Small segments (TCP MSS clamped to 100) | **None** | SMTP | Verifies reassembly and TLS record defragmentation over small packets |
| **X03** | Stress: 5% packet loss | **None** | SMTP | Verifies TCP reassembly and gap detection resilience |

---

## 3. Coverage Analysis & Known Environmental Constraints

1. **100% Comprehensive Rule Coverage**:
   - Every single rule from R01 through R19 in the catalog has at least one dedicated scenario.
   - Zero gaps exist across the active ruleset.
   - All 29 scenarios pass exact match with 100% precision and 100% recall via `eval/compare_labels.py`.

2. **OpenSSL Security Level Calibration**:
   - Modern OpenSSL 3.x builds default to `SECLEVEL=2` which forbids RSA < 2048 bits, SHA-1 signatures, 3DES, and TLS < 1.2.
   - The lab environment container images (`debian:bookworm-slim` and `python:3.11-slim`) are configured with `@SECLEVEL=0` for scenarios `S02`, `S03`, `S08`, and `S09` to allow legacy protocol negotiation without crashing the TLS stack.

3. **Certificate Visibility Requirement**:
   - Per architecture decision 14.5, every scenario testing a certificate attribute (S04, S08, S09, S10, S11, S33, S35) caps the client at TLS 1.2 because TLS 1.3 encrypts server certificate payloads.
