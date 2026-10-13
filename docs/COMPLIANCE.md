# Deliverable Compliance Matrix

This document provides a strict, auditable compliance traceability audit of all 21 deliverables from the course problem statement, plus mitigation recommendations and the blockchain consensus core requirement, reflecting the full verified state of the codebase (incorporating Tier 1, Tier 2 extensions, and Tier 3 asymmetric encryption).

**Status Categories:**
- **Met:** Fully implemented, verified by automated tests, and substantiated by empirical evaluation.
- **Architectural Adaptation:** Objective satisfied using an auditable, deterministic design (e.g., deterministic integer risk scoring in consensus loop, with machine learning isolated to an off-chain advisory layer).

---

## Compliance Audit Table

| # | Problem Statement Deliverable | Status | Evidence (Files & Suites) | Technical Implementation & Architectural Verification |
|:---:|:---|:---:|:---|:---|
| 1 | **Automatic identification of SMTP, IMAP, POP3** | **Met** | `engine/smscope/protocols/identify.py`, `engine/smscope/protocols/imap.py`, `engine/smscope/protocols/pop3.py`, `engine/tests/test_imap.py`, `engine/tests/test_pop3.py` | Automatically identifies SMTP (ports 25, 465, 587), IMAP (ports 143, 993), and POP3 (ports 110, 995) via port heuristics and initial handshake banner inspection. |
| 2 | **STARTTLS negotiation detection and validation** | **Met** | `engine/smscope/protocols/smtp.py`, `engine/tests/test_smtp.py`, `eval/e1_parsing_agreement.py` | Detects `STARTTLS` command, `220` affirmative response, exact packet byte offsets, command injection, and stripped/unencrypted fallback sessions (Rules R01, R02, R04). |
| 3 | **Complete TCP stream reconstruction** | **Met** | `engine/smscope/ingest/reassembly.py`, `engine/tests/test_reassembly.py`, `eval/e1_parsing_agreement.py` | Reassembles bidirectional TCP byte streams with out-of-order packet reordering, initial-payload retention on overlapping segments, and completeness flags. |
| 4 | **TLS handshake reconstruction** | **Met** | `engine/smscope/tls/handshake.py`, `engine/tests/test_tls_parser.py`, `eval/e1_parsing_agreement.py` | Deframes TLS records spanning TCP segment boundaries; parses ClientHello, ServerHello, extensions (SNI, supported_versions, key_share), and session resumption. |
| 5 | **Negotiated TLS versions** | **Met** | `engine/smscope/tls/negotiation.py`, `engine/tests/test_negotiation.py`, `eval/e1_parsing_agreement.py` | Extracts negotiated TLS versions (SSL 3.0, TLS 1.0, 1.1, 1.2, 1.3), parsing RFC 8446 `supported_versions` extensions, flagging deprecated versions (Rule R06). |
| 6 | **Negotiated cipher suites** | **Met** | `engine/smscope/tls/ciphers_generated.py`, `engine/smscope/rules/evaluator.py`, `eval/e1_parsing_agreement.py` | Complete RFC cipher catalog matching algorithms, key sizes, AEAD vs CBC modes, export suites, and NULL ciphers (Rules R07, R08). |
| 7 | **Key exchange mechanisms** | **Met** | `engine/smscope/tls/handshake.py`, `engine/tests/test_negotiation.py`, `eval/e1_parsing_agreement.py` | Identifies key exchange algorithms (ECDHE, DHE, RSA, PSK), named elliptic curves (X25519, secp256r1), and finite field parameter lengths. |
| 8 | **X.509 certificate extraction** | **Met** | `engine/smscope/certs/analyze.py`, `engine/tests/test_certs.py`, `eval/e1_parsing_agreement.py` | Extracts DER certificate chains from TLS 1.0–1.2 Certificate handshake messages; parses SANs, CN, validity periods, algorithms, and SHA-256 fingerprints. TLS 1.3 encrypted certs marked unobservable. |
| 9 | **Certificate chain validation** | **Met** | `engine/smscope/certs/analyze.py`, `engine/tests/test_certs.py`, `eval/e2_detection_accuracy.py` | Validates trust chains against configurable trust stores (`lab/ca/out/client_trust.crt`), detecting untrusted roots and self-signed certificates (Rule R11). |
| 10 | **Certificate expiration analysis** | **Met** | `engine/smscope/certs/analyze.py`, `engine/tests/test_certs.py`, `eval/e2_detection_accuracy.py` | Evaluates certificate `notBefore` and `notAfter` against packet capture timestamp (Rule 2), flagging expired (Rule R12) and not-yet-valid certificates. |
| 11 | **Public key algorithm and key length** | **Met** | `engine/smscope/certs/analyze.py`, `engine/tests/test_certs.py`, `eval/e1_parsing_agreement.py` | Extracts RSA, ECDSA, and Ed25519 key types and bit lengths, flagging weak RSA keys $< 2048$ bits (Rule R13). |
| 12 | **Digital signature algorithm identification** | **Met** | `engine/smscope/certs/analyze.py`, `engine/tests/test_certs.py`, `eval/e2_detection_accuracy.py` | Identifies signature algorithms and digest types, flagging legacy SHA-1 and MD5 certificates (Rule R16). |
| 13 | **Weak algorithms and deprecated TLS versions** | **Met** | `engine/smscope/rules/evaluator.py`, `eval/e2_detection_accuracy.py`, `eval/e3_baseline_comparison.py` | Detects deprecated TLS 1.0/1.1 (R06), RC4/3DES/CBC ciphers (R08), weak RSA keys (R13), SHA-1 signatures (R16), and cleartext traffic. |
| 14 | **Insecure protocol configurations** | **Met** | `engine/smscope/rules/evaluator.py`, `eval/e2_detection_accuracy.py` | Identifies cleartext authentication (R01), unencrypted traffic (R02), and STARTTLS command injection attempts (R03). |
| 15 | **Forward secrecy assessment** | **Met** | `engine/smscope/rules/evaluator.py`, `eval/e2_detection_accuracy.py` | Evaluates forward secrecy on negotiated ciphers, flagging non-PFS suites (e.g., static RSA key exchange) via Rule R09, and computing host PFS share. |
| 16 | **Cryptographic risk scoring** | **Architectural Adaptation** | `engine/smscope/rules/evaluator.py`, `engine/tests/test_rules.py` | Deterministic, integer risk scoring ($0 - 100$) per host based on severity deductions and exposure factor. Machine learning scoring intentionally excluded from consensus root to ensure bitwise consensus agreement (Principle 2). |
| 17 | **AI-assisted anomaly detection** | **Met** | `advisory/anomaly/detector.py`, `eval/e8_anomaly.py`, `engine/tests/test_anomaly.py` | Implements an off-chain Isolation Forest anomaly detector trained on baseline mail sessions, identifying statistical traffic anomalies outside the consensus result root. |
| 18 | **Prioritized security findings** | **Met** | `engine/smscope/rules/evaluator.py`, `backend/reports/builder.py`, `backend/templates/findings.html` | Findings prioritized strictly by severity descending (`Critical` $\to$ `High` $\to$ `Medium` $\to$ `Low`), affected session count descending, and rule ID ascending. |
| 19 | **Comprehensive posture assessment** | **Met** | `engine/smscope/results/pipeline.py`, `contracts/contracts/PostureLedger.sol`, `contracts/test/PostureLedger.test.ts` | Computes integer scores ($0 - 100$), letter grades (`A`–`F`), Merkle inclusion proofs, and commits historical host posture on-chain. |
| 20 | **Exportable reports in JSON, PDF, HTML** | **Partially Met** | `backend/reports/builder.py`, `backend/reports/pdf.py`, `backend/tests/test_reports.py` | Canonical JSON (`report.json`) and self-contained HTML (`report.html`) fully met. PDF export operates in Partial status on host environment where native WeasyPrint GTK3 C libraries are absent, rendering via pure-Python `pydyf` fallback with explicit `fallback rendering` label. |
| 21 | **Interactive visualization dashboard** | **Met** | `backend/app.py`, `backend/charts.py`, `backend/templates/`, `backend/tests/test_dashboard.py` | Server-rendered FastAPI/Jinja2 dashboard with pure-Python inline SVG charts for TLS version distribution, cipher suite usage, and host risk ranking. Zero external CDNs. |
| 22 | **Mitigation recommendations (stated objective)** | **Met** | `backend/reports/recommendations.yaml`, `backend/reports/builder.py` | Comprehensive, actionable remediation directives for Postfix and Dovecot for each rule, referencing official MTA configuration directives. |
| 23 | **Blockchain as the project core (team requirement)** | **Met** | `contracts/contracts/`, `contracts/test/`, `validator/`, `verifier/` | Core platform: `CaseRegistry` (lifecycle & engine pinning), `ValidationQuorum` ($k$-of-$N$ commit-reveal), `PostureLedger` (Merkle-verified historical tracking), and `MerkleVerifier`. |

---

## Tier 2 and Tier 3 Verification Summary

- **Tier 2 Extensions:**
  - T2.1 (IMAP Protocol Parsing): `engine/smscope/protocols/imap.py` (verified by `engine/tests/test_imap.py::test_imap_auth_plain_detection`, `test_imap_starttls_flow`, `test_imap_bad_auth_detection`)
  - T2.2 (POP3 Protocol Parsing): `engine/smscope/protocols/pop3.py` (verified by `engine/tests/test_pop3.py::test_pop3_cleartext_user_pass`, `test_pop3_stls_flow`, `test_pop3_bad_login_detection`)
  - T2.3 (Extended Ruleset R13–R19): `engine/smscope/rules/evaluator.py`, `ruleset/ruleset.yaml` (verified by `engine/tests/test_rules.py::test_rule_r13_weak_rsa_key`, `test_rule_r14_san_mismatch`, `test_rule_r15_revocation_info`, `test_rule_r16_legacy_signature_algorithm`, `test_rule_r17_starttls_downgrade_anomaly`, `test_rule_r18_certificate_churn`, `test_rule_r19_deprecated_hash`)
  - T2.4 (Anomaly Detection): `advisory/anomaly/detector.py` (verified by `engine/tests/test_anomaly.py::test_detector_initialization`, `test_score_session_clean`, `test_score_session_anomaly`, `test_consensus_isolation` and `eval/e8_anomaly.py`)
  - T2.5 (PDF Export): **Partially Met** — `backend/reports/pdf.py` (verified by `backend/tests/test_reports.py::test_pdf_export_s01a_s05_s12`, `test_pydyf_fallback_labels_and_identifiers`; operates in partial fallback mode without native GTK)
  - T2.6 (Evidence Capping & Limits): `engine/smscope/limits.py` (verified by `engine/tests/test_limits.py::test_packet_limit_enforced`, `test_stream_limit_enforced`, `test_finding_evidence_capped`, `test_host_score_leaf_limit`)
  - T2.7 (SVG Visualizations): `backend/charts.py` (verified by `backend/tests/test_dashboard.py::test_all_dashboard_pages_render`, `test_no_unauthorized_external_urls`)

- **Tier 3 Extensions:**
  - T3.1 (Key Generation & API Registration): `validator/keygen.py`, `backend/app.py` (verified by `validator/tests/test_encrypted_delivery.py::test_key_generation_and_storage`, `test_key_registration_api`)
  - T3.2 (Sealed Envelope Distribution): `validator/crypto.py`, `backend/app.py` (verified by `validator/tests/test_encrypted_delivery.py::test_envelope_encryption_and_decryption`)
  - T3.3 (Authenticated Decryptor Service): `validator/crypto.py`, `validator/service.py` (verified by `validator/tests/test_encrypted_delivery.py::test_multi_validator_bundle_isolation`, `test_corrupted_ciphertext_rejection`)
