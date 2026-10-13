# Threats to Validity

This document outlines the methodological assumptions, empirical constraints, and threats to internal, construct, and external validity in the evaluation of SecureMailScope.

---

## 1. Synthetic Traffic Generation

### Threat
All evaluated PCAP captures (scenarios `S01a` through `S13`, plus adversarial variations `X01` through `X03`) were generated inside an isolated Docker lab network using containerized test harnesses rather than collected from live enterprise production networks.

### Impact & Mitigations
- **Noise and Background Traffic:** Synthetic captures contain clean, isolated TCP streams between client and server containers without interleaved enterprise background noise (e.g., DNS queries, NTP, broadcast traffic, unrelated web sessions). The TCP stream reassembler filters streams by port (25, 465, 587) and protocol heuristics, but production traffic may present packet loss, jitter, retransmissions, out-of-order packets spanning multiple MTUs, and asymmetric routing.
- **Payload Realism:** The synthetic messages use standardized test email headers and synthetic payloads rather than human-generated text or varied MIME attachments. However, because SecureMailScope is strictly passive and inspects only protocol command verbs, TLS handshakes, and cryptographic parameters without storing or indexing body payloads (Rule 4), synthetic email bodies do not affect protocol tracking, cryptographic parameter parsing, or rule evaluation.

---

## 2. Single Mail Stack Homogeneity (Postfix & Dovecot)

### Threat
The lab environment exclusively runs **Postfix** (v3.7+) as the SMTP Mail Transfer Agent (MTA) and **Dovecot** (v2.3+) as the SASL authentication backend.

### Impact & Mitigations
- **Implementation Quotas & Dialects:** Different MTA implementations (e.g., Microsoft Exchange, Exim, Sendmail, Haraka, qmail) exhibit slight variations in banner greetings, EHLO capability ordering, pipelining support, error response codes, and TLS negotiation handshakes.
- **Mitigation:** SecureMailScope implements strict RFC 5321 (SMTP), RFC 3207 (STARTTLS), and RFC 8446/5246 (TLS) parsing rules based on token semantics rather than regex matching on specific server implementation banners. Nevertheless, behavior against proprietary enterprise gateways (e.g. Cisco IronPort, Proofpoint) has not been empirically evaluated in Tier 1.

---

## 3. Small Validator Quorum Set ($N = 3, 5$)

### Threat
Consensus evaluations and gas benchmarks were tested with small validator quorum sizes of $N = 3$ ($k = 2$) and $N = 5$ ($k = 3$) running on a local EVM network.

### Impact & Mitigations
- **Scalability vs Byzantine Quorums:** In a consortium of 3 or 5 validators, collusion requires compromising only 2 or 3 validator nodes. While this is sufficient for enterprise consortium auditing (where validators represent known institutions such as independent forensic auditors, insurance underwriters, and internal compliance), public or large-scale decentralization would require larger validator pools.
- **Gas Scaling:** As demonstrated in Experiment E6, the on-chain storage cost for `submitClaim` scales linearly with $N$ due to validator snapshot recording. Scaling beyond $N = 25$ on Layer 1 EVM without optimistic rollups or Merkle validator trees could lead to increased gas overhead per case.

---

## 4. Permissioned Consortium Assumptions

### Threat
The architecture explicitly assumes a permissioned EVM consensus model with role-based access control (`Roles.sol`), where only authorized analysts can open cases and submit claims, and only registered validators can submit commitments and reveals.

### Impact & Mitigations
- **Sybil Resistance:** Because validator registration requires administrative approval (`CaseRegistry.addValidator`), the system does not implement Proof-of-Work, Proof-of-Stake, or slashing deposits for Sybil resistance. If the contract administrator account is compromised, malicious validators could be registered.
- **Mitigation:** Production deployments require multisig governance (e.g., Gnosis Safe with $M$-of-$N$ threshold) for administrator roles.

---

## 5. Tshark as Ground Truth Benchmark

### Threat
Experiment E1 measures protocol and cryptographic parsing agreement against `tshark` (Wireshark 4.x) as the external ground truth.

### Impact & Mitigations
- **Parser Asymmetries & Legacy Field Encodings:** While `tshark` is the de facto industry standard for network protocol dissection, it is software that relies on specific field filters that can reflect legacy protocol structures.
- **RFC 8446 Middlebox Compatibility in E1 (Scenario S01b):** In Experiment E1, a single mismatch (72/73 fields matched, 98.63%) occurs in scenario `S01b` where the engine reports `TLS 1.3` while `tshark` baseline records `TLS 1.2` (`0x0303`). Under RFC 8446 Section 4.1.3, TLS 1.3 servers intentionally set the legacy `ServerHello.version` field to `0x0303` (TLS 1.2) for middlebox compatibility, while conveying the true negotiated version (`0x0304` / TLS 1.3) in the `supported_versions` extension (`0x002b`). SecureMailScope parses this extension according to standard specification, whereas the baseline field extractor queried the legacy `tls.handshake.version` field. The engine behavior is RFC-compliant, and the mismatch is recognized as an artifact of reference field extraction rather than a forensic defect.
- **Field Agreement:** Where representation differences occur, agreement mapping scripts normalize hex strings to canonical forms. Agreement reflects parsing concordance with a widely accepted reference, not absolute mathematical truth.

---

## 6. Label Derivation Methodology

### Threat
Ground truth labels in `lab/labels/` could risk circular validation if they were derived from the engine's own output.

### Impact & Mitigations
- **Methodological Independence:** As mandated by Decision 6 in `docs/PROMPT_LIBRARY.md` and `docs/ARCHITECTURE.md`, all ground truth labels were derived strictly from independently verified configuration parameters (Postfix configuration directives, OpenSSL certificates) and external inspection via `tshark -V`, completely independent of SecureMailScope's engine code.
- **Confusion Matrix Integrity:** Rule definitions were codified into labels prior to running engine comparisons, ensuring that E2 detection accuracy evaluates genuine conformance rather than tautological agreement.
