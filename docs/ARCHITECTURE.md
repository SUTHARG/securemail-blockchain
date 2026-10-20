# SecureMailScope: system architecture and design

Working document for the course project. Status labels used throughout: **Given** (from the problem statement or stated by the team), **Proposed** (our design choice, open to change), **Open** (not yet decided).

## 1. Project context

**Given**

- Title: SecureMailScope: AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications.
- This is a course project for a blockchain course. The team requires blockchain to be the core of the project.
- Problem statement: an AI-assisted passive network forensic framework that analyzes captured traffic (PCAP files) containing SMTP, IMAP, and POP3 communications and assesses the cryptographic security posture of enterprise email infrastructure.
- Intended users: SOC teams, digital forensics teams, incident response teams, and enterprise administrators.
- Required capabilities: reconstruct email sessions and TCP streams, detect STARTTLS and encrypted session upgrades, parse TLS handshakes, extract and validate X.509 certificates, identify negotiated TLS versions, cipher suites, and key exchange, detect weak or deprecated cryptography, assess forward secrecy, classify and score risk, detect anomalous TLS behavior, prioritize findings, recommend mitigations, export JSON, PDF, and HTML reports, and provide an interactive dashboard.

**Open**

- Blockchain platform: EVM with Solidity, or Hyperledger Fabric. This document uses EVM terms as the working default. Section 11 states what changes under Fabric.
- Team size and deadline.

## 2. Design principles

1. **Passive only.** The system reads PCAP files and never contacts a mail server.
2. **Deterministic core.** The same PCAP and the same engine release always produce byte-identical results. Validator agreement depends on this.
3. **The chain stores hashes and results only.** No PCAP content, email content, credentials, or raw evidence goes on-chain.
4. **Evidence without secrets.** Every finding points to streams and packets, and never contains credential values or message content.
5. **Visibility limits are reported, not hidden.** For example, TLS 1.3 certificates are encrypted and are reported as not observable.
6. **ML and LLM output is advisory.** It appears in reports and is excluded from the data validators agree on.

## 3. System architecture

### 3.1 Layers

| Layer | Components | Location |
| --- | --- | --- |
| L1 Ingestion | PCAP reader, TCP reassembly, protocol identification | Off-chain |
| L2 Analysis | Mail session trackers, TLS parser, certificate analyzer | Off-chain |
| L3 Findings | Rule engine, scoring, canonical result builder with Merkle tree | Off-chain |
| L4 Advisory | Anomaly detector, recommendation generator | Off-chain |
| L5 Chain | CaseRegistry, ValidationQuorum, PostureLedger, access control | On-chain |
| L6 Validators | Independent engine instances, each with a chain account | Off-chain, with chain accounts |
| L7 Presentation | Report builder, dashboard, verifier | Off-chain |

### 3.2 Actors and trust

| Actor | Role | Trust placed in them |
| --- | --- | --- |
| Organization analyst | Opens cases, runs the engine, submits the claimed result | None for result correctness. The quorum checks the claim |
| Validator operator | Runs the pinned engine on the same PCAP and submits a result | Trusted only as part of a quorum, never individually |
| Auditor or insurer | Reads the chain and verifies results | Needs no write permission. EVM chain state is publicly readable |
| Admin | Manages validators and pinned engine versions, resolves disputes | Multisig. Demo simplification allowed and must be documented |

### 3.3 End-to-end flow

1. The analyst computes the SHA-256 of the PCAP and opens a case in CaseRegistry.
2. The engine runs off-chain and produces sessions, findings, host scores, and the result root.
3. The analyst submits the claim: result root plus engine and ruleset hashes, which must equal the pinned values.
4. The PCAP is delivered to each validator over an encrypted off-chain channel.
5. Each validator runs the pinned engine and commits a hash of its result root (commit phase).
6. Validators reveal their roots (reveal phase).
7. The contract compares the reveals. If k reveals match the claim, the case is finalized. Otherwise it is disputed or expired.
8. On finalization, per-host scores are written to PostureLedger, each verified by a Merkle proof against the final root.
9. The report is generated and its hash is recorded as a custody event. The dashboard shows verification status.

Advisory outputs (anomaly flags, recommendation text) appear in the report but never enter the result root.

### 3.4 Proposed technology (not yet confirmed)

| Area | Proposal |
| --- | --- |
| Engine language | Python |
| Packet and stream parsing | dpkt or Scapy for packets, custom TCP reassembly and TLS parser |
| X.509 | Python cryptography library |
| Anomaly detection | scikit-learn Isolation Forest |
| Contracts | Solidity with Hardhat, local node first |
| Chain access from engine | web3.py |
| Reports and dashboard | Jinja2 with WeasyPrint for HTML and PDF, web dashboard (framework Open) |
| Engine packaging | Container image, so validators run an identical release |

## 4. Analysis engine design

### 4.1 Ingestion and reassembly (T1)

- Read PCAP files with Ethernet frames. IPv4 and IPv6 are both handled.
- Flow key: the 5-tuple, normalized so both directions map to one flow.
- Per direction, order segments by TCP sequence number, drop exact retransmissions, resolve overlaps, and detect gaps.
- A stream with gaps is marked incomplete. Findings that depend on missing bytes are marked unevaluable instead of guessed.
- Stream index is the ordinal of the flow's first packet in the file, so numbering is deterministic.
- Packets are processed as a stream so large captures need not fit in memory (Proposed).
- A capture with no SMTP, IMAP, or POP3 sessions is rejected with an explicit error, because there is nothing to assess.

### 4.2 Protocol identification (T1)

Content decides, ports are only hints.

| Observation | Result |
| --- | --- |
| Server's first line starts with `220` and client sends EHLO or HELO | SMTP |
| Server's first line starts with `* OK` and client sends tagged commands | IMAP |
| Server's first line starts with `+OK` | POP3 |
| Client's first bytes are a TLS handshake record (0x16, 0x03) | Implicit TLS. The protocol is inferred from the port (465, 993, 995) and recorded as inferred |
| Port hints: 25, 587, 465, 143, 993, 110, 995 | Used only when content is absent or ambiguous |

### 4.3 Mail session tracking (T2)

One state machine per protocol, driven by the reassembled stream. References: RFC 3207 (SMTP STARTTLS), RFC 2595 (IMAP STARTTLS and POP3 STLS), RFC 8314 (implicit TLS ports).

| Protocol | Capability signal | Client command | Success reply | Failure reply |
| --- | --- | --- | --- | --- |
| SMTP | `STARTTLS` in the EHLO response | `STARTTLS` | `220` | `454`, `501`, `530` or other 4xx and 5xx |
| IMAP | `STARTTLS` in CAPABILITY | tagged `STARTTLS` | tagged `OK` | tagged `NO` or `BAD` |
| POP3 | `STLS` in CAPA | `STLS` | `+OK` | `-ERR` |

After a success reply, the next client bytes must be a TLS ClientHello. The tracker records for every session:

- transport mode: `plaintext`, `starttls`, or `implicitTls`
- STARTTLS offered (yes or no), attempted (yes or no), and outcome: `succeeded`, `refused`, `ignored`, or `notOffered`
- cleartext authentication seen before encryption, by mechanism name and packet number only: SMTP `AUTH PLAIN` or `AUTH LOGIN`, IMAP `LOGIN` or `AUTHENTICATE PLAIN`, POP3 `USER` and `PASS` or `AUTH PLAIN`

Credential values are never stored.

### 4.4 TLS parsing (T3)

- Record layer: read handshake records (content type 22). Reassemble handshake messages that span records, and records that span TCP segments.
- Messages parsed: ClientHello, ServerHello (a TLS 1.3 HelloRetryRequest is recognized by its fixed random value), Certificate, ServerKeyExchange, and CertificateStatus (stapled OCSP in TLS 1.2).
- **Negotiated version:** taken from the `supported_versions` extension in the ServerHello when present, because TLS 1.3 keeps 0x0303 in the legacy version field. Otherwise from the ServerHello version field.
- **Cipher suite:** the 2-byte code is looked up in an IANA-derived table giving key exchange, authentication, bulk cipher, MAC or AEAD, and a forward secrecy flag.
- **Key exchange details:** TLS 1.2 ECDHE gives the named curve in ServerKeyExchange. TLS 1.2 DHE gives the prime length in ServerKeyExchange. TLS 1.3 gives the selected group in the ServerHello `key_share`.
- **Resumption:** TLS 1.2 abbreviated handshakes (no Certificate message) and TLS 1.3 sessions with `pre_shared_key` in the ServerHello. Certificates are recorded as not observable (resumed).
- **TLS 1.3:** the certificate is encrypted. Recorded as not observable (TLS 1.3). Version, cipher suite, and key share group are still extracted.
- **Fingerprints:** JA3 from the ClientHello and JA3S from the ServerHello, using the published definitions.
- Cleartext TLS alerts that end a failed handshake are recorded.
- Encrypted application data is never decrypted.

### 4.5 Certificate analysis (T4)

Applies to certificates observable in TLS 1.2 and earlier sessions.

- Extract the certificate list in order from the Certificate message.
- Per certificate record: SHA-256 fingerprint, subject, issuer, validity period, public key algorithm and size or curve, signature algorithm, subject alternative names, basicConstraints, keyUsage, and extendedKeyUsage.
- **Time reference:** validity is judged against the capture timestamp of the packet carrying the Certificate message, not the analysis machine's clock.
- **Chain:** built and validated against a configurable trust store that can include enterprise CAs.
- **Name check:** compared with the SNI from the ClientHello. Without SNI the check is marked not evaluable, never guessed.
- **Revocation:** not checkable passively, except stapled OCSP in TLS 1.2. Not implemented in the first version (Proposed).

Verdicts are kept distinct, and one certificate can carry several: valid, expired, not yet valid, weak key, weak signature, name mismatch, self-signed, unknown issuer (incomplete chain or issuer not in the trust store), and not observable. Unknown issuer is deliberately not the same as invalid.

### 4.6 Forward secrecy

- TLS 1.3: always provided.
- TLS 1.2 and earlier: provided for ECDHE and DHE suites, not provided for static RSA or static DH key exchange.
- DHE with a prime below 2048 bits is flagged separately.
- Reported per session, and per server as the share of sessions with forward secrecy.

### 4.7 Rule engine and scoring (T5)

Rules live in a versioned configuration file. Initial catalog (severities are Proposed and are calibrated on lab captures):

| ID | Finding | Severity | Basis |
| --- | --- | --- | --- |
| R01 | Cleartext credentials sent before encryption | Critical | Credentials readable on the wire |
| R02 | Mail session with no encryption and STARTTLS not offered | High | No transport protection |
| R03 | STARTTLS offered but never attempted | High | Available upgrade not used |
| R04 | STARTTLS attempted, refused, session continued in plaintext | High | Fallback to plaintext |
| R05 | SSL 3.0 or older negotiated | Critical | RFC 7568 |
| R06 | TLS 1.0 or 1.1 negotiated | High | RFC 8996 |
| R07 | NULL, EXPORT, or anonymous cipher suite | Critical | No confidentiality or no authentication |
| R08 | RC4, DES, or 3DES cipher suite | High | RFC 7465 for RC4, birthday attacks on 64-bit block ciphers |
| R09 | No forward secrecy (static RSA or static DH) | Medium | Past sessions decryptable after later key compromise |
| R10 | DHE prime below 2048 bits | Medium, High below 1024 | Weak finite-field group |
| R11 | Certificate expired at capture time | High | Validity |
| R12 | RSA key below 2048 bits or EC key below 224 bits | High | Key strength |
| R13 | MD5 or SHA-1 signature on a non-root certificate in the chain | High | Weak signature hash |
| R14 | Certificate name does not match SNI | Medium | Identity mismatch |
| R15 | Unknown issuer or incomplete chain | Low | May reflect an enterprise CA |
| R16 | Self-signed leaf certificate | Medium | No third-party trust |
| R17 | STARTTLS advertised to one server in some sessions and not in others | Medium | Inconsistency indicator, not proof of stripping |
| R18 | Different leaf certificate for the same server endpoint within the capture | Medium | Change indicator |
| R19 | Certificate not observable (TLS 1.3 or resumed) | Info | Visibility limit |

**Deduplication:** one finding per rule and server endpoint, listing the affected sessions and their count.

**Scoring (Proposed, integer arithmetic only):**

- Severity weights: Critical 40, High 20, Medium 8, Low 2, Info 0.
- Exposure factor from affected session count: 1 for one session, 2 for two to nine, 3 for ten or more.
- Host score = max(0, 100 minus the sum of weight times exposure factor over the host's findings).
- Grade bands (Proposed): A 90 and above, B 75 to 89, C 60 to 74, D 40 to 59, F below 40.
- The dashboard shows the lowest host score as the capture summary.

Integers replace the logarithmic exposure factor suggested earlier, because floating-point results could differ between validator machines.

### 4.8 Advisory layers (T6, T7)

- **Anomaly detection (T6):** Isolation Forest over per-session features: TLS version, cipher suite, JA3 rarity relative to a baseline, certificate change for the same server, handshake size (measured from TLS start offset when available, bucketed by 256 bytes), resumption flag, STARTTLS offered and used. Baseline comes from clean lab traffic. Output is flagged sessions with the top deviating features. Excluded from the result root.
- **Recommendations (T7):** an LLM receives the findings JSON only. When an external LLM is offline or unconfigured, an offline provider generates deterministic template-based remediation guidance. A validator rejects any recommendation that cites a finding ID that does not exist and falls back to static templates. Excluded from the result root.
- **Open:** the problem statement asks for AI-based risk scoring. The score in 4.7 is rule-based. Options are to keep it rule-based, or to add an ML-derived ranking next to it and compare the two. Not yet decided.

## 5. Data model

### 5.1 Session record

All fields are deterministic. Timestamps are integer epoch seconds from the PCAP. No processing-time or random values.

| Field | Content |
| --- | --- |
| sessionId | Stream ordinal |
| clientEndpoint, serverEndpoint | IP and port |
| protocol, protocolSource | `smtp`, `imap`, `pop3`. Source is `content` or `port` |
| transportMode | `plaintext`, `starttls`, `implicitTls` |
| streamComplete | False if gaps were detected |
| firstPacketTs | Capture time of the first packet |
| starttls | offered, attempted, outcome |
| cleartextAuth | List of mechanism name and packet number |
| tls | version, cipherSuiteCode, cipherSuiteName, kxType, kxGroupOrDhBits, forwardSecrecy, resumed, ja3, ja3s, sni, certObservable and reason |
| certificates | sha256, subject, issuer, notBefore, notAfter, keyAlgorithm, keySize, signatureAlgorithm, san, isCa, verdicts |

### 5.2 Finding and host score

- **Finding:** findingId, ruleId, severity, serverEndpoint, sortedSessionIds, sessionCount, evidence (session, packet number, note), rule-specific integer or string details.
- **Host score:** hostId, score, grade, and a digest of the host's sorted findingIds.
- **hostId** on-chain is an HMAC-SHA-256 of the server endpoint under an organization-level secret shared with validators over the same encrypted channel as the PCAP. A plain hash of an IP address is easy to reverse. (Proposed)

### 5.3 Canonicalization and result root

- Findings are serialized as canonical JSON: UTF-8, sorted keys, no whitespace, integers only, following RFC 8785 or an equivalent documented rule.
- Leaf hashes use one-byte type tags for domain separation:
  - finding leaf: SHA-256 of 0x00 followed by the canonical JSON bytes
  - host-score leaf: SHA-256 of 0x02 followed by hostId (32 bytes), findings digest (32 bytes), and score (2 bytes, big-endian)
- Inner node: SHA-256 of 0x01 followed by the two child hashes in sorted order, so proofs need no left or right flags. An odd node is carried up unchanged.
- Leaves are sorted by hash before the tree is built.
- The root is the **result root**. It covers findings and host scores, so validators agree on both. (Earlier text called it the findings root.)

### 5.4 Case manifest

Case ID, pcapSha256, engine image digest, ruleset hash, result root, finding count, host count, report hash once generated, and transaction hashes for each on-chain step.

## 6. Blockchain layer design

### 6.1 Contract suite

| Contract | Responsibility |
| --- | --- |
| CaseRegistry | Cases, PCAP hash, custody events, report anchoring |
| ValidationQuorum | Claims, commits, reveals, outcome, disputes |
| PostureLedger | Hash-linked per-host posture records |
| Access control | Roles for admin, analyst, validator |

All contract state is publicly readable on an EVM chain. Roles restrict who can write, not who can read.

### 6.2 Engine pinning

The admin registers approved engine releases by container image digest and the matching ruleset hash. A claim must carry the active pinned values. Validators also report them at reveal. This is self-reported, so the real guarantee is root equality: a different engine that produces the same root is equivalent for this purpose.

### 6.3 Case lifecycle

| State | Entered when | Who acts | Next |
| --- | --- | --- | --- |
| Opened | Analyst registers the PCAP hash | Analyst | Claimed |
| Claimed | Analyst submits result root and pinned hashes. Validator set is snapshotted: N validators, k = floor(N/2) + 1 | Analyst | Committing |
| Committing | Claim accepted, commit deadline set | Validators | Revealing |
| Revealing | Commit window closed | Validators | Finalized, Disputed, or Expired |
| Finalized | At least k reveals equal the claimed root. Can happen as soon as k matching reveals exist | Anyone triggers finalize | PostureLedger writes |
| Disputed | Reveal window closed, reveals exist, but fewer than k match the claim | Admin | Finalized, new Committing round, or Rejected |
| Expired | Reveal window closed with fewer than k validators revealing | Admin | New round or Rejected |
| Rejected | Admin decision | None | Terminal |

In a dispute, if a root other than the claim has at least k reveals, the admin resolution attests that root and marks the claim as contradicted. Deadlines use block timestamps. N is at least 3 (Proposed).

This refines the earlier lifecycle: it adds the commit and reveal split and the Expired state.

### 6.4 Commit-reveal

- Commit: a validator submits keccak256 of the case ID, its own address, its result root, and a random salt.
- Reveal: the validator submits the root and salt, and the contract checks them against the commit.
- Purpose: prevents a validator from copying another validator's visible transaction instead of running the engine. It does not prove that a validator actually analyzed the PCAP.
- keccak256 is used for commitments because it is native to the EVM and the value never leaves the chain. Findings and PCAP hashes stay SHA-256.

### 6.5 Proofs

- Single finding: an auditor receives the finding JSON and sibling hashes and recomputes up to the result root. This works off-chain.
- Host score: PostureLedger verifies on-chain, using the EVM sha256 function, that the leaf built from hostId, findings digest, and score is included in the finalized root.

### 6.6 Posture ledger

One hash-linked chain per hostId. Each record holds hostId, caseId, score, result root, previous record hash, timestamp, and its own hash (keccak256 over those fields). The first record has no predecessor. History cannot be rewritten without breaking every later record.

### 6.7 Roles and functions

| Role | Functions |
| --- | --- |
| Admin (multisig) | registerEngine, addValidator, removeValidator, resolveDispute, extendDeadline |
| Analyst | openCase, submitClaim, anchorReport, recordPosture after finalization |
| Validator | commit, reveal |
| Anyone | finalize, read all state |

### 6.8 Events

CaseOpened, ClaimSubmitted, CommitSubmitted, RevealSubmitted, CaseFinalized, CaseDisputed, CaseExpired, CaseResolved, ReportAnchored, PostureRecorded, ValidatorAdded, ValidatorRemoved, EngineRegistered. Together they form the custody log.

## 7. Validator node design

- Runs the pinned container image, with no network access during analysis.
- Receives the PCAP and the organization secret over an encrypted off-chain channel.
- Runs the engine, builds the result root, commits, waits for the reveal window, and reveals.
- Holds its own chain account and key.
- For the demo, N validators run as separate processes on one machine with separate Hardhat accounts. A multi-machine run is optional.

## 8. Presentation layer

**Reports (JSON, HTML, PDF)** contain: case ID, PCAP hash, engine and ruleset hashes, result root, transaction hashes, per-host scores and grades, prioritized findings with evidence references, session and TLS summaries, certificate table, visibility limits, advisory sections clearly labeled (anomaly flags, recommendations), and on-chain case state.

**Dashboard views:** capture overview, host posture table, prioritized findings with evidence, session explorer, TLS version and cipher distribution, certificate table, advisory anomaly flags, and a chain panel showing case state, validator commits and reveals, and a verify button.

**Verifier steps:**

1. Recompute the PCAP SHA-256 and compare with the on-chain PCAP hash.
2. Rebuild leaves and result root from the findings JSON, or check one finding with a proof.
3. Compare with the finalized root on-chain.
4. Walk the host's posture chain and recompute each record hash.
5. Compare the report hash with the anchored value.

## 9. Limitations and risks

- TLS 1.3 and resumed sessions hide certificates. Reported as not observable, never silently skipped.
- No decryption, so nothing inside encrypted sessions is analyzed.
- Passive analysis cannot prove STARTTLS stripping. R17 and R18 are indicators only.
- Revocation is not checked.
- Name matching depends on SNI. Without it the check is not evaluable.
- Verification proves evidence is unchanged since anchoring. It does not prove the capture was authentic when taken or that the analysis logic is correct. Correctness comes from the evaluation.
- Validators need the PCAP. This only fits a permissioned consortium under agreement, not a public validator network.
- On-chain metadata (case IDs, timestamps, addresses) reveals that an analysis happened. Use pseudonymous identifiers.
- A colluding majority of validators can finalize a false result. The claim is that trust moves from one operator to a quorum, not that the system is trustless.
- Commit-reveal prevents copying but cannot prove a validator ran the engine.
- Incomplete captures (dropped packets) limit what can be assessed. Gaps are flagged.
- IP fragmentation: IP fragments (packets with IPv4 MF flag set or non-zero fragment offset, or IPv6 fragment extension headers) are not reassembled; fragmented packets beyond initial TCP headers cannot be tracked and are logged as incomplete capture gaps.
- Trust store path validation: Certificate chain trust store validation evaluates against system or custom-configured CA bundle paths. Missing, invalid, or unreadable trust store files fail closed. Revocation checks (OCSP/CRL) are not evaluated in passive capture analysis.

## 10. Requirement traceability

| Problem statement deliverable | Section |
| --- | --- |
| Automatic identification of SMTP, IMAP, POP3 | 4.2 |
| STARTTLS negotiation detection and validation | 4.3 |
| Complete TCP stream reconstruction | 4.1 |
| TLS handshake reconstruction | 4.4 |
| Negotiated TLS versions | 4.4 |
| Negotiated cipher suites | 4.4 |
| Key exchange mechanisms | 4.4 |
| X.509 certificate extraction | 4.5 |
| Certificate chain validation | 4.5 |
| Certificate expiration analysis | 4.5 |
| Public key algorithm and key length | 4.5 |
| Digital signature algorithm identification | 4.5 |
| Weak algorithms and deprecated TLS versions | 4.7 (R05 to R08, R12, R13) |
| Insecure protocol configurations | 4.3, 4.7 (R01 to R04) |
| Forward secrecy assessment | 4.6, R09, R10 |
| AI-based cryptographic risk scoring | 4.7 rule-based score, 4.8 open question |
| AI-assisted anomaly detection | 4.8 |
| Prioritized security findings | 4.7 |
| Comprehensive posture assessment | 4.7, 8 |
| Exportable reports in JSON, PDF, HTML | 8 |
| Interactive visualization dashboard | 8 |
| Mitigation recommendations (stated objective) | 4.8 |
| Blockchain as the project core (team requirement) | 6 |

## 11. Evaluation plan

- **Ground truth:** a Docker Postfix and Dovecot lab with deliberately varied configurations (TLS 1.0 enabled, weak ciphers, expired certificate, optional STARTTLS, cleartext authentication), captured and labeled with the expected findings.
- **Parsing accuracy:** compare stream reassembly, protocol identification, and TLS fields against tshark on the same captures.
- **Detection accuracy:** per-rule precision and recall against the lab labels. Compare with Zeek's default weak-keys script on the same PCAPs.
- **Determinism:** the same PCAP across repeated runs and different machines yields an identical result root.
- **Chain tests:** tamper with the PCAP, a finding, or a report and verification fails. A validator with a modified ruleset is outvoted. A non-validator submission is rejected. Disputed and expired paths are exercised.
- **Cost and scale:** gas per registry write, claim, commit, reveal, finalize, and ledger record. Engine runtime against PCAP size.
- **Under Fabric (if mandated):** the quorum becomes chaincode with an endorsement policy, and commit-reveal and the gas table are replaced by endorsement and transaction metrics. Sections 3 to 5 are unchanged.

## 12. Open decisions

1. Blockchain platform: EVM and Solidity, or Hyperledger Fabric.
2. Team size and deadline.
3. Whether the posture score stays purely rule-based or gains an ML-derived ranking.
4. Validator deployment for the demo: separate processes on one machine, or multiple machines.
5. Trust store contents for chain validation.
6. Whether inferring the protocol from the port for implicit TLS is acceptable.
7. Dashboard and PDF tooling.

## 13. Changes from the earlier plan

- Integer scoring replaces the logarithmic exposure factor.
- The result root now covers host scores as well as findings.
- Commit-reveal and an Expired state were added to the quorum.
- Per-host ledger records are verified on-chain with Merkle proofs.
- Host identifiers on-chain are keyed hashes.

## 14. Decisions introduced by the prompt library

1. Expired takes precedence over Disputed: if fewer than k validators reveal at all, the case is Expired, otherwise Disputed.
2. Reveals must match the engine and ruleset hashes stored in the case at claim time, not the current pinned pair.
3. caseId = keccak256(abi.encode(pcapHash, analyst, counter)). Registering the same PCAP twice creates two cases.
4. Validators run in strict mode by default and abort before committing if their local ruleset hash differs from the case's. Only the evaluation scenarios disable this.
5. Certificate-rule lab scenarios use a client capped at TLS 1.2. S01 is split into S01a (certificate visible) and S01b (TLS 1.3, certificate not observable, R19).
6. Expected findings in lab labels are derived from tshark-observed fields and the rule definitions, never from the engine's own output.
7. Tier 1 delivers PCAPs to validators by file copy. Encrypted delivery and encryption at rest are Tier 3.
8. Admin is a single account in the demo and must be described as a simplification in the report.
9. PCAPNG and link types other than Ethernet and Linux cooked capture are rejected.
10. Overlapping TCP segments keep first-seen bytes, and a stream with a gap delivers only its contiguous prefix and is marked incomplete.
