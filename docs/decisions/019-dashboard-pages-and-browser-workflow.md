# Decision 019: Server-Rendered Dashboard and Verification Workflow

## Context
Prompt 7.2 requires implementing server-rendered dashboard pages directly in the FastAPI application using Jinja2 without any frontend framework or external CDN dependencies. These pages must support running a case from upload to verification entirely in the browser.

## Decisions

1. **Server-Rendered Architecture**:
   - Built with Jinja2 templates and inline CSS.
   - Zero external scripts, CDN stylesheets, or web fonts.
   - Fully accessible and operable without JavaScript enabled (including form POST submissions for upload, analysis, distribution, finalize, record, anchor, and verify).
   - An optional lightweight inline JavaScript script provides client-side table filtering on `/cases/{id}/sessions`.

2. **Routes & Views**:
   - `/`: Dashboard home showing recent case list and a direct file upload form.
   - `/cases/{id}`: Case overview with status timeline (uploaded -> analyzed -> opened -> claimed -> distributed -> committing -> revealing -> finalized -> recorded -> report_anchored), PCAP SHA-256, result root, and workflow action buttons.
   - `/cases/{id}/hosts`: Host posture table showing hostId, endpoint, integer score, letter grade, and findings digest.
   - `/cases/{id}/findings`: Severity-prioritized findings with evidence packet numbers and concrete Postfix/Dovecot configuration guidance.
   - `/cases/{id}/sessions`: Interactive session explorer listing protocol, transport mode, STARTTLS negotiation, TLS version, cipher suite, forward secrecy, and certificate verdicts. Filterable by host and finding ID.
   - `/cases/{id}/tls`: Visual breakdown of TLS versions and cipher suites using pure HTML/CSS bar charts.
   - `/cases/{id}/certificates`: X.509 certificate table with SHA-256 fingerprints, subjects, issuers, validity dates, key types, SANs, and validation verdicts.
   - `/cases/{id}/chain`: Blockchain ledger panel showing on-chain status, validator commit/reveal state, transaction hashes, and interactive 5-Step Verification Suite.

3. **Explicit Visibility State Presentation**:
   - Protocol states that cannot be observed or evaluated passively are shown with explicit explanations rather than empty cells:
     - TLS 1.3: "Not observable (TLS 1.3 encrypted handshake per RFC 8446)"
     - Resumed: "Not observable (Resumed session using tickets/cache)"
     - Missing SNI: "Not present (Client Hello omitted SNI)"
     - Incomplete stream: "Not evaluable (Incomplete / truncated TCP stream)"

4. **Five-Step Verification Suite**:
   - `POST /cases/{id}/verify` runs all 5 steps of docs/ARCHITECTURE.md Section 8:
     1. Local PCAP SHA-256 equals on-chain `pcapHash`.
     2. Rebuilt Merkle root from canonical findings and host scores matches `result.json`.
     3. Merkle root matches on-chain `finalRoot`.
     4. Host posture records verified on `PostureLedger` hash chain.
     5. Canonical `report.json` SHA-256 matches on-chain `reportHash`.
   - Modifying a single byte of `pcap.bin` causes Step 1 to fail immediately.
