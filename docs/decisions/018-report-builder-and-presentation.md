# Decision 018: Report Builder and Presentation Architecture

## Context
Prompt 7.1 requires building report artifacts (`report.json` and `report.html`) for analyzed cases in `backend/reports/` using engine outputs and on-chain state, and exposing them via `GET /cases/{id}/report?format=json|html`.

## Decisions

1. **Deterministic Report Schema (`report.json`)**:
   - `report.json` is canonicalized using `engine.smscope.results.canonical.canonical_json` and hashed using SHA-256.
   - Contains: `caseId`, `pcapHash`, `engineVersion`, `rulesetHash`, `resultRoot`, `txHashes`, `hostScores`, `findings`, `sessionSummary`, `certificates`, `visibilityLimits`, `recommendations`, `onChainState`.
   - Strict determinism: No floating point values (use integers for percentages/scores), no wall-clock timestamps (use integer epoch timestamps from sessions/PCAP), all keys ASCII, and all lists deterministically sorted.

2. **Prioritization Ordering for Findings**:
   - Findings in `report.json` and `report.html` are sorted by:
     1. Severity weight descending: Critical (40) > High (20) > Medium (8) > Low (2) > Info (0).
     2. Exposure factor descending: 3 (>=10 sessions) > 2 (2-9 sessions) > 1 (<=1 session).
     3. Rule ID ascending (e.g., R01 < R02).

3. **Recommendations (`recommendations.yaml`)**:
   - Provides concrete Postfix and Dovecot remediation configuration directives for all 12 Tier 1 rules (R01, R02, R03, R06, R08, R09, R11, R12, R13, R15, R16, R19).
   - Parameters verified against official Postfix and Dovecot documentation.
   - Includes official documentation URLs.

4. **Self-Contained HTML Presentation (`report.html`)**:
   - Rendered using Jinja2 templates without any external CSS stylesheets, JavaScript scripts, web fonts, or CDN references.
   - The only external hyperlinks present are legitimate documentation URLs pointing to official postfix.org, dovecot.org, ietf.org, or openssl.org sites.
   - Embeds visual representations of the five verification steps defined in Section 8.

5. **Privacy and Compliance Integrity**:
   - Strictly enforces AGENT_RULES.md: no plaintext passwords, SASL credentials, or email body payloads are present in the report. Evidence references contain only session IDs, stream IDs, and packet index/frame numbers.
