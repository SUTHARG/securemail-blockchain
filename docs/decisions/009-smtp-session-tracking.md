# Decision 009: SMTP Session Tracking and Parsing Policies

## Status
Accepted

## Context
`docs/ARCHITECTURE.md` section 4.3 and Prompt 5.3 specify mail session tracking for SMTP (with IMAP and POP3 stubbed out with `NotImplementedError` for Tier 1). The SMTP session tracker parses reassembled client and server streams to evaluate transport modes (`plaintext`, `starttls`, `implicitTls`), STARTTLS capabilities and negotiations (`offered`, `attempted`, `outcome`), cleartext authentication occurrences (`mechanism`, `packetNumber`), and the byte offsets where TLS records begin.

## Decisions

1. **Stream Delimiters and Line Splitting**:
   - Client commands and server responses are delimited by CRLF (`\r\n`) or bare LF (`\n`).
   - Trailing whitespace and CR/LF characters are stripped when evaluating command words and reply codes.

2. **Server Reply Parsing**:
   - Server replies are parsed into 3-digit integer codes and text strings.
   - Multiline replies: In accordance with RFC 5321, lines formatted as `<code>-<text>` indicate continuation. The multiline reply terminates at the line formatted as `<code> <text>` with the same 3-digit code.
   - Capability extraction: The capability list is derived from the server's reply to `EHLO`. If the capability list contains the token `STARTTLS` (case-insensitive), `starttls.offered` is set to `True`.

3. **Message Body and Binary Data Skipping**:
   - To strictly comply with `AGENT_RULES.md` rule 4 ("Never store, log, or print credential values or email content"), email message contents are completely skipped and never retained:
     - After client command `DATA` (case-insensitive), all client bytes are bypassed until the standalone end-of-data sequence `\r\n.\r\n` (or `\n.\n`).
     - For `BDAT <chunk_size> [LAST]` commands (RFC 3030), the declared integer `<chunk_size>` bytes are advanced over without parsing.

4. **STARTTLS Flow & Outcome Mapping**:
   - If `STARTTLS` command is issued by the client:
     - `starttls.attempted = True`.
     - Next server reply:
       - Code `220`: `starttls.outcome = "succeeded"`, `transportMode = "starttls"`.
       - Code `4xx` or `5xx`: `starttls.outcome = "refused"`, `transportMode = "plaintext"`.
   - If client never issues `STARTTLS`:
     - If `starttls.offered == True`: `starttls.outcome = "ignored"`, `transportMode = "plaintext"`.
     - If `starttls.offered == False`: `starttls.outcome = "notOffered"`, `transportMode = "plaintext"`.

5. **TLS Start Offsets**:
   - For `transportMode == "starttls"` with `outcome == "succeeded"`:
     - `clientTlsStartOffset`: Exact byte offset in `clientBytes` immediately following `STARTTLS\r\n`.
     - `serverTlsStartOffset`: Exact byte offset in `serverBytes` immediately following the `220` reply to STARTTLS.
   - For `transportMode == "implicitTls"`:
     - `clientTlsStartOffset = 0` and `serverTlsStartOffset = 0`.
     - `starttls = { offered: False, attempted: False, outcome: "notOffered" }`.
   - For `transportMode == "plaintext"`:
     - Both offsets are `None`.

6. **Cleartext Authentication Handling**:
   - In the plaintext phase only, client commands starting with `AUTH PLAIN` or `AUTH LOGIN` (case-insensitive) record `{ mechanism, packetNumber }`.
   - `packetNumber` is looked up via `stream.frame_for_offset("client", command_offset)`.
   - No credential payloads, challenge strings, or responses are parsed, logged, or retained.

7. **Protocol Stubs**:
   - IMAP and POP3 session tracking raise `NotImplementedError` per Tier 1 specification scope.

## Consequences
- Conforms fully with `spec/schemas/session_record.json` and `docs/ARCHITECTURE.md` section 4.3.
- Guarantees zero credential leakage or payload storage.
- Accurately tracks TLS handoff boundaries for downstream TLS record and handshake dissection.
