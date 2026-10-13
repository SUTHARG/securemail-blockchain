# Decision 008: Protocol Identification and Transport Hint Rules

## Status
Accepted

## Context
SecureMailScope analyzes PCAP network streams to identify email protocols (SMTP, IMAP, POP3) passively. According to `docs/ARCHITECTURE.md` section 4.2 and Prompt 5.2, content is the primary discriminator while destination ports serve strictly as hints. To ensure deterministic categorization and clear delineation between content-derived and port-derived protocol classifications, the matching order, line extraction rules, and fallback mechanisms must be clearly specified.

## Decisions

1. **Content Matching Priority**:
   - Client and server streams are inspected before considering port hints.
   - Server greeting lines are split on CRLF (`\r\n`) or LF (`\n`).
   - Line prefixes and commands are evaluated case-insensitively with leading whitespace ignored:
     - Server first line starts with `220 ` or `220-` AND client first command starts with `EHLO` or `HELO` $\to$ `protocol = "smtp"`, `source = "content"`, `transport_hint = "plaintext"`.
     - Server first line starts with `* OK` $\to$ `protocol = "imap"`, `source = "content"`, `transport_hint = "plaintext"`.
     - Server first line starts with `+OK` $\to$ `protocol = "pop3"`, `source = "content"`, `transport_hint = "plaintext"`.

2. **Implicit TLS Identification**:
   - If client stream starts with TLS handshake bytes `0x16 0x03`:
     - `transport_hint = "implicitTls"`.
     - The protocol cannot be observed in plaintext content and is inferred from the server port:
       - Port 465 $\to$ `protocol = "smtp"`, `source = "port"`.
       - Port 993 $\to$ `protocol = "imap"`, `source = "port"`.
       - Port 995 $\to$ `protocol = "pop3"`, `source = "port"`.
     - Any other server port with `0x16 0x03` yields `protocol = "unknown"`, `source = "port"`.

3. **Ambiguous or Absent Content Fallback**:
   - When content does not match any of the above criteria (e.g. empty streams, incomplete greetings, or non-matching commands), port hints are consulted:
     - Ports 25 or 587 $\to$ `protocol = "smtp"`, `source = "port"`, `transport_hint = "plaintext"`.
     - Port 465 $\to$ `protocol = "smtp"`, `source = "port"`, `transport_hint = "implicitTls"`.
     - Port 143 $\to$ `protocol = "imap"`, `source = "port"`, `transport_hint = "plaintext"`.
     - Port 993 $\to$ `protocol = "imap"`, `source = "port"`, `transport_hint = "implicitTls"`.
     - Port 110 $\to$ `protocol = "pop3"`, `source = "port"`, `transport_hint = "plaintext"`.
     - Port 995 $\to$ `protocol = "pop3"`, `source = "port"`, `transport_hint = "implicitTls"`.
   - All other streams are classified as `protocol = "unknown"`, `source = "port"`, `transport_hint = "plaintext"` (or `"implicitTls"` if TLS record header was present).

4. **Return Structure**:
   - Returns a `ProtocolIdentification` dataclass exposing `protocol`, `source`, `transport_hint`, and `transportHint` properties.
   - Implements `__iter__` to support direct tuple unpacking `protocol, source, transport_hint = identify(stream)`.

## Consequences
- Conforms strictly to section 4.2 and Prompt 5.2 acceptance criteria.
- Ensures all lab captures (e.g., S01a, S05, S13) are deterministically and correctly identified.
- Prevents unknown protocols or non-mail traffic from contaminating the downstream analysis pipeline.
