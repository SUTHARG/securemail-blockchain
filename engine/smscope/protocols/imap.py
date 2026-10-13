"""IMAP session tracking state machine (RFC 3501, RFC 2595)."""
import re
from typing import List, Optional, Tuple

from engine.smscope.ingest.reassembly import Stream
from engine.smscope.models import CleartextAuth, SessionRecord, StarttlsInfo
from engine.smscope.protocols.identify import ProtocolIdentification, identify


class ImapParseError(Exception):
    """Raised when IMAP parsing encounters a malformed stream."""
    pass


def _extract_capabilities(text: str) -> Tuple[bool, bool, bool]:
    """
    Extracts key capability flags from an IMAP capability string.
    Returns: (starttls_offered, logindisabled, auth_plain)
    """
    starttls = bool(re.search(r"\bSTARTTLS\b", text, re.IGNORECASE))
    logindisabled = bool(re.search(r"\bLOGINDISABLED\b", text, re.IGNORECASE))
    auth_plain = bool(re.search(r"\bAUTH=PLAIN\b", text, re.IGNORECASE))
    return starttls, logindisabled, auth_plain


def _parse_server_lines(server_bytes: bytes) -> List[Tuple[int, int, str]]:
    """
    Parses server bytes into lines.
    Returns list of (start_offset, end_offset, line_text).
    Stops if binary TLS record (0x16 0x03) is encountered.
    """
    lines: List[Tuple[int, int, str]] = []
    offset = 0
    total_len = len(server_bytes)

    while offset < total_len:
        if server_bytes[offset:offset + 2] == b"\x16\x03":
            break

        nl_pos = server_bytes.find(b"\n", offset)
        if nl_pos == -1:
            line_bytes = server_bytes[offset:]
            next_offset = total_len
        else:
            line_bytes = server_bytes[offset:nl_pos + 1]
            next_offset = nl_pos + 1

        try:
            line_text = line_bytes.decode("ascii", errors="replace").rstrip("\r\n")
            lines.append((offset, next_offset, line_text))
        except Exception:
            break

        offset = next_offset

    return lines


def _get_frame(stream: Stream, direction: str, offset: int) -> int:
    """Safely retrieves packet number for offset, falling back to firstFrame."""
    try:
        return stream.frame_for_offset(direction, offset)
    except Exception:
        return getattr(stream, "firstFrame", 1) or 1


def track_imap(stream: Stream, ident: Optional[ProtocolIdentification] = None) -> SessionRecord:
    """
    Tracks an IMAP session across reassembled client and server streams.
    Identifies STARTTLS negotiation, capability advertisements, and cleartext credentials.
    """
    if ident is None:
        ident = identify(stream)

    client_bytes = stream.clientBytes
    server_bytes = stream.serverBytes

    starttls_offered = False
    starttls_attempted = False
    starttls_outcome = "notOffered"
    transport_mode = "plaintext"
    cleartext_auth: List[CleartextAuth] = []

    client_tls_start_offset: Optional[int] = None
    server_tls_start_offset: Optional[int] = None

    # 1. Handle Implicit TLS (e.g. port 993 or direct TLS handshake)
    if ident.transport_hint == "implicitTls" or client_bytes.startswith(b"\x16\x03"):
        return SessionRecord(
            sessionId=stream.index,
            clientEndpoint=stream.client,
            serverEndpoint=stream.server,
            protocol="imap",
            protocolSource=ident.source,
            transportMode="implicitTls",
            streamComplete=stream.complete,
            firstPacketTs=stream.firstTs,
            starttls=StarttlsInfo(offered=False, attempted=False, outcome="notOffered"),
            cleartextAuth=[],
            tls=None,
            certificates=[],
            clientTlsStartOffset=0,
            serverTlsStartOffset=0,
            stream=stream,
        )

    # 2. Parse Server Greeting & Capability responses
    server_lines = _parse_server_lines(server_bytes)
    for start_off, end_off, line in server_lines:
        # Check greeting: * OK ...
        if line.startswith("* OK") or line.startswith("* PREAUTH"):
            st, ld, ap = _extract_capabilities(line)
            if st:
                starttls_offered = True

        # Check untagged capability line: * CAPABILITY ...
        if line.startswith("* CAPABILITY"):
            st, ld, ap = _extract_capabilities(line)
            if st:
                starttls_offered = True

    # 3. Parse Client Commands
    client_offset = 0
    total_client_len = len(client_bytes)

    while client_offset < total_client_len:
        if client_bytes[client_offset:client_offset + 2] == b"\x16\x03":
            # Direct switch to TLS
            client_tls_start_offset = client_offset
            break

        nl_pos = client_bytes.find(b"\n", client_offset)
        if nl_pos == -1:
            line_bytes = client_bytes[client_offset:]
            next_client_offset = total_client_len
        else:
            line_bytes = client_bytes[client_offset:nl_pos + 1]
            next_client_offset = nl_pos + 1

        try:
            line_text = line_bytes.decode("ascii", errors="replace").rstrip("\r\n").strip()
        except Exception:
            break

        if not line_text:
            client_offset = next_client_offset
            continue

        # IMAP command format: <tag> <command> [<args>]
        parts = line_text.split(None, 2)
        tag = parts[0]
        cmd_verb = parts[1].upper() if len(parts) > 1 else ""

        # Handle synchronizing literal syntax {n} in command name
        literal_match = re.search(r"\{(\d+)\}\s*$", line_text)
        literal_bytes_to_skip = int(literal_match.group(1)) if literal_match else 0

        # Check for Cleartext Authentication in plaintext portion
        if cmd_verb == "LOGIN":
            packet_no = _get_frame(stream, "client", client_offset)
            cleartext_auth.append(CleartextAuth(mechanism="LOGIN", packetNumber=packet_no))
        elif cmd_verb == "AUTHENTICATE":
            auth_mech = parts[2].split()[0].upper() if len(parts) > 2 else ""
            if auth_mech == "PLAIN":
                packet_no = _get_frame(stream, "client", client_offset)
                cleartext_auth.append(CleartextAuth(mechanism="PLAIN", packetNumber=packet_no))

        # Check for STARTTLS command
        elif cmd_verb == "STARTTLS":
            starttls_attempted = True
            client_tls_start_offset = next_client_offset

            # Search server lines for matching tag response: <tag> OK / NO / BAD
            found_reply = False
            for s_start, s_end, s_line in server_lines:
                s_parts = s_line.split(None, 2)
                if len(s_parts) >= 2 and s_parts[0] == tag:
                    status = s_parts[1].upper()
                    found_reply = True
                    if status == "OK":
                        starttls_outcome = "succeeded"
                        transport_mode = "starttls"
                        server_tls_start_offset = s_end
                    elif status in ("NO", "BAD"):
                        starttls_outcome = "refused"
                        transport_mode = "plaintext"
                        client_tls_start_offset = None
                        server_tls_start_offset = None
                    else:
                        starttls_outcome = "refused"
                        transport_mode = "plaintext"
                    break

            if not found_reply:
                starttls_outcome = "refused"
                transport_mode = "plaintext"

            if starttls_outcome == "succeeded":
                # Upgraded to TLS; exit plaintext loop
                break

        # Advance client offset, skipping literal octets if synchronizing literal was declared
        if literal_bytes_to_skip > 0:
            client_offset = next_client_offset + literal_bytes_to_skip
        else:
            client_offset = next_client_offset

    # Determine final outcome if not attempted
    if not starttls_attempted:
        if starttls_offered:
            starttls_outcome = "ignored"
        else:
            starttls_outcome = "notOffered"

    starttls_info = StarttlsInfo(
        offered=starttls_offered,
        attempted=starttls_attempted,
        outcome=starttls_outcome,
    )

    return SessionRecord(
        sessionId=stream.index,
        clientEndpoint=stream.client,
        serverEndpoint=stream.server,
        protocol="imap",
        protocolSource=ident.source,
        transportMode=transport_mode,
        streamComplete=stream.complete,
        firstPacketTs=stream.firstTs,
        starttls=starttls_info,
        cleartextAuth=cleartext_auth,
        tls=None,
        certificates=[],
        clientTlsStartOffset=client_tls_start_offset,
        serverTlsStartOffset=server_tls_start_offset,
        stream=stream,
    )
