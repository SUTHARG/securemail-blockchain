"""SMTP session tracking state machine."""
import re
from typing import List, Optional, Tuple

from engine.smscope.ingest.reassembly import Stream
from engine.smscope.models import CleartextAuth, SessionRecord, StarttlsInfo
from engine.smscope.protocols.identify import ProtocolIdentification, identify


class SmtpParseError(Exception):
    """Raised when SMTP parsing encounters a malformed stream."""
    pass


from engine.smscope.protocols.imap import track_imap
from engine.smscope.protocols.pop3 import track_pop3


def _parse_server_replies(server_bytes: bytes) -> List[Tuple[int, int, int, List[str]]]:
    """
    Parses the server byte stream into replies.
    Returns a list of tuples: (start_offset, end_offset, reply_code, text_lines).
    Multiline replies (code-text ... code text) are grouped into a single logical reply.
    Stops parsing if binary / non-ASCII reply bytes are encountered (e.g. TLS records).
    """
    replies: List[Tuple[int, int, int, List[str]]] = []
    offset = 0
    total_len = len(server_bytes)

    curr_reply_start: Optional[int] = None
    curr_reply_code: Optional[int] = None
    curr_lines: List[str] = []

    while offset < total_len:
        # Check if byte is start of TLS record (0x16 0x03)
        if server_bytes[offset:offset + 2] == b"\x16\x03":
            break

        nl_pos = server_bytes.find(b"\n", offset)
        if nl_pos == -1:
            line_bytes = server_bytes[offset:]
            next_offset = total_len
        else:
            line_bytes = server_bytes[offset:nl_pos + 1]
            next_offset = nl_pos + 1

        stripped = line_bytes.rstrip(b"\r\n")
        if len(stripped) < 3:
            # Not an SMTP reply line
            break

        code_bytes = stripped[:3]
        if not code_bytes.isdigit():
            # Non-numeric code -> likely binary TLS or malformed
            break

        code = int(code_bytes.decode("ascii"))
        is_continuation = len(stripped) > 3 and stripped[3:4] == b"-"
        text_line = stripped[4:].decode("ascii", errors="replace").strip()

        if curr_reply_start is None:
            curr_reply_start = offset
            curr_reply_code = code

        curr_lines.append(text_line)

        if not is_continuation:
            # Reply is complete
            replies.append((curr_reply_start, next_offset, curr_reply_code, curr_lines))
            curr_reply_start = None
            curr_reply_code = None
            curr_lines = []

        offset = next_offset

    return replies


def track_smtp(stream: Stream, ident: Optional[ProtocolIdentification] = None) -> SessionRecord:
    """
    Parses reassembled client and server streams for an SMTP connection
    into a SessionRecord per section 5.1 and Prompt 5.3.
    """
    if ident is None:
        ident = identify(stream)

    # 1. Handle Implicit TLS streams
    if ident.transport_hint == "implicitTls":
        rec = SessionRecord(
            sessionId=stream.index,
            clientEndpoint=stream.client,
            serverEndpoint=stream.server,
            protocol="smtp",
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
        )
        return rec

    # 2. Parse Plaintext SMTP streams
    client_bytes = stream.clientBytes
    server_bytes = stream.serverBytes

    server_replies = _parse_server_replies(server_bytes)

    # Identify initial server greeting (first reply)
    # Remaining server replies respond to client commands
    reply_idx = 1 if len(server_replies) > 1 else 0

    starttls_offered = False
    starttls_attempted = False
    starttls_outcome = "notOffered"
    transport_mode = "plaintext"
    cleartext_auth: List[CleartextAuth] = []
    client_tls_start_offset: Optional[int] = None
    server_tls_start_offset: Optional[int] = None

    client_offset = 0
    total_client_len = len(client_bytes)

    while client_offset < total_client_len:
        # Check if client reached TLS records (0x16 0x03)
        if client_bytes[client_offset:client_offset + 2] == b"\x16\x03":
            break

        nl_pos = client_bytes.find(b"\n", client_offset)
        if nl_pos == -1:
            cmd_bytes = client_bytes[client_offset:]
            next_client_offset = total_client_len
        else:
            cmd_bytes = client_bytes[client_offset:nl_pos + 1]
            next_client_offset = nl_pos + 1

        cmd_str = cmd_bytes.rstrip(b"\r\n").decode("ascii", errors="replace").strip()
        cmd_upper = cmd_str.upper()

        # Handle DATA command: skip body until solitary "." line
        if cmd_upper == "DATA" or cmd_upper.startswith("DATA "):
            client_offset = next_client_offset
            # Search for end-of-data marker: \r\n.\r\n or \n.\n
            eod_patterns = [b"\r\n.\r\n", b"\n.\r\n", b"\n.\n"]
            found_eod = False
            for pat in eod_patterns:
                pos = client_bytes.find(pat, client_offset)
                if pos != -1:
                    client_offset = pos + len(pat)
                    found_eod = True
                    break
            if not found_eod:
                # Truncated DATA body, advance to end
                client_offset = total_client_len
            if reply_idx < len(server_replies):
                reply_idx += 1  # 354 reply
            if reply_idx < len(server_replies):
                reply_idx += 1  # 250 reply to message acceptance
            continue

        # Handle BDAT command: skip declared octets (RFC 3030)
        if cmd_upper.startswith("BDAT"):
            parts = cmd_upper.split()
            bdat_size = 0
            if len(parts) >= 2 and parts[1].isdigit():
                bdat_size = int(parts[1])
            client_offset = next_client_offset + bdat_size
            if reply_idx < len(server_replies):
                reply_idx += 1
            continue

        # Check for Cleartext Authentication: AUTH PLAIN or AUTH LOGIN
        if cmd_upper.startswith("AUTH PLAIN"):
            packet_no = stream.frame_for_offset("client", client_offset)
            cleartext_auth.append(CleartextAuth(mechanism="PLAIN", packetNumber=packet_no))
        elif cmd_upper.startswith("AUTH LOGIN"):
            packet_no = stream.frame_for_offset("client", client_offset)
            cleartext_auth.append(CleartextAuth(mechanism="LOGIN", packetNumber=packet_no))

        # Check for EHLO command to extract capability list
        if cmd_upper.startswith("EHLO ") or cmd_upper == "EHLO":
            if reply_idx < len(server_replies):
                ehlo_reply = server_replies[reply_idx]
                reply_idx += 1
                for line in ehlo_reply[3]:
                    # Check if STARTTLS is in capability list
                    if re.search(r"\bSTARTTLS\b", line, re.IGNORECASE):
                        starttls_offered = True

        # Check for STARTTLS command
        elif cmd_upper == "STARTTLS" or cmd_upper.startswith("STARTTLS "):
            starttls_attempted = True
            client_tls_start_offset = next_client_offset

            if reply_idx < len(server_replies):
                stls_reply = server_replies[reply_idx]
                reply_idx += 1
                reply_code = stls_reply[2]
                if reply_code == 220:
                    starttls_outcome = "succeeded"
                    transport_mode = "starttls"
                    server_tls_start_offset = stls_reply[1]
                    # Successfully upgraded to TLS; stop parsing client commands in plaintext
                    break
                elif 400 <= reply_code < 600:
                    starttls_outcome = "refused"
                    transport_mode = "plaintext"
                    client_tls_start_offset = None
                    server_tls_start_offset = None
                else:
                    starttls_outcome = "refused"
                    transport_mode = "plaintext"
            else:
                # No server reply captured
                starttls_outcome = "refused"
                transport_mode = "plaintext"

        else:
            if reply_idx < len(server_replies):
                reply_idx += 1

        client_offset = next_client_offset

    # If STARTTLS was never attempted, determine outcome from capability offer
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

    rec = SessionRecord(
        sessionId=stream.index,
        clientEndpoint=stream.client,
        serverEndpoint=stream.server,
        protocol="smtp",
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
    return rec


def track_session(stream: Stream) -> SessionRecord:
    """Dispatches stream to corresponding protocol tracker."""
    ident = identify(stream)
    if ident.protocol == "smtp":
        return track_smtp(stream, ident)
    elif ident.protocol == "imap":
        return track_imap(stream)
    elif ident.protocol == "pop3":
        return track_pop3(stream)
    else:
        raise ValueError(f"Unknown or unsupported protocol: {ident.protocol}")
