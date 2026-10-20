"""POP3 session tracking state machine (RFC 1939, RFC 2595)."""
import re
from typing import List, Optional, Tuple

from engine.smscope.ingest.reassembly import Stream
from engine.smscope.models import CleartextAuth, SessionRecord, StarttlsInfo
from engine.smscope.protocols.identify import ProtocolIdentification, identify


class Pop3ParseError(Exception):
    """Raised when POP3 parsing encounters a malformed stream."""
    pass


def _get_frame(stream: Stream, direction: str, offset: int) -> int:
    """Safely retrieves packet number for offset, falling back to firstFrame."""
    try:
        return stream.frame_for_offset(direction, offset)
    except Exception:
        return getattr(stream, "firstFrame", 1) or 1


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


def track_pop3(stream: Stream, ident: Optional[ProtocolIdentification] = None) -> SessionRecord:
    """
    Tracks a POP3 session across reassembled client and server streams.
    Identifies STLS negotiation, CAPA capability advertisements, and cleartext credentials (USER, PASS, AUTH PLAIN).
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

    # 1. Handle Implicit TLS (e.g. port 995 or direct TLS handshake)
    if ident.transport_hint == "implicitTls" or client_bytes.startswith(b"\x16\x03"):
        s_cont = getattr(stream, "contiguous", getattr(stream, "complete", True))
        s_term = getattr(stream, "terminated", False)
        s_comp = getattr(stream, "confirmed_complete", s_cont and s_term)
        return SessionRecord(
            sessionId=stream.index,
            clientEndpoint=stream.client,
            serverEndpoint=stream.server,
            protocol="pop3",
            protocolSource=ident.source,
            transportMode="implicitTls",
            streamComplete=s_cont,
            firstPacketTs=stream.firstTs,
            starttls=StarttlsInfo(offered=False, attempted=False, outcome="notOffered"),
            cleartextAuth=[],
            tls=None,
            certificates=[],
            clientTlsStartOffset=0,
            serverTlsStartOffset=0,
            stream=stream,
            streamContiguous=s_cont,
            streamTerminated=s_term,
            confirmedComplete=s_comp,
        )

    # 2. Parse Server Lines to check for CAPA blocks and STLS advertisement
    starttls_offered_frame: Optional[int] = None
    starttls_attempted_frame: Optional[int] = None
    starttls_outcome_frame: Optional[int] = None

    server_lines = _parse_server_lines(server_bytes)
    in_capa_block = False

    for start_off, end_off, line in server_lines:
        line_upper = line.strip().upper()
        if "+OK CAPA" in line_upper or ("+OK" in line_upper and "CAPABILITY" in line_upper):
            in_capa_block = True
            continue

        if in_capa_block:
            if line.strip() == ".":
                in_capa_block = False
            elif re.search(r"\bSTLS\b", line_upper):
                starttls_offered = True
                starttls_offered_frame = _get_frame(stream, "server", start_off)

        # Some servers list STLS directly in banner or greeting
        if not starttls_offered and re.search(r"\bSTLS\b", line_upper):
            starttls_offered = True
            starttls_offered_frame = _get_frame(stream, "server", start_off)

    if not starttls_offered_frame and server_lines:
        starttls_offered_frame = _get_frame(stream, "server", server_lines[0][0])

    # 3. Parse Client Commands
    # Greeting consumes line 0 if present
    if server_lines and server_lines[0][2].strip().startswith("+OK"):
        server_line_idx = 1
    else:
        server_line_idx = 0

    client_offset = 0
    total_client_len = len(client_bytes)

    while client_offset < total_client_len:
        if client_bytes[client_offset:client_offset + 2] == b"\x16\x03":
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

        parts = line_text.split(None, 1)
        cmd_verb = parts[0].upper()

        # Check for Cleartext Authentication: USER, PASS, AUTH PLAIN
        if cmd_verb == "USER":
            has_payload = (len(parts) > 1 and len(parts[1].strip()) > 0)
            if has_payload:
                packet_no = _get_frame(stream, "client", client_offset)
                cleartext_auth.append(CleartextAuth(mechanism="USER", packetNumber=packet_no))
            if server_line_idx < len(server_lines):
                server_line_idx += 1
        elif cmd_verb == "PASS":
            has_payload = (len(parts) > 1 and len(parts[1].strip()) > 0)
            if has_payload:
                packet_no = _get_frame(stream, "client", client_offset)
                cleartext_auth.append(CleartextAuth(mechanism="PASS", packetNumber=packet_no))
            if server_line_idx < len(server_lines):
                server_line_idx += 1
        elif cmd_verb == "AUTH":
            auth_arg = parts[1].strip().upper() if len(parts) > 1 else ""
            if auth_arg.startswith("PLAIN"):
                auth_parts = auth_arg.split()
                has_payload = False
                if len(auth_parts) > 1 and len(auth_parts[1].strip()) > 0:
                    has_payload = True
                else:
                    cmd_frame = _get_frame(stream, "client", client_offset)
                    # Correlate challenge: must start with '+ ' or bare '+', ignore '+OK'
                    has_challenge = False
                    challenge_line_idx = None
                    for s_idx in range(server_line_idx, len(server_lines)):
                        s_start, s_end, s_line = server_lines[s_idx]
                        s_frame = _get_frame(stream, "server", s_start)
                        if s_frame >= cmd_frame:
                            s_clean = s_line.strip()
                            if s_clean.startswith("+ ") or s_clean == "+":
                                has_challenge = True
                                challenge_line_idx = s_idx
                                break
                            elif s_clean.startswith("+OK") or s_clean.startswith("-ERR"):
                                break
                    if has_challenge and next_client_offset < total_client_len:
                        next_end = client_bytes.find(b"\n", next_client_offset)
                        if next_end == -1:
                            next_line = client_bytes[next_client_offset:].decode("latin-1", errors="replace").strip()
                            resp_next_offset = total_client_len
                        else:
                            next_line = client_bytes[next_client_offset:next_end].decode("latin-1", errors="replace").strip()
                            resp_next_offset = next_end + 1
                        if next_line and next_line != "*":
                            has_payload = True
                        next_client_offset = resp_next_offset
                        if challenge_line_idx is not None:
                            server_line_idx = challenge_line_idx + 1
                if has_payload:
                    packet_no = _get_frame(stream, "client", client_offset)
                    cleartext_auth.append(CleartextAuth(mechanism="PLAIN", packetNumber=packet_no))
            if server_line_idx < len(server_lines):
                server_line_idx += 1
        elif cmd_verb == "CAPA":
            # CAPA response is multiline if +OK, ending with '.'
            if server_line_idx < len(server_lines):
                if server_lines[server_line_idx][2].strip().startswith("+OK"):
                    while server_line_idx < len(server_lines) and server_lines[server_line_idx][2].strip() != ".":
                        server_line_idx += 1
                    if server_line_idx < len(server_lines):
                        server_line_idx += 1  # skip '.'
                else:
                    server_line_idx += 1

        # Check for STLS command (RFC 2595)
        elif cmd_verb == "STLS":
            starttls_attempted = True
            starttls_attempted_frame = _get_frame(stream, "client", client_offset)
            client_tls_start_offset = next_client_offset
            if client_bytes[client_tls_start_offset:client_tls_start_offset + 2] != b"\x16\x03":
                ch_pos = client_bytes.find(b"\x16\x03", client_tls_start_offset)
                if ch_pos != -1:
                    client_tls_start_offset = ch_pos

            # Check server response to STLS
            found_reply = False
            while server_line_idx < len(server_lines):
                s_start, s_end, s_line = server_lines[server_line_idx]
                server_line_idx += 1
                s_stripped = s_line.strip()
                starttls_outcome_frame = _get_frame(stream, "server", s_start)
                if s_stripped.startswith("+OK"):
                    starttls_outcome = "succeeded"
                    transport_mode = "starttls"
                    server_tls_start_offset = s_end
                    if server_bytes[server_tls_start_offset:server_tls_start_offset + 2] != b"\x16\x03":
                        sh_pos = server_bytes.find(b"\x16\x03", server_tls_start_offset)
                        if sh_pos != -1:
                            server_tls_start_offset = sh_pos
                    found_reply = True
                    break
                elif s_stripped.startswith("-ERR"):
                    starttls_outcome = "refused"
                    transport_mode = "plaintext"
                    client_tls_start_offset = None
                    server_tls_start_offset = None
                    found_reply = True
                    break

            if not found_reply:
                starttls_outcome = "refused"
                transport_mode = "plaintext"

            if starttls_outcome == "succeeded":
                # Successfully upgraded to TLS
                break
        else:
            if server_line_idx < len(server_lines):
                server_line_idx += 1

        client_offset = next_client_offset

    # If STLS was never attempted, determine outcome from capability offer
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

    s_cont = getattr(stream, "contiguous", getattr(stream, "complete", True))
    s_term = getattr(stream, "terminated", False)
    s_comp = getattr(stream, "confirmed_complete", s_cont and s_term)

    return SessionRecord(
        sessionId=stream.index,
        clientEndpoint=stream.client,
        serverEndpoint=stream.server,
        protocol="pop3",
        protocolSource=ident.source,
        transportMode=transport_mode,
        streamComplete=s_cont,
        firstPacketTs=stream.firstTs,
        starttls=starttls_info,
        cleartextAuth=cleartext_auth,
        tls=None,
        certificates=[],
        clientTlsStartOffset=client_tls_start_offset,
        serverTlsStartOffset=server_tls_start_offset,
        stream=stream,
        starttls_offered_frame=starttls_offered_frame,
        starttls_attempted_frame=starttls_attempted_frame,
        starttls_outcome_frame=starttls_outcome_frame,
        streamContiguous=s_cont,
        streamTerminated=s_term,
        confirmedComplete=s_comp,
    )
