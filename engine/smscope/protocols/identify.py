"""Protocol identification for SecureMailScope."""
from dataclasses import dataclass
from typing import Optional

from engine.smscope.ingest.reassembly import Stream


@dataclass(frozen=True)
class ProtocolIdentification:
    """Protocol identification result."""
    protocol: str       # "smtp", "imap", "pop3", "unknown"
    source: str         # "content", "port"
    transport_hint: str # "plaintext", "implicitTls"

    @property
    def transportHint(self) -> str:
        return self.transport_hint

    def __iter__(self):
        return iter((self.protocol, self.source, self.transport_hint))


def _extract_first_line(data: bytes) -> str:
    """Extracts first line of payload as decoded ASCII string (ignoring decode errors)."""
    if not data:
        return ""
    line_bytes = data.split(b"\n")[0].rstrip(b"\r")
    return line_bytes.decode("ascii", errors="replace").strip()


def _get_server_port(endpoint: str) -> Optional[int]:
    """Extracts integer port from endpoint string."""
    try:
        return int(endpoint.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return None


def identify(stream: Stream) -> ProtocolIdentification:
    """
    Identifies application protocol and transport mode hint from a reassembled Stream.
    Content decides first; ports are fallback hints.
    """
    client_bytes = stream.clientBytes
    server_bytes = stream.serverBytes
    server_port = _get_server_port(stream.server)

    # 1. Implicit TLS check
    if client_bytes.startswith(b"\x16\x03"):
        if server_port == 465:
            return ProtocolIdentification(protocol="smtp", source="port", transport_hint="implicitTls")
        elif server_port == 993:
            return ProtocolIdentification(protocol="imap", source="port", transport_hint="implicitTls")
        elif server_port == 995:
            return ProtocolIdentification(protocol="pop3", source="port", transport_hint="implicitTls")
        elif server_port in (25, 587):
            return ProtocolIdentification(protocol="smtp", source="port", transport_hint="implicitTls")
        elif server_port == 143:
            return ProtocolIdentification(protocol="imap", source="port", transport_hint="implicitTls")
        elif server_port == 110:
            return ProtocolIdentification(protocol="pop3", source="port", transport_hint="implicitTls")
        else:
            return ProtocolIdentification(protocol="unknown", source="port", transport_hint="implicitTls")

    # 2. Content-based plaintext checks
    server_line = _extract_first_line(server_bytes)
    client_line = _extract_first_line(client_bytes)

    # SMTP: Server starts with '220 ' or '220-' and client starts with EHLO or HELO
    server_is_smtp_220 = server_line.startswith("220 ") or server_line.startswith("220-")
    client_upper = client_line.upper()
    client_is_smtp_hello = (
        client_upper.startswith("EHLO ")
        or client_upper.startswith("HELO ")
        or client_upper in ("EHLO", "HELO")
    )

    if server_is_smtp_220 and client_is_smtp_hello:
        return ProtocolIdentification(protocol="smtp", source="content", transport_hint="plaintext")

    # IMAP: Server first line starts with '* OK'
    if server_line.upper().startswith("* OK"):
        return ProtocolIdentification(protocol="imap", source="content", transport_hint="plaintext")

    # POP3: Server first line starts with '+OK'
    if server_line.upper().startswith("+OK"):
        return ProtocolIdentification(protocol="pop3", source="content", transport_hint="plaintext")

    # 3. Content absent or ambiguous -> Port hints
    if server_port in (25, 587):
        return ProtocolIdentification(protocol="smtp", source="port", transport_hint="plaintext")
    elif server_port == 465:
        return ProtocolIdentification(protocol="smtp", source="port", transport_hint="implicitTls")
    elif server_port == 143:
        return ProtocolIdentification(protocol="imap", source="port", transport_hint="plaintext")
    elif server_port == 993:
        return ProtocolIdentification(protocol="imap", source="port", transport_hint="implicitTls")
    elif server_port == 110:
        return ProtocolIdentification(protocol="pop3", source="port", transport_hint="plaintext")
    elif server_port == 995:
        return ProtocolIdentification(protocol="pop3", source="port", transport_hint="implicitTls")

    # 4. Unknown
    return ProtocolIdentification(protocol="unknown", source="port", transport_hint="plaintext")
