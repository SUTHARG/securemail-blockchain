"""TLS handshake message parser and defragmenter."""
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from engine.smscope.ingest.reassembly import Stream
from engine.smscope.tls.records import (
    CONTENT_TYPE_HANDSHAKE,
    TlsAlert,
    TlsParseError,
    TlsRecord,
    parse_tls_records,
)

# Handshake Message Types (RFC 5246 / RFC 8446)
HANDSHAKE_TYPE_HELLO_REQUEST = 0
HANDSHAKE_TYPE_CLIENT_HELLO = 1
HANDSHAKE_TYPE_SERVER_HELLO = 2
HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4
HANDSHAKE_TYPE_END_OF_EARLY_DATA = 5
HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8
HANDSHAKE_TYPE_CERTIFICATE = 11
HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12
HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13
HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14
HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15
HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16
HANDSHAKE_TYPE_FINISHED = 20
HANDSHAKE_TYPE_CERTIFICATE_STATUS = 22
HANDSHAKE_TYPE_KEY_UPDATE = 24

# RFC 8446 Section 4.1.3: HelloRetryRequest fixed random magic
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


@dataclass
class ClientHello:
    legacy_version: int
    random: bytes
    session_id: bytes
    cipher_suites: List[int]
    compression_methods: bytes
    extensions: Dict[str, Any] = field(default_factory=dict)
    extension_types: List[int] = field(default_factory=list)


@dataclass
class ServerHello:
    version: int
    random: bytes
    session_id: bytes
    cipher_suite: int
    compression_method: int
    extensions: Dict[str, Any] = field(default_factory=dict)
    extension_types: List[int] = field(default_factory=list)


@dataclass
class ServerKeyExchange:
    param_type: str  # "ec_diffie_hellman", "diffie_hellman", "unknown"
    raw_bytes: bytes
    named_curve: Optional[int] = None
    dh_p_bits: Optional[int] = None


@dataclass
class CertificateStatus:
    status_type: int
    ocsp_response: bytes


@dataclass
class TlsHandshake:
    client_hello: Optional[ClientHello] = None
    server_hello: Optional[ServerHello] = None
    is_hello_retry_request: bool = False
    certificates: List[bytes] = field(default_factory=list)
    server_key_exchange: Optional[ServerKeyExchange] = None
    certificate_status: Optional[CertificateStatus] = None
    negotiated_version: Optional[int] = None
    fatal_alert: Optional[TlsAlert] = None
    parse_errors: List[TlsParseError] = field(default_factory=list)
    encrypted_record_count: int = 0

    @property
    def selected_cipher(self) -> Optional[int]:
        if self.server_hello:
            return self.server_hello.cipher_suite
        return None

    @property
    def sni(self) -> Optional[str]:
        if self.client_hello and "server_name" in self.client_hello.extensions:
            return self.client_hello.extensions["server_name"]
        return None

    @property
    def offered_ciphers(self) -> List[int]:
        if self.client_hello:
            return self.client_hello.cipher_suites
        return []

    @property
    def version_hex(self) -> Optional[str]:
        if self.negotiated_version is not None:
            return f"0x{self.negotiated_version:04x}"
        return None


def _parse_client_hello_extensions(ext_data: bytes) -> Tuple[Dict[str, Any], List[int]]:
    """Parses ClientHello extension blocks."""
    extensions: Dict[str, Any] = {}
    extension_types: List[int] = []
    idx = 0
    total_len = len(ext_data)

    while idx + 4 <= total_len:
        ext_type, ext_len = struct.unpack("!HH", ext_data[idx:idx + 4])
        idx += 4
        if idx + ext_len > total_len:
            break
        val = ext_data[idx:idx + ext_len]
        idx += ext_len
        extension_types.append(ext_type)

        if ext_type == 0:  # server_name (SNI)
            if len(val) >= 5:
                name_list_len = struct.unpack("!H", val[:2])[0]
                name_type = val[2]
                if name_type == 0 and len(val) >= 5:
                    name_len = struct.unpack("!H", val[3:5])[0]
                    if len(val) >= 5 + name_len:
                        extensions["server_name"] = val[5:5 + name_len].decode("ascii", errors="replace")

        elif ext_type == 10:  # supported_groups
            if len(val) >= 2:
                groups_len = struct.unpack("!H", val[:2])[0]
                groups = []
                for i in range(2, min(len(val), 2 + groups_len), 2):
                    if i + 2 <= len(val):
                        groups.append(struct.unpack("!H", val[i:i + 2])[0])
                extensions["supported_groups"] = groups

        elif ext_type == 11:  # ec_point_formats
            if len(val) >= 1:
                formats_len = val[0]
                extensions["ec_point_formats"] = list(val[1:1 + formats_len])

        elif ext_type == 13:  # signature_algorithms
            if len(val) >= 2:
                sig_len = struct.unpack("!H", val[:2])[0]
                sigs = []
                for i in range(2, min(len(val), 2 + sig_len), 2):
                    if i + 2 <= len(val):
                        sigs.append(struct.unpack("!H", val[i:i + 2])[0])
                extensions["signature_algorithms"] = sigs

        elif ext_type == 16:  # alpn
            if len(val) >= 2:
                alpn_len = struct.unpack("!H", val[:2])[0]
                protocols = []
                p_idx = 2
                while p_idx < 2 + alpn_len and p_idx < len(val):
                    p_len = val[p_idx]
                    p_idx += 1
                    if p_idx + p_len <= len(val):
                        protocols.append(val[p_idx:p_idx + p_len].decode("ascii", errors="replace"))
                    p_idx += p_len
                extensions["alpn"] = protocols

        elif ext_type == 43:  # supported_versions
            if len(val) >= 1:
                vers_len = val[0]
                versions = []
                for i in range(1, min(len(val), 1 + vers_len), 2):
                    if i + 2 <= len(val):
                        versions.append(struct.unpack("!H", val[i:i + 2])[0])
                extensions["supported_versions"] = versions

        elif ext_type == 45:  # psk_key_exchange_modes
            if len(val) >= 1:
                modes_len = val[0]
                extensions["psk_key_exchange_modes"] = list(val[1:1 + modes_len])

        elif ext_type == 51:  # key_share
            if len(val) >= 2:
                client_shares_len = struct.unpack("!H", val[:2])[0]
                shares = []
                s_idx = 2
                while s_idx + 4 <= min(len(val), 2 + client_shares_len):
                    group, k_len = struct.unpack("!HH", val[s_idx:s_idx + 4])
                    s_idx += 4
                    if s_idx + k_len <= len(val):
                        shares.append({"group": group, "key_exchange": val[s_idx:s_idx + k_len]})
                    s_idx += k_len
                extensions["key_share"] = shares

    return extensions, extension_types


def _parse_server_hello_extensions(ext_data: bytes) -> Tuple[Dict[str, Any], List[int]]:
    """Parses ServerHello extension blocks."""
    extensions: Dict[str, Any] = {}
    extension_types: List[int] = []
    idx = 0
    total_len = len(ext_data)

    while idx + 4 <= total_len:
        ext_type, ext_len = struct.unpack("!HH", ext_data[idx:idx + 4])
        idx += 4
        if idx + ext_len > total_len:
            break
        val = ext_data[idx:idx + ext_len]
        idx += ext_len
        extension_types.append(ext_type)

        if ext_type == 43:  # supported_versions (RFC 8446)
            if len(val) >= 2:
                extensions["supported_versions"] = struct.unpack("!H", val[:2])[0]

        elif ext_type == 51:  # key_share
            if len(val) >= 4:
                group, k_len = struct.unpack("!HH", val[:4])
                extensions["key_share"] = {
                    "group": group,
                    "key_exchange": val[4:4 + k_len] if len(val) >= 4 + k_len else b"",
                }

        elif ext_type == 41:  # pre_shared_key
            if len(val) >= 2:
                extensions["pre_shared_key"] = struct.unpack("!H", val[:2])[0]

    return extensions, extension_types


def _reassemble_handshake_payload(records: List[TlsRecord]) -> bytes:
    """Concatenates payloads of all Handshake (type 22) records."""
    chunks = [r.payload for r in records if r.content_type == CONTENT_TYPE_HANDSHAKE]
    return b"".join(chunks)


def parse_tls_handshake(
    stream: Stream,
    client_tls_offset: int,
    server_tls_offset: int,
) -> TlsHandshake:
    """
    Parses TLS record layer and handshake messages from client and server streams.
    Returns populated TlsHandshake dataclass.
    """
    handshake = TlsHandshake()

    def safe_frame_lookup(direction: str, off: int) -> int:
        try:
            return stream.frame_for_offset(direction, off)
        except Exception:
            return stream.firstFrame

    # 1. Parse Record Layer for Client and Server
    c_records, c_errors, c_alerts, c_enc_count = parse_tls_records(
        stream.clientBytes,
        client_tls_offset,
        lambda off: safe_frame_lookup("client", off),
    )

    s_records, s_errors, s_alerts, s_enc_count = parse_tls_records(
        stream.serverBytes,
        server_tls_offset,
        lambda off: safe_frame_lookup("server", off),
    )

    handshake.parse_errors.extend(c_errors)
    handshake.parse_errors.extend(s_errors)
    handshake.encrypted_record_count = c_enc_count + s_enc_count

    # Capture cleartext fatal alerts if present
    for alert in c_alerts + s_alerts:
        if alert.level == 2:
            handshake.fatal_alert = alert
            break

    # 2. Parse Client Handshake Messages
    client_payload = _reassemble_handshake_payload(c_records)
    c_idx = 0
    c_len = len(client_payload)

    while c_idx + 4 <= c_len:
        msg_type = client_payload[c_idx]
        msg_len = (client_payload[c_idx + 1] << 16) | (client_payload[c_idx + 2] << 8) | client_payload[c_idx + 3]
        from engine.smscope.limits import check_handshake_message_length, check_certificate_length
        check_handshake_message_length(msg_len)
        body_start = c_idx + 4
        body_end = body_start + msg_len

        if body_end > c_len:
            frame = safe_frame_lookup("client", client_tls_offset)
            handshake.parse_errors.append(TlsParseError(kind="truncated", offset=client_tls_offset + c_idx, frame=frame))
            break

        body = client_payload[body_start:body_end]

        if msg_type == HANDSHAKE_TYPE_CLIENT_HELLO:
            if len(body) >= 34:
                legacy_ver = struct.unpack("!H", body[:2])[0]
                rnd = body[2:34]
                sess_id_len = body[34]
                sess_id = body[35:35 + sess_id_len]
                b_off = 35 + sess_id_len

                if b_off + 2 <= len(body):
                    cs_len = struct.unpack("!H", body[b_off:b_off + 2])[0]
                    b_off += 2
                    ciphers = []
                    for i in range(b_off, min(len(body), b_off + cs_len), 2):
                        if i + 2 <= len(body):
                            ciphers.append(struct.unpack("!H", body[i:i + 2])[0])
                    b_off += cs_len

                    if b_off < len(body):
                        comp_len = body[b_off]
                        comp_methods = body[b_off + 1:b_off + 1 + comp_len]
                        b_off += 1 + comp_len

                        extensions: Dict[str, Any] = {}
                        ext_types: List[int] = []
                        if b_off + 2 <= len(body):
                            ext_total_len = struct.unpack("!H", body[b_off:b_off + 2])[0]
                            b_off += 2
                            extensions, ext_types = _parse_client_hello_extensions(body[b_off:b_off + ext_total_len])

                        handshake.client_hello = ClientHello(
                            legacy_version=legacy_ver,
                            random=rnd,
                            session_id=sess_id,
                            cipher_suites=ciphers,
                            compression_methods=comp_methods,
                            extensions=extensions,
                            extension_types=ext_types,
                        )

        c_idx = body_end

    # 3. Parse Server Handshake Messages
    server_payload = _reassemble_handshake_payload(s_records)
    s_idx = 0
    s_len = len(server_payload)

    is_tls13 = False

    while s_idx + 4 <= s_len:
        msg_type = server_payload[s_idx]
        msg_len = (server_payload[s_idx + 1] << 16) | (server_payload[s_idx + 2] << 8) | server_payload[s_idx + 3]
        from engine.smscope.limits import check_handshake_message_length, check_certificate_length
        check_handshake_message_length(msg_len)
        body_start = s_idx + 4
        body_end = body_start + msg_len

        if body_end > s_len:
            frame = safe_frame_lookup("server", server_tls_offset)
            handshake.parse_errors.append(TlsParseError(kind="truncated", offset=server_tls_offset + s_idx, frame=frame))
            break

        body = server_payload[body_start:body_end]

        if msg_type == HANDSHAKE_TYPE_SERVER_HELLO:
            if len(body) >= 34:
                ver = struct.unpack("!H", body[:2])[0]
                rnd = body[2:34]
                sess_id_len = body[34]
                sess_id = body[35:35 + sess_id_len]
                b_off = 35 + sess_id_len

                if b_off + 2 <= len(body):
                    cs = struct.unpack("!H", body[b_off:b_off + 2])[0]
                    b_off += 2
                    comp_method = body[b_off] if b_off < len(body) else 0
                    b_off += 1

                    extensions = {}
                    ext_types = []
                    if b_off + 2 <= len(body):
                        ext_total_len = struct.unpack("!H", body[b_off:b_off + 2])[0]
                        b_off += 2
                        extensions, ext_types = _parse_server_hello_extensions(body[b_off:b_off + ext_total_len])

                    handshake.server_hello = ServerHello(
                        version=ver,
                        random=rnd,
                        session_id=sess_id,
                        cipher_suite=cs,
                        compression_method=comp_method,
                        extensions=extensions,
                        extension_types=ext_types,
                    )

                    # Check HelloRetryRequest
                    if rnd == HRR_RANDOM:
                        handshake.is_hello_retry_request = True

                    # Determine Negotiated Version
                    if "supported_versions" in extensions:
                        handshake.negotiated_version = extensions["supported_versions"]
                    else:
                        handshake.negotiated_version = ver

                    if handshake.negotiated_version == 0x0304:
                        is_tls13 = True

        elif msg_type == HANDSHAKE_TYPE_CERTIFICATE:
            if is_tls13:
                # TLS 1.3 Certificate (RFC 8446)
                if len(body) >= 4:
                    context_len = body[0]
                    b_off = 1 + context_len
                    if b_off + 3 <= len(body):
                        certs_total_len = (body[b_off] << 16) | (body[b_off + 1] << 8) | body[b_off + 2]
                        b_off += 3
                        while b_off + 3 <= len(body) and b_off < len(body):
                            cert_len = (body[b_off] << 16) | (body[b_off + 1] << 8) | body[b_off + 2]
                            check_certificate_length(cert_len)
                            b_off += 3
                            if b_off + cert_len <= len(body):
                                handshake.certificates.append(body[b_off:b_off + cert_len])
                            b_off += cert_len
                            # Skip extensions
                            if b_off + 2 <= len(body):
                                ext_len = struct.unpack("!H", body[b_off:b_off + 2])[0]
                                b_off += 2 + ext_len
            else:
                # TLS 1.2 Certificate (RFC 5246)
                if len(body) >= 3:
                    certs_total_len = (body[0] << 16) | (body[1] << 8) | body[2]
                    b_off = 3
                    while b_off + 3 <= len(body) and b_off < 3 + certs_total_len:
                        cert_len = (body[b_off] << 16) | (body[b_off + 1] << 8) | body[b_off + 2]
                        check_certificate_length(cert_len)
                        b_off += 3
                        if b_off + cert_len <= len(body):
                            handshake.certificates.append(body[b_off:b_off + cert_len])
                        b_off += cert_len

        elif msg_type == HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
            param_type = "unknown"
            named_curve = None
            dh_bits = None

            if len(body) >= 3 and body[0] == 3:  # named_curve
                param_type = "ec_diffie_hellman"
                named_curve = struct.unpack("!H", body[1:3])[0]
            elif len(body) >= 2:
                p_len = struct.unpack("!H", body[:2])[0]
                if len(body) >= 2 + p_len:
                    param_type = "diffie_hellman"
                    dh_bits = p_len * 8

            handshake.server_key_exchange = ServerKeyExchange(
                param_type=param_type,
                raw_bytes=body,
                named_curve=named_curve,
                dh_p_bits=dh_bits,
            )

        elif msg_type == HANDSHAKE_TYPE_CERTIFICATE_STATUS:
            if len(body) >= 4:
                status_type = body[0]
                resp_len = (body[1] << 16) | (body[2] << 8) | body[3]
                resp = body[4:4 + resp_len] if len(body) >= 4 + resp_len else b""
                handshake.certificate_status = CertificateStatus(
                    status_type=status_type,
                    ocsp_response=resp,
                )

        s_idx = body_end

        # In TLS 1.3, everything after ServerHello is encrypted
        if is_tls13 and handshake.server_hello is not None:
            break

    return handshake
