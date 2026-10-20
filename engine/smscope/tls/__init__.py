"""TLS analysis stage for SecureMailScope."""
from typing import List
from engine.smscope.models import SessionRecord
from engine.smscope.tls.records import (
    TlsRecord,
    TlsParseError,
    TlsAlert,
    parse_tls_records,
)
from engine.smscope.tls.handshake import (
    ClientHello,
    ServerHello,
    ServerKeyExchange,
    CertificateStatus,
    TlsHandshake,
    parse_tls_handshake,
)
from engine.smscope.tls.negotiation import (
    compute_ja3,
    compute_ja3s,
    compute_ja3_string,
    compute_ja3s_string,
    filter_grease,
    negotiate_tls,
)


def process_tls(sessions: List[SessionRecord]) -> List[SessionRecord]:
    """Parses TLS records, handshake messages, and negotiates TLS parameters."""
    for sess in sessions:
        stream = getattr(sess, "stream", None)
        if stream is not None:
            is_tls = (
                sess.transportMode in ("starttls", "tls", "implicitTls")
                or sess.clientTlsStartOffset is not None
                or sess.protocol in ("smtps", "imaps", "pop3s")
            )
            if is_tls:
                hs = parse_tls_handshake(stream, sess.clientTlsStartOffset, sess.serverTlsStartOffset)
                if hs:
                    sess.tls = negotiate_tls(hs)
                    sess._raw_certificates = hs.certificates
                    sess._sni = hs.sni
                    sess._certificate_ts_sec = hs.certificate_ts_sec
                    sess._certificate_frame = hs.certificate_frame
                    sess._server_hello_frame = hs.server_hello_frame
                    sess._server_key_exchange_frame = hs.server_key_exchange_frame
    return sessions
