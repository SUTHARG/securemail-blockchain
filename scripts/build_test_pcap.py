"""Synthesize test PCAP files using struct without external dependencies."""
import hashlib
import socket
import struct
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
CAPTURES_DIR = REPO_ROOT / "lab" / "captures"
CA_OUT = REPO_ROOT / "lab" / "ca" / "out"

CLIENT_IP = socket.inet_aton("172.28.0.20")
SERVER_IP = socket.inet_aton("172.28.0.10")
CLIENT_MAC = b"\x02\x42\xac\x1c\x00\x14"
SERVER_MAC = b"\x02\x42\xac\x1c\x00\x0a"
CLIENT_PORT = 45000
SERVER_PORT = 25


def ip_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


class RawPcapWriter:
    def __init__(self, filepath: Path, server_port: int = 25, client_port: int = CLIENT_PORT):
        self.filepath = filepath
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        self.server_port = server_port
        self.client_port = client_port
        self.f = open(filepath, "wb")
        # Global header: magic (0xa1b2c3d4), v2.4, zone 0, sigfigs 0, snaplen 65535, linktype 1 (Ethernet)
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.ts_sec = 1792000000
        self.ts_usec = 0
        self.client_seq = 1000
        self.server_seq = 5000

    def start_session(self, client_port: int):
        self.client_port = client_port
        self.client_seq = 1000
        self.server_seq = 5000
        self.handshake()

    def close(self):
        self.f.close()

    def _write_frame(self, src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags, seq, ack, payload=b""):
        # TCP header without checksum
        data_offset = (5 << 4)  # 5 * 4 = 20 bytes
        tcp_hdr = struct.pack(
            "!HHIIBBHHH",
            sport,
            dport,
            seq,
            ack,
            data_offset,
            flags,
            65535,
            0,  # checksum placeholder
            0,
        )
        # Pseudo-header for TCP checksum
        pseudo = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, 6, len(tcp_hdr) + len(payload))
        csum = ip_checksum(pseudo + tcp_hdr + payload)
        tcp_hdr = struct.pack(
            "!HHIIBBHHH",
            sport,
            dport,
            seq,
            ack,
            data_offset,
            flags,
            65535,
            csum,
            0,
        )
        tcp_packet = tcp_hdr + payload

        # IPv4 header
        ip_total_len = 20 + len(tcp_packet)
        ip_hdr_no_csum = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            ip_total_len,
            12345,
            0x4000,  # Don't fragment
            64,
            6,  # TCP
            0,
            src_ip,
            dst_ip,
        )
        ip_csum = ip_checksum(ip_hdr_no_csum)
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            ip_total_len,
            12345,
            0x4000,
            64,
            6,
            ip_csum,
            src_ip,
            dst_ip,
        )
        ip_packet = ip_hdr + tcp_packet

        # Ethernet frame
        eth_frame = dst_mac + src_mac + struct.pack("!H", 0x0800) + ip_packet

        # PCAP record header
        record_hdr = struct.pack("<IIII", self.ts_sec, self.ts_usec, len(eth_frame), len(eth_frame))
        self.f.write(record_hdr + eth_frame)
        self.ts_usec += 10000
        if self.ts_usec >= 1000000:
            self.ts_sec += 1
            self.ts_usec = 0

    def send_client(self, payload=b"", flags=0x10):  # ACK
        self._write_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, self.client_port, self.server_port, flags, self.client_seq, self.server_seq, payload)
        self.client_seq += len(payload)

    def send_server(self, payload=b"", flags=0x10):  # ACK
        self._write_frame(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, self.server_port, self.client_port, flags, self.server_seq, self.client_seq, payload)
        self.server_seq += len(payload)

    def handshake(self):
        # SYN
        self._write_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, self.client_port, self.server_port, 0x02, self.client_seq, 0)
        self.client_seq += 1
        # SYN-ACK
        self._write_frame(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, self.server_port, self.client_port, 0x12, self.server_seq, self.client_seq)
        self.server_seq += 1
        # ACK
        self._write_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, self.client_port, self.server_port, 0x10, self.client_seq, self.server_seq)


def build_s05():
    """S05: No STARTTLS, cleartext authentication."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S05.pcap")
    pcap.handshake()

    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-PIPELINING\r\n250-AUTH PLAIN LOGIN\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"AUTH PLAIN AGxhYnVzZXIAfieldQ==\r\n")
    pcap.send_server(b"235 2.7.0 Authentication successful\r\n")
    pcap.send_client(b"MAIL FROM:<sender@lab.local>\r\n")
    pcap.send_server(b"250 2.1.0 Ok\r\n")
    pcap.send_client(b"RCPT TO:<recipient@lab.local>\r\n")
    pcap.send_server(b"250 2.1.5 Ok\r\n")
    pcap.send_client(b"QUIT\r\n")
    pcap.send_server(b"221 2.0.0 Bye\r\n")
    pcap.close()
    print("[+] Generated S05.pcap")


def build_s06():
    """S06: STARTTLS offered but optional, client continues in plaintext."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S06.pcap")
    pcap.handshake()

    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"MAIL FROM:<sender@lab.local>\r\n")
    pcap.send_server(b"250 2.1.0 Ok\r\n")
    pcap.send_client(b"RCPT TO:<recipient@lab.local>\r\n")
    pcap.send_server(b"250 2.1.5 Ok\r\n")
    pcap.send_client(b"QUIT\r\n")
    pcap.send_server(b"221 2.0.0 Bye\r\n")
    pcap.close()
    print("[+] Generated S06.pcap")



def build_tls_handshake_bytes():
    """Constructs valid TLS 1.2 ClientHello, ServerHello, and Certificate records."""
    cert_path = CA_OUT / "valid-2048-sha256.crt"
    der_bytes = b""
    if cert_path.exists():
        pem_text = cert_path.read_text(encoding="utf-8")
        import base64
        in_cert = False
        b64_lines = []
        for l in pem_text.splitlines():
            if "-----BEGIN CERTIFICATE-----" in l:
                in_cert = True
                continue
            if "-----END CERTIFICATE-----" in l:
                break
            if in_cert:
                b64_lines.append(l.strip())
        der_bytes = base64.b64decode("".join(b64_lines))
    if not der_bytes:
        der_bytes = b"\x30\x82\x01\x00" + b"\x00" * 256

    # 1. ClientHello
    sni_bytes = b"172.28.0.10"
    sni_ext = b"\x00\x00" + (len(sni_bytes) + 5).to_bytes(2, "big") + (len(sni_bytes) + 3).to_bytes(2, "big") + b"\x00" + len(sni_bytes).to_bytes(2, "big") + sni_bytes
    supp_vers_ext = b"\x00\x2b\x00\x03\x02\x03\x03"
    extensions = sni_ext + supp_vers_ext
    ciphers = b"\xc0\x2f\xc0\x2b\x00\x9f\x00\x9c"
    ch_body = (
        b"\x03\x03"
        + b"\xaa" * 32
        + b"\x00"
        + len(ciphers).to_bytes(2, "big") + ciphers
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big") + extensions
    )
    ch_hs = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
    ch_record = b"\x16\x03\x03" + len(ch_hs).to_bytes(2, "big") + ch_hs

    # 2. ServerHello
    sh_body = (
        b"\x03\x03"
        + b"\xbb" * 32
        + b"\x00"
        + b"\xc0\x2f"
        + b"\x00"
    )
    sh_hs = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body
    sh_record = b"\x16\x03\x03" + len(sh_hs).to_bytes(2, "big") + sh_hs

    # 3. Certificate message
    cert_list_payload = len(der_bytes).to_bytes(3, "big") + der_bytes
    cert_hs_body = len(cert_list_payload).to_bytes(3, "big") + cert_list_payload
    cert_hs = b"\x0b" + len(cert_hs_body).to_bytes(3, "big") + cert_hs_body
    cert_record = b"\x16\x03\x03" + len(cert_hs).to_bytes(2, "big") + cert_hs

    # 4. ServerHelloDone
    shd_hs = b"\x0e\x00\x00\x00"
    shd_record = b"\x16\x03\x03\x00\x04" + shd_hs

    return ch_record, sh_record + cert_record + shd_record


def build_s01a():
    """S01a: Valid STARTTLS, TLS 1.2 handshake."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S01a.pcap")
    pcap.handshake()

    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")

    ch_rec, sh_certs_rec = build_tls_handshake_bytes()
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)

    pcap.close()
    print("[+] Generated S01a.pcap")


def build_x02():
    """X02: Small segments (MSS clamped to 100)."""
    pcap = RawPcapWriter(CAPTURES_DIR / "X02.pcap")
    pcap.handshake()

    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")

    ch_rec, sh_certs_rec = build_tls_handshake_bytes()
    
    chunk_size = 80
    for i in range(0, len(ch_rec), chunk_size):
        pcap.send_client(ch_rec[i:i+chunk_size])

    for i in range(0, len(sh_certs_rec), chunk_size):
        pcap.send_server(sh_certs_rec[i:i+chunk_size])

    pcap.close()
    print("[+] Generated X02.pcap")


def build_x01():
    """X01: Reordering and duplication (stress test)."""
    pcap = RawPcapWriter(CAPTURES_DIR / "X01.pcap")
    pcap.handshake()

    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")

    ch_rec, sh_certs_rec = build_tls_handshake_bytes()

    # Client side: send segment 2, then segment 1, duplicate segment 2, then segment 3
    s1 = ch_rec[:40]
    s2 = ch_rec[40:80]
    s3 = ch_rec[80:]
    seq0 = pcap.client_seq

    # Send s2 (out-of-order)
    pcap._write_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, 0x10, seq0 + len(s1), pcap.server_seq, s2)
    # Send s1
    pcap._write_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, 0x10, seq0, pcap.server_seq, s1)
    # Duplicate s2
    pcap._write_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, 0x10, seq0 + len(s1), pcap.server_seq, s2)
    # Send s3
    pcap._write_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, 0x10, seq0 + len(s1) + len(s2), pcap.server_seq, s3)
    pcap.client_seq = seq0 + len(ch_rec)

    # Server side: normal delivery with a duplicate segment
    sh_s1 = sh_certs_rec[:100]
    sh_s2 = sh_certs_rec[100:]
    pcap.send_server(sh_s1)
    # Duplicate sh_s1
    pcap._write_frame(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, 0x10, pcap.server_seq - len(sh_s1), pcap.client_seq, sh_s1)
    pcap.send_server(sh_s2)

    pcap.close()
    print("[+] Generated X01.pcap")


def build_x03():
    """X03: Packet loss resulting in unfillable sequence gap."""
    pcap = RawPcapWriter(CAPTURES_DIR / "X03.pcap")
    pcap.handshake()

    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")

    ch_rec, sh_certs_rec = build_tls_handshake_bytes()

    # Client side: send prefix, skip middle chunk (loss), send suffix
    s1 = ch_rec[:40]
    s2 = ch_rec[40:80]  # DROPPED
    s3 = ch_rec[80:]
    seq0 = pcap.client_seq

    # Send s1
    pcap._write_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, 0x10, seq0, pcap.server_seq, s1)
    # Skip s2 (never sent)
    # Send s3 (future segment creating gap)
    pcap._write_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, 0x10, seq0 + len(s1) + len(s2), pcap.server_seq, s3)
    pcap.client_seq = seq0 + len(ch_rec)

    pcap.send_server(sh_certs_rec)

    pcap.close()
    print("[+] Generated X03.pcap")


def build_s13():
    """S13: Implicit TLS on port 465."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S13.pcap")
    # Handshake on port 465
    sport = CLIENT_PORT
    dport = 465

    # SYN
    pcap._write_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, sport, dport, 0x02, pcap.client_seq, 0)
    pcap.client_seq += 1
    # SYN-ACK
    pcap._write_frame(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, dport, sport, 0x12, pcap.server_seq, pcap.client_seq)
    pcap.server_seq += 1
    # ACK
    pcap._write_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, sport, dport, 0x10, pcap.client_seq, pcap.server_seq)

    # Immediately TLS ClientHello (implicit TLS, no plaintext greeting)
    ch_rec, sh_certs_rec = build_tls_handshake_bytes()
    pcap._write_frame(CLIENT_MAC, SERVER_MAC, CLIENT_IP, SERVER_IP, sport, dport, 0x10, pcap.client_seq, pcap.server_seq, ch_rec)
    pcap.client_seq += len(ch_rec)

    pcap._write_frame(SERVER_MAC, CLIENT_MAC, SERVER_IP, CLIENT_IP, dport, sport, 0x10, pcap.server_seq, pcap.client_seq, sh_certs_rec)
    pcap.server_seq += len(sh_certs_rec)

    pcap.close()
    print("[+] Generated S13.pcap")


def build_custom_tls_handshake_bytes(
    version: int = 0x0303,
    cipher: int = 0xC02F,
    client_ciphers: Optional[List[int]] = None,
    client_session_id: bytes = b"",
    server_session_id: bytes = b"",
    include_cert: bool = True,
    named_curve: Optional[int] = None,
    dh_bits: Optional[int] = None,
    sni: bytes = b"172.28.0.10",
    cert_name: str = "valid-2048-sha256.crt",
    cert_bytes: Optional[bytes] = None,
):
    if cert_bytes is not None:
        der_bytes = cert_bytes
    else:
        cert_path = CA_OUT / cert_name
        der_bytes = b""
        if cert_path.exists():
            pem_text = cert_path.read_text(encoding="utf-8")
            import base64
            in_cert = False
            b64_lines = []
            for l in pem_text.splitlines():
                if "-----BEGIN CERTIFICATE-----" in l:
                    in_cert = True
                    continue
                if "-----END CERTIFICATE-----" in l:
                    break
                if in_cert:
                    b64_lines.append(l.strip())
            der_bytes = base64.b64decode("".join(b64_lines))
        if not der_bytes:
            der_bytes = b"\x30\x82\x01\x00" + b"\x00" * 256

    # 1. ClientHello
    sni_bytes = sni
    sni_ext = b"\x00\x00" + (len(sni_bytes) + 5).to_bytes(2, "big") + (len(sni_bytes) + 3).to_bytes(2, "big") + b"\x00" + len(sni_bytes).to_bytes(2, "big") + sni_bytes
    supp_vers_ext = b"\x00\x2b\x00\x03\x02" + version.to_bytes(2, "big")
    extensions = sni_ext + supp_vers_ext
    c_list = client_ciphers or [cipher]
    ciphers_bytes = b"".join(c.to_bytes(2, "big") for c in c_list)
    ch_body = (
        version.to_bytes(2, "big")
        + b"\xaa" * 32
        + len(client_session_id).to_bytes(1, "big") + client_session_id
        + len(ciphers_bytes).to_bytes(2, "big") + ciphers_bytes
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big") + extensions
    )
    ch_hs = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
    ch_record = b"\x16" + version.to_bytes(2, "big") + len(ch_hs).to_bytes(2, "big") + ch_hs

    # 2. ServerHello
    sh_body = (
        version.to_bytes(2, "big")
        + b"\xbb" * 32
        + len(server_session_id).to_bytes(1, "big") + server_session_id
        + cipher.to_bytes(2, "big")
        + b"\x00"
    )
    sh_hs = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body
    sh_record = b"\x16" + version.to_bytes(2, "big") + len(sh_hs).to_bytes(2, "big") + sh_hs

    server_records = sh_record

    # 3. Certificate
    if include_cert:
        cert_list_payload = len(der_bytes).to_bytes(3, "big") + der_bytes
        cert_hs_body = len(cert_list_payload).to_bytes(3, "big") + cert_list_payload
        cert_hs = b"\x0b" + len(cert_hs_body).to_bytes(3, "big") + cert_hs_body
        cert_record = b"\x16" + version.to_bytes(2, "big") + len(cert_hs).to_bytes(2, "big") + cert_hs
        server_records += cert_record

    # 4. ServerKeyExchange (if named_curve or dh_bits)
    if named_curve is not None:
        ske_body = b"\x03" + named_curve.to_bytes(2, "big") + b"\x20" + (b"\x33" * 32) + b"\x04\x01\x00\x40" + (b"\x77" * 64)
        ske_hs = b"\x0c" + len(ske_body).to_bytes(3, "big") + ske_body
        ske_record = b"\x16" + version.to_bytes(2, "big") + len(ske_hs).to_bytes(2, "big") + ske_hs
        server_records += ske_record
    elif dh_bits is not None:
        p_len_bytes = dh_bits // 8
        p_bytes = b"\xff" * p_len_bytes
        g_bytes = b"\x02"
        ys_bytes = b"\x11" * p_len_bytes
        ske_body = (
            len(p_bytes).to_bytes(2, "big") + p_bytes
            + len(g_bytes).to_bytes(2, "big") + g_bytes
            + len(ys_bytes).to_bytes(2, "big") + ys_bytes
            + b"\x04\x01\x00\x40" + (b"\x77" * 64)
        )
        ske_hs = b"\x0c" + len(ske_body).to_bytes(3, "big") + ske_body
        ske_record = b"\x16" + version.to_bytes(2, "big") + len(ske_hs).to_bytes(2, "big") + ske_hs
        server_records += ske_record

    # 5. ServerHelloDone
    shd_hs = b"\x0e\x00\x00\x00"
    shd_record = b"\x16" + version.to_bytes(2, "big") + b"\x00\x04" + shd_hs
    server_records += shd_record

    return ch_record, server_records


def build_s01b():
    """S01b: Valid STARTTLS, TLS 1.3 handshake (encrypted certificate)."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S01b.pcap")
    pcap.handshake()

    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")

    sni_bytes = b"172.28.0.10"
    sni_ext = b"\x00\x00" + (len(sni_bytes) + 5).to_bytes(2, "big") + (len(sni_bytes) + 3).to_bytes(2, "big") + b"\x00" + len(sni_bytes).to_bytes(2, "big") + sni_bytes
    supp_vers_ext = b"\x00\x2b\x00\x05\x04\x03\x04\x03\x03"
    ks_ext = b"\x00\x33\x00\x26\x00\x24\x00\x1d\x00\x20" + (b"\x44" * 32)
    extensions = sni_ext + supp_vers_ext + ks_ext
    ciphers = b"\x13\x01\x13\x02\xc0\x2f"
    ch_body = (
        b"\x03\x03"
        + b"\xaa" * 32
        + b"\x00"
        + len(ciphers).to_bytes(2, "big") + ciphers
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big") + extensions
    )
    ch_hs = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body
    ch_record = b"\x16\x03\x03" + len(ch_hs).to_bytes(2, "big") + ch_hs

    sh_supp_vers = b"\x00\x2b\x00\x02\x03\x04"
    sh_ks = b"\x00\x33\x00\x24\x00\x1d\x00\x20" + (b"\xee" * 32)
    sh_extensions = sh_supp_vers + sh_ks
    sh_body = (
        b"\x03\x03"
        + b"\xbb" * 32
        + b"\x00"
        + b"\x13\x01"
        + b"\x00"
        + len(sh_extensions).to_bytes(2, "big") + sh_extensions
    )
    sh_hs = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body
    sh_record = b"\x16\x03\x03" + len(sh_hs).to_bytes(2, "big") + sh_hs

    ccs_record = b"\x14\x03\x03\x00\x01\x01"
    enc_app1 = b"\x17\x03\x03\x00\x40" + (b"\x99" * 64)
    enc_app2 = b"\x17\x03\x03\x00\x80" + (b"\x88" * 128)

    pcap.send_client(ch_record)
    pcap.send_server(sh_record + ccs_record + enc_app1 + enc_app2)

    pcap.close()
    print("[+] Generated S01b.pcap")


def build_s02():
    """S02: STARTTLS, TLS 1.0 negotiated."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S02.pcap")
    pcap.handshake()

    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")

    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0301,
        cipher=0x002F,
        client_ciphers=[0x002F, 0x000A],
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)

    pcap.close()
    print("[+] Generated S02.pcap")


def build_s03():
    """S03: STARTTLS, 3DES cipher negotiated."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S03.pcap")
    pcap.handshake()

    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")

    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0x000A,
        client_ciphers=[0x000A, 0x002F],
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)

    pcap.close()
    print("[+] Generated S03.pcap")


def build_s07():
    """S07: STARTTLS, static RSA suite AES256-GCM-SHA384 (no forward secrecy)."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S07.pcap")
    pcap.handshake()

    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")

    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0x009D,
        client_ciphers=[0x009D, 0x002F],
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)

    pcap.close()
    print("[+] Generated S07.pcap")


def build_s12():
    """S12: STARTTLS, resumed TLS 1.2 session (no certificate on wire)."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S12.pcap")
    pcap.handshake()

    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")

    session_id = b"\x77" * 32
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        client_session_id=session_id,
        server_session_id=session_id,
        include_cert=False,
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)

    pcap.close()
    print("[+] Generated S12.pcap")


def build_s04():
    """S04: Expired certificate."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S04.pcap")
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        cert_name="expired.crt",
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated S04.pcap")


def build_s08():
    """S08: RSA key below 2048 bits (1024-bit)."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S08.pcap")
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        cert_name="rsa1024.crt",
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated S08.pcap")


def build_s09():
    """S09: SHA-1 signature on certificate."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S09.pcap")
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        cert_name="sha1.crt",
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated S09.pcap")


def build_s10():
    """S10: Self-signed leaf certificate."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S10.pcap")
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        cert_name="self-signed.crt",
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated S10.pcap")


def build_s11():
    """S11: Untrusted root CA absent from trust store."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S11.pcap")
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        cert_name="untrusted-ca.crt",
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated S11.pcap")


def build_s20():
    """S20: IMAP STARTTLS, TLS 1.2, valid."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S20.pcap", server_port=143)
    pcap.handshake()
    pcap.send_server(b"* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] Dovecot ready.\r\n")
    pcap.send_client(b"a1 STARTTLS\r\n")
    pcap.send_server(b"a1 OK Begin TLS negotiation now.\r\n")
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        cert_name="mailserver.crt",
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated S20.pcap")


def build_s21():
    """S21: IMAP cleartext LOGIN, no TLS."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S21.pcap", server_port=143)
    pcap.handshake()
    pcap.send_server(b"* OK Dovecot ready.\r\n")
    pcap.send_client(b"a1 LOGIN labuser LabPass-123!\r\n")
    pcap.send_server(b"a1 OK Logged in.\r\n")
    pcap.close()
    print("[+] Generated S21.pcap")


def build_s22():
    """S22: IMAP implicit TLS on port 993."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S22.pcap", server_port=993)
    pcap.handshake()
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        cert_name="mailserver.crt",
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated S22.pcap")


def build_s23():
    """S23: POP3 STLS, TLS 1.2, valid."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S23.pcap", server_port=110)
    pcap.handshake()
    pcap.send_server(b"+OK Dovecot ready.\r\n")
    pcap.send_client(b"CAPA\r\n")
    pcap.send_server(b"+OK Capability list follows\r\nSTLS\r\nUSER\r\nSASL PLAIN\r\n.\r\n")
    pcap.send_client(b"STLS\r\n")
    pcap.send_server(b"+OK Begin TLS negotiation\r\n")
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        cert_name="mailserver.crt",
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated S23.pcap")


def build_s24():
    """S24: POP3 cleartext USER and PASS, no TLS."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S24.pcap", server_port=110)
    pcap.handshake()
    pcap.send_server(b"+OK Dovecot ready.\r\n")
    pcap.send_client(b"USER labuser\r\n")
    pcap.send_server(b"+OK User accepted\r\n")
    pcap.send_client(b"PASS LabPass-123!\r\n")
    pcap.send_server(b"+OK Logged in\r\n")
    pcap.close()
    print("[+] Generated S24.pcap")


def build_s25():
    """S25: POP3 implicit TLS on port 995."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S25.pcap", server_port=995)
    pcap.handshake()
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        cert_name="mailserver.crt",
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated S25.pcap")


def get_or_create_second_valid_cert_der() -> bytes:
    cert_path = CA_OUT / "valid2-2048-sha256.der"
    if cert_path.exists():
        return cert_path.read_bytes()

    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    ca_key_path = REPO_ROOT / "lab" / "ca" / "demoCA" / "ca.key"
    ca_crt_path = CA_OUT / "ca.crt"
    if ca_key_path.exists() and ca_crt_path.exists():
        ca_priv = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(ca_crt_path.read_bytes())
    else:
        # Fallback to local root
        ca_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_subj = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "SecureMailScope Root CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subj)
            .issuer_name(ca_subj)
            .public_key(ca_priv.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_priv, hashes.SHA256())
        )

    priv2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert2 = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(x509.NameOID.COMMON_NAME, "172.28.0.10"),
                    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "SecureMailScope Secondary Node"),
                ]
            )
        )
        .issuer_name(ca_cert.subject)
        .public_key(priv2.public_key())
        .serial_number(99999)
        .not_valid_before(datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.IPAddress(ipaddress.IPv4Address("172.28.0.10")),
                    x509.DNSName("mailserver.lab.local"),
                ]
            ),
            critical=False,
        )
        .sign(ca_priv, hashes.SHA256())
    )
    der = cert2.public_bytes(serialization.Encoding.DER)
    cert_path.write_bytes(der)
    return der


def build_s30():
    """S30: SMTP server answers STARTTLS with 454; client continues in plaintext -> R04."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S30.pcap")
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"454 4.7.0 TLS not available due to temporary reason\r\n")
    pcap.send_client(b"MAIL FROM:<sender@lab.local>\r\n")
    pcap.send_server(b"250 2.1.0 Ok\r\n")
    pcap.send_client(b"RCPT TO:<recipient@lab.local>\r\n")
    pcap.send_server(b"250 2.1.5 Ok\r\n")
    pcap.send_client(b"QUIT\r\n")
    pcap.send_server(b"221 2.0.0 Bye\r\n")
    pcap.close()
    print("[+] Generated S30.pcap")


def build_s31():
    """S31: SSL 3.0 and anonymous cipher (TLS_DH_anon_WITH_AES_128_CBC_SHA 0x0034) -> R05 and R07."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S31.pcap")
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0300,  # SSL 3.0 -> R05
        cipher=0x0034,   # TLS_DH_anon_WITH_AES_128_CBC_SHA -> R07 (anon)
        include_cert=False,
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated S31.pcap")


def build_s32():
    """S32: DHE with a 1024-bit prime -> R10."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S32.pcap")
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0x0033,  # TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        dh_bits=1024,   # 1024-bit prime -> R10
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated S32.pcap")


def build_s33():
    """S33: SNI does not match certificate SAN -> R14."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S33.pcap")
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        sni=b"unmatched.example.com",  # Doesn't match cert -> R14
        cert_name="valid-2048-sha256.crt",
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated S33.pcap")


def build_s34():
    """S34: Proxy removes STARTTLS in session 2 -> R17 and R02."""
    pcap = RawPcapWriter(CAPTURES_DIR / "S34.pcap", client_port=45001)
    # Session 1: Clean STARTTLS
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(version=0x0303, cipher=0xC02F)
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)

    # Session 2: Proxy strips STARTTLS (client_port=45002)
    pcap.start_session(client_port=45002)
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"MAIL FROM:<sender@lab.local>\r\n")
    pcap.send_server(b"250 2.1.0 Ok\r\n")
    pcap.send_client(b"QUIT\r\n")
    pcap.send_server(b"221 2.0.0 Bye\r\n")
    pcap.close()
    print("[+] Generated S34.pcap")


def build_s35():
    """S35: Server certificate replaced between two sessions -> R18."""
    cert2_bytes = get_or_create_second_valid_cert_der()

    pcap = RawPcapWriter(CAPTURES_DIR / "S35.pcap", client_port=45001)
    # Session 1: Certificate 1 (valid-2048-sha256.crt)
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec1, sh_certs_rec1 = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        cert_name="valid-2048-sha256.crt",
    )
    pcap.send_client(ch_rec1)
    pcap.send_server(sh_certs_rec1)

    # Session 2: Certificate 2 (distinct leaf fingerprint)
    pcap.start_session(client_port=45002)
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec2, sh_certs_rec2 = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        cert_bytes=cert2_bytes,
    )
    pcap.send_client(ch_rec2)
    pcap.send_server(sh_certs_rec2)
    pcap.close()
    print("[+] Generated S35.pcap")


def build_a1():
    """A1: Injected anomaly - Server certificate changes between sessions."""
    cert2_bytes = get_or_create_second_valid_cert_der()
    pcap = RawPcapWriter(CAPTURES_DIR / "A1.pcap", client_port=45001)

    # Session 1: Certificate 1
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec1, sh_certs_rec1 = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        cert_name="valid-2048-sha256.crt",
    )
    pcap.send_client(ch_rec1)
    pcap.send_server(sh_certs_rec1)

    # Session 2: Certificate 2
    pcap.start_session(client_port=45002)
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec2, sh_certs_rec2 = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0xC02F,
        cert_bytes=cert2_bytes,
    )
    pcap.send_client(ch_rec2)
    pcap.send_server(sh_certs_rec2)
    pcap.close()
    print("[+] Generated A1.pcap")


def build_a2():
    """A2: Injected anomaly - One client suddenly negotiates TLS 1.0 where baseline used 1.2."""
    pcap = RawPcapWriter(CAPTURES_DIR / "A2.pcap")
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0301,  # TLS 1.0
        cipher=0xC02F,
        cert_name="valid-2048-sha256.crt",
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated A2.pcap")


def build_a3():
    """A3: Injected anomaly - Client with an unseen JA3."""
    pcap = RawPcapWriter(CAPTURES_DIR / "A3.pcap")
    pcap.handshake()
    pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
    pcap.send_client(b"EHLO mail.lab.local\r\n")
    pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
    pcap.send_client(b"STARTTLS\r\n")
    pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")
    ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
        version=0x0303,
        cipher=0x009C,
        client_ciphers=[0xCCA9, 0xCCA8, 0x009C, 0x002F, 0x000A],
        cert_name="valid-2048-sha256.crt",
    )
    pcap.send_client(ch_rec)
    pcap.send_server(sh_certs_rec)
    pcap.close()
    print("[+] Generated A3.pcap")


if __name__ == "__main__":
    build_s01a()
    build_s01b()
    build_s02()
    build_s03()
    build_s04()
    build_s05()
    build_s06()
    build_s07()
    build_s08()
    build_s09()
    build_s10()
    build_s11()
    build_s12()
    build_s13()
    build_s20()
    build_s21()
    build_s22()
    build_s23()
    build_s24()
    build_s25()
    build_s30()
    build_s31()
    build_s32()
    build_s33()
    build_s34()
    build_s35()
    build_a1()
    build_a2()
    build_a3()
    build_x01()
    build_x02()
    build_x03()




