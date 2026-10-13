"""Generate baseline dataset (>=200 clean sessions) and train advisory Isolation Forest model (Tier 2 / Prompt T2.4)."""
import os
import struct
import sys
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.build_test_pcap import (
    RawPcapWriter,
    build_custom_tls_handshake_bytes,
    CLIENT_MAC,
    SERVER_MAC,
    CLIENT_IP,
    SERVER_IP,
)
from engine.smscope.ingest.reassembly import reassemble_pcap
from engine.smscope.protocols.smtp import track_session
from engine.smscope.tls.handshake import parse_tls_handshake
from engine.smscope.tls.negotiation import negotiate_tls
from engine.smscope.certs.analyze import analyze_certificate_chain
from advisory.anomaly.detector import AnomalyDetector

CAPTURES_DIR = REPO_ROOT / "lab" / "captures"
ADVISORY_DIR = REPO_ROOT / "advisory" / "anomaly"
TRUST_STORE_PATH = REPO_ROOT / "lab" / "ca" / "out" / "client_trust.crt"


# 5 client profiles representing different MTAs / client software (e.g. Postfix, Exim, Thunderbird, Python, curl)
CLIENT_PROFILES = [
    {
        "name": "standard_mta",
        "ciphers": [0xC02F, 0xC02B, 0x009F, 0x009C],
        "version": 0x0303,
    },
    {
        "name": "modern_client",
        "ciphers": [0xC02B, 0xC02F, 0xC030, 0x009E],
        "version": 0x0303,
    },
    {
        "name": "enterprise_mta",
        "ciphers": [0x009D, 0x009C, 0xC02F],
        "version": 0x0303,
    },
    {
        "name": "submission_agent",
        "ciphers": [0xC02F, 0x009C, 0xC014],
        "version": 0x0303,
    },
    {
        "name": "fetchmail_agent",
        "ciphers": [0xC030, 0xC02C, 0x009F],
        "version": 0x0303,
    },
]


def build_baseline_pcap(filepath: Path, session_count: int = 250):
    """Generate baseline PCAP with at least 200 clean sessions."""
    pcap = RawPcapWriter(filepath, client_port=40001)

    for i in range(session_count):
        sport = 40000 + (i % 20000) + 1
        pcap.start_session(client_port=sport)

        # SMTP STARTTLS flow
        pcap.send_server(b"220 mailserver.lab.local ESMTP Postfix\r\n")
        pcap.send_client(b"EHLO client.lab.local\r\n")
        pcap.send_server(b"250-mailserver.lab.local\r\n250-STARTTLS\r\n250 ENHANCEDSTATUSCODES\r\n")
        pcap.send_client(b"STARTTLS\r\n")
        pcap.send_server(b"220 2.0.0 Ready to start TLS\r\n")

        # Select client profile
        prof = CLIENT_PROFILES[i % len(CLIENT_PROFILES)]
        ch_rec, sh_certs_rec = build_custom_tls_handshake_bytes(
            version=prof["version"],
            cipher=prof["ciphers"][0],
            client_ciphers=prof["ciphers"],
            cert_name="valid-2048-sha256.crt",
        )
        pcap.send_client(ch_rec)
        pcap.send_server(sh_certs_rec)

    pcap.close()
    print(f"[+] Successfully generated baseline PCAP with {session_count} clean sessions at {filepath}")


def train_baseline_model():
    """Build baseline capture and train advisory Isolation Forest model."""
    baseline_pcap = CAPTURES_DIR / "baseline.pcap"
    build_baseline_pcap(baseline_pcap, session_count=250)

    # Reassemble and track sessions
    streams, _ = reassemble_pcap(baseline_pcap)
    sessions = []
    for stream in streams:
        sess = track_session(stream)
        if sess.transportMode == "starttls":
            hs = parse_tls_handshake(stream, sess.clientTlsStartOffset, sess.serverTlsStartOffset)
            if hs:
                sess.tls = negotiate_tls(hs)
                if hs.certificates:
                    sess.certificates = analyze_certificate_chain(
                        hs.certificates,
                        capture_ts_sec=sess.firstPacketTs,
                        sni=hs.sni,
                        trust_store_path=TRUST_STORE_PATH if TRUST_STORE_PATH.exists() else None,
                    )
        sessions.append(sess)

    print(f"[+] Reassembled and tracked {len(sessions)} sessions from baseline PCAP")

    # Train Isolation Forest model
    detector = AnomalyDetector()
    summary = detector.train(sessions, random_state=42, contamination=0.05)

    model_path = ADVISORY_DIR / "model.joblib"
    summary_path = ADVISORY_DIR / "baseline_summary.json"
    detector.save(model_path, summary_path)

    print(f"[+] Trained Isolation Forest model (scikit-learn {summary['sklearn_version']})")
    print(f"[+] Saved model to {model_path} and baseline summary to {summary_path}")
    print(f"[+] Calibrated anomaly threshold: {summary['threshold']:.4f}")


if __name__ == "__main__":
    train_baseline_model()
