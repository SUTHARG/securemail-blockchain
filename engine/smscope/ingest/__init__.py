"""Ingest stage for SecureMailScope."""
import hashlib
from pathlib import Path
from typing import List, Optional, Tuple

from engine.smscope.ingest.pcap import (
    PcapError,
    PcapFormatError,
    UnsupportedLinkTypeError,
    RawPacket,
    read_pcap_packets,
)
from engine.smscope.ingest.reassembly import (
    Stream,
    format_endpoint,
    reassemble_pcap,
    reassemble_packets,
)


class IngestError(Exception):
    """Raised when ingest fails or capture has no mail sessions."""
    pass


class EmptyCaptureError(IngestError):
    """Raised when capture has no mail sessions."""
    pass


def compute_pcap_sha256(pcap_path: Path) -> str:
    """Compute SHA-256 of the PCAP file."""
    h = hashlib.sha256()
    with open(pcap_path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def ingest(pcap_path: Path) -> Tuple[List[Stream], str]:
    """Real ingest stage: reassembles PCAP packets into TCP streams and computes pcapSha256."""
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    if pcap_path.stat().st_size == 0:
        raise EmptyCaptureError(f"No mail sessions found in capture: {pcap_path}")

    pcap_sha256 = compute_pcap_sha256(pcap_path)

    try:
        streams, _ = reassemble_pcap(pcap_path)
    except (PcapError, PcapFormatError, UnsupportedLinkTypeError) as e:
        raise IngestError(f"Failed to parse PCAP file: {e}") from e

    if not streams:
        raise EmptyCaptureError(f"No mail sessions found in capture: {pcap_path}")

    return streams, pcap_sha256
