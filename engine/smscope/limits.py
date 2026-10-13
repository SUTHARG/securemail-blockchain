"""Engine resource and input safety limits (Tier 2 / Prompt T2.6).

Guards the engine against Denial of Service, unbounded memory allocation,
infinite loops, and malformed inputs.
Exceeding any limit raises LimitExceededError, which causes the CLI to exit
immediately with exit code 3 and a message naming the breached limit.
"""
import os
import sys
import time
from typing import Optional


class LimitExceededError(Exception):
    """Raised when a hard execution safety limit is exceeded."""

    def __init__(self, limit_name: str, detail: str):
        self.limit_name = limit_name
        self.detail = detail
        super().__init__(f"Limit exceeded: {limit_name} - {detail}")


# Default Hard Limits (configurable via environment variables)
# 1. Maximum PCAP file size (default: 100 MB)
MAX_PCAP_SIZE_BYTES = int(os.environ.get("SMSCOPE_MAX_PCAP_SIZE", 100 * 1024 * 1024))

# 2. Maximum number of TCP streams tracked in one capture (default: 10,000)
MAX_STREAMS = int(os.environ.get("SMSCOPE_MAX_STREAMS", 10000))

# 3. Maximum buffered bytes per stream in each direction (default: 10 MB)
MAX_BUFFERED_BYTES_PER_STREAM = int(os.environ.get("SMSCOPE_MAX_STREAM_BYTES", 10 * 1024 * 1024))

# 4. Maximum TLS record payload length (RFC 8446 allows 2^14 = 16384 + padding/tag; max 18432)
MAX_TLS_RECORD_LENGTH = int(os.environ.get("SMSCOPE_MAX_TLS_RECORD_LENGTH", 18432))

# 5. Maximum X.509 certificate length (default: 65,536 bytes = 64 KB)
MAX_CERTIFICATE_LENGTH = int(os.environ.get("SMSCOPE_MAX_CERT_LENGTH", 65536))

# 6. Maximum TLS handshake message length (default: 131,072 bytes = 128 KB)
MAX_HANDSHAKE_MESSAGE_LENGTH = int(os.environ.get("SMSCOPE_MAX_HANDSHAKE_MSG_LENGTH", 131072))

# 7. Maximum execution runtime in seconds (default: 60 seconds)
MAX_RUNTIME_SECONDS = int(os.environ.get("SMSCOPE_MAX_RUNTIME_SECONDS", 60))

_start_time: Optional[float] = None


def start_runtime_timer():
    """Start or reset execution runtime watchdog timer."""
    global _start_time
    _start_time = time.time()


def check_runtime():
    """Verify runtime has not exceeded MAX_RUNTIME_SECONDS."""
    global _start_time
    if _start_time is not None:
        elapsed = time.time() - _start_time
        if elapsed > MAX_RUNTIME_SECONDS:
            raise LimitExceededError(
                "runtime_seconds",
                f"Execution elapsed {elapsed:.2f}s exceeded maximum runtime {MAX_RUNTIME_SECONDS}s",
            )


def check_pcap_size(size_bytes: int):
    """Verify PCAP file size does not exceed MAX_PCAP_SIZE_BYTES."""
    check_runtime()
    if size_bytes > MAX_PCAP_SIZE_BYTES:
        raise LimitExceededError(
            "pcap_size",
            f"PCAP size {size_bytes} bytes exceeds limit {MAX_PCAP_SIZE_BYTES} bytes",
        )


def check_stream_count(stream_count: int):
    """Verify stream count does not exceed MAX_STREAMS."""
    check_runtime()
    if stream_count > MAX_STREAMS:
        raise LimitExceededError(
            "stream_count",
            f"Stream count {stream_count} exceeds limit {MAX_STREAMS}",
        )


def check_stream_buffered_bytes(stream_bytes_len: int, stream_id: Optional[str] = None):
    """Verify buffered bytes in a stream do not exceed MAX_BUFFERED_BYTES_PER_STREAM."""
    check_runtime()
    if stream_bytes_len > MAX_BUFFERED_BYTES_PER_STREAM:
        s_id_str = f" for stream {stream_id}" if stream_id else ""
        raise LimitExceededError(
            "buffered_bytes_per_stream",
            f"Buffered bytes {stream_bytes_len}{s_id_str} exceeds limit {MAX_BUFFERED_BYTES_PER_STREAM} bytes",
        )


def check_tls_record_length(rec_len: int):
    """Verify TLS record declared length does not exceed MAX_TLS_RECORD_LENGTH."""
    check_runtime()
    if rec_len > MAX_TLS_RECORD_LENGTH:
        raise LimitExceededError(
            "tls_record_length",
            f"TLS record length {rec_len} exceeds limit {MAX_TLS_RECORD_LENGTH} bytes",
        )


def check_handshake_message_length(msg_len: int):
    """Verify TLS handshake message declared length does not exceed MAX_HANDSHAKE_MESSAGE_LENGTH."""
    check_runtime()
    if msg_len > MAX_HANDSHAKE_MESSAGE_LENGTH:
        raise LimitExceededError(
            "handshake_message_length",
            f"TLS handshake message length {msg_len} exceeds limit {MAX_HANDSHAKE_MESSAGE_LENGTH} bytes",
        )


def check_certificate_length(cert_len: int):
    """Verify certificate length does not exceed MAX_CERTIFICATE_LENGTH."""
    check_runtime()
    if cert_len > MAX_CERTIFICATE_LENGTH:
        raise LimitExceededError(
            "certificate_length",
            f"Certificate length {cert_len} exceeds limit {MAX_CERTIFICATE_LENGTH} bytes",
        )
