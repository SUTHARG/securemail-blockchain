"""Unit tests for safety limits and denial-of-service protections."""
import os
import sys
import tempfile
import time
from pathlib import Path
import pytest

from engine.smscope.limits import (
    LimitExceededError,
    check_pcap_size,
    check_stream_count,
    check_stream_buffered_bytes,
    check_tls_record_length,
    check_handshake_message_length,
    check_certificate_length,
    check_runtime,
    start_runtime_timer,
    MAX_PCAP_SIZE_BYTES,
    MAX_STREAMS,
    MAX_BUFFERED_BYTES_PER_STREAM,
    MAX_TLS_RECORD_LENGTH,
    MAX_CERTIFICATE_LENGTH,
    MAX_HANDSHAKE_MESSAGE_LENGTH,
    MAX_RUNTIME_SECONDS,
)
from engine.smscope.cli import main


def test_pcap_size_limit():
    with pytest.raises(LimitExceededError) as exc_info:
        check_pcap_size(MAX_PCAP_SIZE_BYTES + 1)
    assert exc_info.value.limit_name == "pcap_size"


def test_stream_count_limit():
    with pytest.raises(LimitExceededError) as exc_info:
        check_stream_count(MAX_STREAMS + 1)
    assert exc_info.value.limit_name == "stream_count"


def test_stream_buffered_bytes_limit():
    with pytest.raises(LimitExceededError) as exc_info:
        check_stream_buffered_bytes(MAX_BUFFERED_BYTES_PER_STREAM + 1)
    assert exc_info.value.limit_name == "buffered_bytes_per_stream"


def test_tls_record_length_limit():
    with pytest.raises(LimitExceededError) as exc_info:
        check_tls_record_length(MAX_TLS_RECORD_LENGTH + 1)
    assert exc_info.value.limit_name == "tls_record_length"


def test_handshake_message_length_limit():
    with pytest.raises(LimitExceededError) as exc_info:
        check_handshake_message_length(MAX_HANDSHAKE_MESSAGE_LENGTH + 1)
    assert exc_info.value.limit_name == "handshake_message_length"


def test_certificate_length_limit():
    with pytest.raises(LimitExceededError) as exc_info:
        check_certificate_length(MAX_CERTIFICATE_LENGTH + 1)
    assert exc_info.value.limit_name == "certificate_length"


def test_runtime_limit(monkeypatch):
    start_runtime_timer()
    # Simulate past start time
    from engine.smscope import limits
    monkeypatch.setattr(limits, "_start_time", time.time() - (MAX_RUNTIME_SECONDS + 10))
    with pytest.raises(LimitExceededError) as exc_info:
        check_runtime()
    assert exc_info.value.limit_name == "runtime_seconds"


def test_cli_exit_code_3_on_breach(tmp_path, monkeypatch, capsys):
    # Set max pcap size to a small value
    from engine.smscope import limits
    monkeypatch.setattr(limits, "MAX_PCAP_SIZE_BYTES", 10)

    dummy_pcap = tmp_path / "oversized.pcap"
    dummy_pcap.write_bytes(b"0123456789abcdefghij")  # 20 bytes

    out_dir = tmp_path / "out"
    out_dir.mkdir()

    ret = main([
        "analyze",
        str(dummy_pcap),
        "--org-secret-hex", "00" * 32,
        "--out", str(out_dir),
    ])

    assert ret == 3
    captured = capsys.readouterr()
    assert "Limit exceeded: pcap_size" in captured.err
