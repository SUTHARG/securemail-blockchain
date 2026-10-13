"""Regression tests for edge cases discovered during fuzzing (Prompt T2.6)."""
import pytest
from engine.smscope.tls.records import parse_tls_records
from engine.smscope.certs.analyze import analyze_certificate_chain


def test_regression_parse_tls_records_none_offset():
    """Fuzz crash #7: None or negative start_offset must return empty records, never crash."""
    records, errors, alerts, count = parse_tls_records(b"\x16\x03\x01\x00\x05hello", None, lambda off: 1)
    assert records == []
    assert errors == []
    assert alerts == []
    assert count == 0


def test_regression_analyze_certificate_chain_invalid_asn1():
    """Fuzz crash #13: ASN.1 parse errors on malformed DER certificates must be caught gracefully."""
    # Build invalid DER data that fails inside cryptography ASN.1 parser
    corrupted_der = b"\x30\x82\x01\x00" + b"\xff" * 200
    res = analyze_certificate_chain([corrupted_der], 1700000000)
    assert res == []
