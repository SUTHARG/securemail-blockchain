"""Tests for canonical JSON serialization."""
import pytest
from engine.smscope.results.canonical import canonical_json


def test_canonical_json_sorting_and_compactness():
    obj = {"z": 1, "a": 2, "m": {"b": 3, "a": 4}}
    output = canonical_json(obj)
    # Expected: {"a":2,"m":{"a":4,"b":3},"z":1}
    assert output == b'{"a":2,"m":{"a":4,"b":3},"z":1}'


def test_canonical_json_integer_values():
    obj = {"score": 100, "count": 0, "neg": -5, "flag": True, "none_val": None}
    output = canonical_json(obj)
    assert output == b'{"count":0,"flag":true,"neg":-5,"none_val":null,"score":100}'


def test_canonical_json_rejects_floats():
    with pytest.raises(TypeError, match="Floating-point"):
        canonical_json({"score": 95.5})

    with pytest.raises(TypeError, match="Floating-point"):
        canonical_json({"nested": [1, 2, 3.14]})


def test_canonical_json_rejects_nan():
    with pytest.raises(TypeError, match="Floating-point"):
        canonical_json({"val": float("nan")})


def test_canonical_json_rejects_non_ascii_keys():
    with pytest.raises(ValueError, match="Non-ASCII"):
        canonical_json({"café": 1})

    with pytest.raises(ValueError, match="Non-ASCII"):
        canonical_json({"ключ": 1})


def test_canonical_json_allows_utf8_string_values():
    obj = {"name": "München"}
    output = canonical_json(obj)
    assert output == '{"name":"München"}'.encode("utf-8")
