"""Canonical JSON serializer adhering to SecureMailScope determinism rules."""
import json
import math
from typing import Any


def _validate_deterministic_types(obj: Any) -> None:
    """Recursively enforce that no floats, NaN, or non-ASCII dictionary keys exist."""
    if isinstance(obj, float) or (isinstance(obj, (int, float)) and not isinstance(obj, bool) and math.isnan(obj)):
        raise TypeError(f"Floating-point numbers and NaN are forbidden in canonical JSON: {obj!r}")
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError(f"Dictionary keys must be strings: {k!r}")
            if not k.isascii():
                raise ValueError(f"Non-ASCII dictionary keys are forbidden: {k!r}")
            _validate_deterministic_types(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _validate_deterministic_types(item)


def canonical_json(obj: Any) -> bytes:
    """Serialize a Python object into canonical JSON bytes.

    Rules:
    - UTF-8 encoding
    - Keys sorted lexicographically
    - Compact separators (',', ':') with zero whitespace
    - Floats, NaN, and infinity strictly forbidden
    - Non-ASCII dictionary keys strictly forbidden
    """
    _validate_deterministic_types(obj)
    # separators=(',', ':') removes whitespace after commas and colons
    text = json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode('utf-8')
