"""Tests for cryptographic hashing functions using spec test vectors."""
import json
from pathlib import Path
import pytest

from engine.smscope.results.hashing import (
    finding_id,
    findings_digest,
    host_id,
    finding_leaf,
    host_score_leaf,
    node,
)

VECTORS_PATH = Path(__file__).resolve().parents[2] / "spec" / "test-vectors" / "hashes.json"


@pytest.fixture(scope="module")
def hash_vectors():
    with open(VECTORS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_finding_id_vectors(hash_vectors):
    for item in hash_vectors["finding_id"]:
        actual = finding_id(item["ruleId"], item["serverEndpoint"])
        assert actual == item["expectedHex"], f"Failed for rule {item['ruleId']}"


def test_findings_digest_vectors(hash_vectors):
    for item in hash_vectors["findings_digest"]:
        actual = findings_digest(item["inputFindingIds"])
        assert actual == item["expectedDigestHex"]


def test_host_id_vectors(hash_vectors):
    for item in hash_vectors["host_id"]:
        org_secret = bytes.fromhex(item["orgSecretHex"])
        actual = host_id(org_secret, item["serverEndpoint"]).hex()
        assert actual == item["expectedHostIdHex"]


def test_finding_leaf_vectors(hash_vectors):
    for item in hash_vectors["finding_leaf"]:
        canonical_bytes = item["canonicalUtf8"].encode("utf-8")
        actual = finding_leaf(canonical_bytes).hex()
        assert actual == item["expectedLeafHex"]


def test_host_score_leaf_vectors(hash_vectors):
    for item in hash_vectors["host_score_leaf"]:
        actual = host_score_leaf(
            item["hostIdHex"],
            item["findingsDigestHex"],
            item["score"],
        ).hex()
        assert actual == item["expectedLeafHex"]


def test_node_vectors(hash_vectors):
    for item in hash_vectors["node"]:
        a = bytes.fromhex(item["aHex"])
        b = bytes.fromhex(item["bHex"])
        actual_ab = node(a, b).hex()
        actual_ba = node(b, a).hex()
        assert actual_ab == item["expectedNodeHex"]
        assert actual_ba == item["expectedNodeHex"]
