"""Tests for Merkle tree construction and proofs."""
import json
from pathlib import Path
import pytest
from hypothesis import given, strategies as st, seed

from engine.smscope.results.merkle import build_tree, verify, MerkleTree

MERKLE_VECTORS_PATH = Path(__file__).resolve().parents[2] / "spec" / "test-vectors" / "merkle_trees.json"


@pytest.fixture(scope="module")
def merkle_vectors():
    with open(MERKLE_VECTORS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_merkle_tree_vectors(merkle_vectors):
    for entry in merkle_vectors:
        count = entry["leafCount"]
        leaf_hexes = [item["leaf"] for item in entry["leaves"]]
        tree = build_tree(leaf_hexes)

        # Assert root matches vector
        assert tree.root_hex == entry["rootHex"], f"Root mismatch for leafCount {count}"

        # Assert all proofs match and verify
        for l_hex, expected_proof in entry["proofs"].items():
            proof = tree.proof_hex(l_hex)
            assert proof == expected_proof, f"Proof mismatch for leaf {l_hex}"
            assert verify(l_hex, proof, tree.root_hex) is True


def test_merkle_rejects_empty():
    with pytest.raises(ValueError, match="Empty"):
        build_tree([])


def test_merkle_rejects_duplicates():
    dup = "aa" * 32
    with pytest.raises(ValueError, match="Duplicate"):
        build_tree([dup, dup])


def test_single_leaf_root_is_leaf():
    leaf = "11" * 32
    tree = build_tree([leaf])
    assert tree.root_hex == leaf
    assert tree.proof_hex(leaf) == []
    assert verify(leaf, [], tree.root_hex) is True


@seed(42)
@given(
    st.lists(
        st.binary(min_size=32, max_size=32),
        min_size=1,
        max_size=20,
        unique=True,
    )
)
def test_merkle_property_all_leaves_verify_and_tampering_fails(leaves):
    tree = build_tree(leaves)
    root = tree.root

    for leaf in leaves:
        proof = tree.proof(leaf)
        # Leaf verifies cleanly
        assert verify(leaf, proof, root) is True

        # Mutated leaf fails verification
        tampered_byte = bytes([(leaf[0] ^ 0xFF)]) + leaf[1:]
        assert verify(tampered_byte, proof, root) is False

        # Mutated proof sibling fails verification if proof is non-empty
        if proof:
            tampered_proof = list(proof)
            tampered_sibling = bytes([(proof[0][0] ^ 0xFF)]) + proof[0][1:]
            tampered_proof[0] = tampered_sibling
            assert verify(leaf, tampered_proof, root) is False
