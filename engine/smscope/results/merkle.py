"""Merkle tree implementation for SecureMailScope result roots and posture proofs."""
from typing import Sequence, List, Union

from engine.smscope.results.hashing import node


class MerkleTree:
    """Deterministic Merkle tree adhering to Decision 001.

    Rules:
    - Leaves sorted ascending by raw hash bytes.
    - Duplicate leaves strictly rejected.
    - Empty leaf list strictly rejected.
    - Single-leaf root is that leaf itself.
    - Odd node at any level carried up unchanged.
    - Internal nodes: SHA-256(0x01 + min(a, b) + max(a, b)).
    - Proofs require no directional flags.
    """

    def __init__(self, leaves: Sequence[Union[bytes, str]]) -> None:
        if not leaves:
            raise ValueError("Empty leaf list is rejected")

        raw_leaves: List[bytes] = []
        for leaf in leaves:
            if isinstance(leaf, str):
                b = bytes.fromhex(leaf)
            elif isinstance(leaf, (bytes, bytearray)):
                b = bytes(leaf)
            else:
                raise TypeError(f"Leaf must be hex str or bytes, got {type(leaf)}")
            if len(b) != 32:
                raise ValueError(f"Leaf must be 32 bytes, got {len(b)}")
            raw_leaves.append(b)

        # Check for duplicates before sorting
        if len(set(raw_leaves)) != len(raw_leaves):
            raise ValueError("Duplicate leaves are strictly rejected")

        # Sort leaves ascending by raw bytes
        self.leaves: List[bytes] = sorted(raw_leaves)
        self.layers: List[List[bytes]] = [self.leaves]

        # Build layers upwards
        current_layer = self.leaves
        while len(current_layer) > 1:
            next_layer: List[bytes] = []
            i = 0
            n = len(current_layer)
            while i < n:
                if i + 1 < n:
                    next_layer.append(node(current_layer[i], current_layer[i + 1]))
                    i += 2
                else:
                    # Odd node carried up unchanged
                    next_layer.append(current_layer[i])
                    i += 1
            self.layers.append(next_layer)
            current_layer = next_layer

    @property
    def root(self) -> bytes:
        """Return the 32-byte root hash."""
        return self.layers[-1][0]

    @property
    def root_hex(self) -> str:
        """Return the root hash as a lowercase hex string."""
        return self.root.hex()

    def proof(self, leaf: Union[bytes, str]) -> List[bytes]:
        """Generate inclusion proof for the given leaf.

        Returns a list of 32-byte sibling hashes from bottom to top.
        """
        if isinstance(leaf, str):
            target = bytes.fromhex(leaf)
        else:
            target = bytes(leaf)

        try:
            idx = self.leaves.index(target)
        except ValueError:
            raise ValueError("Leaf not present in Merkle tree")

        proof_hashes: List[bytes] = []
        for layer in self.layers[:-1]:
            layer_len = len(layer)
            if idx % 2 == 0:
                if idx + 1 < layer_len:
                    proof_hashes.append(layer[idx + 1])
                # If idx is even and last element, it was carried up without sibling
            else:
                proof_hashes.append(layer[idx - 1])
            idx = idx // 2

        return proof_hashes

    def proof_hex(self, leaf: Union[bytes, str]) -> List[str]:
        """Generate inclusion proof as a list of hex strings."""
        return [h.hex() for h in self.proof(leaf)]


def build_tree(leaves: Sequence[Union[bytes, str]]) -> MerkleTree:
    """Build a MerkleTree instance from a collection of leaves."""
    return MerkleTree(leaves)


def verify(
    leaf: Union[bytes, str],
    proof: Sequence[Union[bytes, str]],
    root: Union[bytes, str]
) -> bool:
    """Verify an inclusion proof against a root hash.

    Since node(a, b) sorts inputs, no directional flags are needed.
    """
    if isinstance(leaf, str):
        current = bytes.fromhex(leaf)
    else:
        current = bytes(leaf)

    if len(current) != 32:
        return False

    if isinstance(root, str):
        expected_root = bytes.fromhex(root)
    else:
        expected_root = bytes(root)

    if len(expected_root) != 32:
        return False

    for sibling in proof:
        if isinstance(sibling, str):
            sib_bytes = bytes.fromhex(sibling)
        else:
            sib_bytes = bytes(sibling)
        if len(sib_bytes) != 32:
            return False
        current = node(current, sib_bytes)

    return current == expected_root
