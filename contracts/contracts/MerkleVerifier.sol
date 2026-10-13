// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/**
 * @title MerkleVerifier
 * @notice Cryptographic library for verifying SecureMailScope Merkle inclusion proofs.
 * Adheres to Decision 001 and ARCHITECTURE.md Section 5.3 / 6.5.
 */
library MerkleVerifier {
    /**
     * @notice Computes host-score leaf = sha256(abi.encodePacked(bytes1(0x02), hostId, findingsDigest, score)).
     * @dev uint16 score packs as 2 bytes big-endian.
     * @param hostId HMAC-SHA-256 host identifier (32 bytes).
     * @param findingsDigest SHA-256 digest of concatenated host finding IDs (32 bytes).
     * @param score Host risk posture score (0 - 100).
     * @return 32-byte SHA-256 leaf hash.
     */
    function hostScoreLeaf(
        bytes32 hostId,
        bytes32 findingsDigest,
        uint16 score
    ) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(bytes1(0x02), hostId, findingsDigest, score));
    }

    /**
     * @notice Computes interior node = sha256(abi.encodePacked(bytes1(0x01), min, max)) comparing a and b as uint256.
     * @param a First node hash.
     * @param b Second node hash.
     * @return 32-byte SHA-256 interior node hash.
     */
    function node(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        bytes32 minVal;
        bytes32 maxVal;
        if (uint256(a) <= uint256(b)) {
            minVal = a;
            maxVal = b;
        } else {
            minVal = b;
            maxVal = a;
        }
        return sha256(abi.encodePacked(bytes1(0x01), minVal, maxVal));
    }

    /**
     * @notice Verifies an inclusion proof against a root hash.
     * @dev Since node(a, b) sorts inputs, no left/right positional flags are needed.
     * @param proof Sequence of 32-byte sibling hashes from bottom to top.
     * @param root Expected Merkle root hash.
     * @param leaf Leaf hash to verify.
     * @return True if the proof recomputes to root, false otherwise.
     */
    function verify(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        bytes32 current = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            current = node(current, proof[i]);
        }
        return current == root;
    }
}
