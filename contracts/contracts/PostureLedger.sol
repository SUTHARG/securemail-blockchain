// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./Roles.sol";
import "./CaseRegistry.sol";
import "./MerkleVerifier.sol";

/**
 * @title PostureLedger
 * @notice Immutable, hash-linked per-host posture ledger verifying on-chain inclusion proofs
 * against finalized case result roots.
 */
contract PostureLedger is Roles {
    struct Record {
        bytes32 hostId;
        bytes32 caseId;
        uint16 score;
        bytes32 resultRoot;
        bytes32 prevHash;
        uint256 timestamp;
        bytes32 recordHash;
    }

    CaseRegistry public immutable caseRegistry;

    // hostId => array of posture records
    mapping(bytes32 => Record[]) private _records;

    // caseId => hostId => whether already recorded
    mapping(bytes32 => mapping(bytes32 => bool)) private _recorded;

    // --- Events ---

    event PostureRecorded(
        bytes32 indexed hostId,
        bytes32 indexed caseId,
        bytes32 indexed recordHash,
        uint16 score,
        bytes32 prevHash,
        uint256 timestamp
    );

    // --- Custom Errors ---

    error ZeroAddress();
    error InvalidHostId();
    error NotCaseAnalyst(bytes32 caseId, address caller);
    error CaseNotFinalized(bytes32 caseId, CaseRegistry.State currentState);
    error InvalidScore(uint16 score);
    error InvalidInclusionProof();
    error PostureAlreadyRecorded(bytes32 caseId, bytes32 hostId);
    error NoRecordsForHost(bytes32 hostId);
    error IndexOutOfBounds(bytes32 hostId, uint256 index);

    constructor(address caseRegistryAddress) Roles() {
        if (caseRegistryAddress == address(0)) revert ZeroAddress();
        caseRegistry = CaseRegistry(caseRegistryAddress);
    }

    /**
     * @notice Records an audited host posture assessment backed by a verified Merkle proof.
     * @param caseId Identifier of the finalized case.
     * @param hostId HMAC-SHA-256 host identifier.
     * @param findingsDigest SHA-256 digest of findings for this host.
     * @param score Integer risk score (0 - 100).
     * @param proof Merkle inclusion proof siblings from bottom to top.
     */
    function recordPosture(
        bytes32 caseId,
        bytes32 hostId,
        bytes32 findingsDigest,
        uint16 score,
        bytes32[] calldata proof
    ) external {
        if (hostId == bytes32(0)) revert InvalidHostId();
        if (score > 100) revert InvalidScore(score);
        if (_recorded[caseId][hostId]) revert PostureAlreadyRecorded(caseId, hostId);

        bytes32 root = _validateCase(caseId);

        if (!MerkleVerifier.verify(proof, root, MerkleVerifier.hostScoreLeaf(hostId, findingsDigest, score))) {
            revert InvalidInclusionProof();
        }

        bytes32 prevHash = bytes32(0);
        uint256 count = _records[hostId].length;
        if (count > 0) {
            prevHash = _records[hostId][count - 1].recordHash;
        }

        bytes32 recordHash = keccak256(
            abi.encode(hostId, caseId, score, root, prevHash, block.timestamp)
        );

        _records[hostId].push(Record({
            hostId: hostId,
            caseId: caseId,
            score: score,
            resultRoot: root,
            prevHash: prevHash,
            timestamp: block.timestamp,
            recordHash: recordHash
        }));
        _recorded[caseId][hostId] = true;

        emit PostureRecorded(hostId, caseId, recordHash, score, prevHash, block.timestamp);
    }

    // --- Internal Helpers ---

    function _validateCase(bytes32 caseId) internal view returns (bytes32) {
        if (!caseRegistry.hasRole(ANALYST_ROLE, msg.sender)) {
            revert AccessControlUnauthorizedAccount(msg.sender, ANALYST_ROLE);
        }

        if (msg.sender != caseRegistry.analyst(caseId)) {
            revert NotCaseAnalyst(caseId, msg.sender);
        }

        CaseRegistry.State state = caseRegistry.caseState(caseId);
        if (state != CaseRegistry.State.Finalized) {
            revert CaseNotFinalized(caseId, state);
        }

        return caseRegistry.finalRoot(caseId);
    }

    // --- Public Getters ---

    function latestRecord(bytes32 hostId) external view returns (Record memory) {
        uint256 count = _records[hostId].length;
        if (count == 0) revert NoRecordsForHost(hostId);
        return _records[hostId][count - 1];
    }

    function recordAt(bytes32 hostId, uint256 index) external view returns (Record memory) {
        if (index >= _records[hostId].length) revert IndexOutOfBounds(hostId, index);
        return _records[hostId][index];
    }

    function recordCount(bytes32 hostId) external view returns (uint256) {
        return _records[hostId].length;
    }

    function hasRecorded(bytes32 caseId, bytes32 hostId) external view returns (bool) {
        return _recorded[caseId][hostId];
    }

    // --- Pure Helpers Exposing Merkle Verification ---

    function hostScoreLeaf(
        bytes32 hostId,
        bytes32 findingsDigest,
        uint16 score
    ) external pure returns (bytes32) {
        return MerkleVerifier.hostScoreLeaf(hostId, findingsDigest, score);
    }

    function node(bytes32 a, bytes32 b) external pure returns (bytes32) {
        return MerkleVerifier.node(a, b);
    }

    function verify(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf
    ) external pure returns (bool) {
        return MerkleVerifier.verify(proof, root, leaf);
    }
}
