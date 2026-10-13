// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./Roles.sol";
import "./CaseRegistry.sol";

/**
 * @title ValidationQuorum
 * @notice Coordinates independent validators verifying analyst forensic claims
 * via commit-reveal quorum consensus.
 */
contract ValidationQuorum is Roles {
    enum ResolutionAction {
        AttestMajority,
        NewRound,
        Reject
    }

    struct RoundData {
        address[] validatorSnapshot;
        mapping(address => bool) isSnapshotValidator;
        uint32 validatorCount;
        uint32 quorum;
        uint64 commitDeadline;
        uint64 revealDeadline;
        mapping(address => bytes32) commitments;
        mapping(address => bool) hasCommitted;
        mapping(address => bool) hasRevealed;
        mapping(address => bytes32) validatorRoots;
        mapping(bytes32 => uint32) revealCounts;
        uint32 totalReveals;
    }

    // --- State Variables ---

    CaseRegistry public immutable caseRegistry;
    uint64 public commitWindow;
    uint64 public revealWindow;

    // caseId => round => RoundData
    mapping(bytes32 => mapping(uint32 => RoundData)) private _rounds;

    // --- Events ---

    event ClaimSubmitted(
        bytes32 indexed caseId,
        address indexed analyst,
        bytes32 claimedRoot,
        bytes32 engineHash,
        bytes32 rulesetHash
    );

    event CommitSubmitted(
        bytes32 indexed caseId,
        address indexed validator,
        bytes32 commitment,
        uint32 round
    );

    event RevealSubmitted(
        bytes32 indexed caseId,
        address indexed validator,
        bytes32 resultRoot,
        uint32 round
    );

    event CaseFinalized(bytes32 indexed caseId, bytes32 finalRoot, bool contradicted);
    event CaseDisputed(bytes32 indexed caseId, uint32 round);
    event CaseExpired(bytes32 indexed caseId, uint32 round);

    event CaseResolved(
        bytes32 indexed caseId,
        ResolutionAction action,
        bytes32 root
    );

    event WindowsUpdated(uint64 commitWindow, uint64 revealWindow);

    // --- Custom Errors ---

    error ZeroAddress();
    error InvalidWindow();
    error NotCaseAnalyst(bytes32 caseId, address caller);
    error InvalidCaseState(bytes32 caseId, CaseRegistry.State currentState);
    error InsufficientValidators(uint256 currentCount);
    error EngineMismatch();
    error RulesetMismatch();
    error EngineNotConfigured();
    error InvalidResultRoot();
    error InvalidCommitment();
    error NotSnapshotValidator(bytes32 caseId, uint32 round, address caller);
    error CommitDeadlinePassed(uint64 commitDeadline, uint256 currentTimestamp);
    error CommitWindowActive(uint64 commitDeadline, uint256 currentTimestamp);
    error AlreadyCommitted(bytes32 caseId, uint32 round, address caller);
    error RevealDeadlinePassed(uint64 revealDeadline, uint256 currentTimestamp);
    error NoPriorCommitment(bytes32 caseId, uint32 round, address caller);
    error AlreadyRevealed(bytes32 caseId, uint32 round, address caller);
    error CommitmentMismatch();
    error OutcomeNotReady(uint64 revealDeadline, uint256 currentTimestamp);
    error QuorumNotReached(uint32 requiredQuorum, uint32 actualReveals);
    error AttestMajorityNotAllowedForExpired();

    // --- Modifiers ---

    modifier onlyAdmin() {
        if (!hasRole(ADMIN_ROLE, msg.sender) && !caseRegistry.hasRole(ADMIN_ROLE, msg.sender)) {
            revert AccessControlUnauthorizedAccount(msg.sender, ADMIN_ROLE);
        }
        _;
    }

    constructor(
        address caseRegistryAddress,
        uint64 _commitWindow,
        uint64 _revealWindow
    ) Roles() {
        if (caseRegistryAddress == address(0)) revert ZeroAddress();
        if (_commitWindow == 0 || _revealWindow == 0) revert InvalidWindow();

        caseRegistry = CaseRegistry(caseRegistryAddress);
        commitWindow = _commitWindow;
        revealWindow = _revealWindow;
    }

    // --- Admin Configuration ---

    function setWindows(uint64 newCommitWindow, uint64 newRevealWindow) external onlyAdmin {
        if (newCommitWindow == 0 || newRevealWindow == 0) revert InvalidWindow();
        commitWindow = newCommitWindow;
        revealWindow = newRevealWindow;
        emit WindowsUpdated(newCommitWindow, newRevealWindow);
    }

    // --- Core Quorum Workflow ---

    /**
     * @notice Submits the analyst's claimed forensic result root and snapshots registered validators.
     * @param caseId Identifier of the case in CaseRegistry.
     * @param resultRoot Pinned forensic consensus result root.
     * @param engineHash Hash of the analysis engine container image.
     * @param rulesetHash Hash of the ruleset file.
     */
    function submitClaim(
        bytes32 caseId,
        bytes32 resultRoot,
        bytes32 engineHash,
        bytes32 rulesetHash
    ) external {
        if (resultRoot == bytes32(0)) revert InvalidResultRoot();

        CaseRegistry.State state = caseRegistry.caseState(caseId);
        if (state != CaseRegistry.State.Opened) revert InvalidCaseState(caseId, state);

        if (!caseRegistry.hasRole(ANALYST_ROLE, msg.sender)) {
            revert AccessControlUnauthorizedAccount(msg.sender, ANALYST_ROLE);
        }

        address caseAnalyst = caseRegistry.analyst(caseId);
        if (msg.sender != caseAnalyst) revert NotCaseAnalyst(caseId, msg.sender);

        uint256 n = caseRegistry.validatorCount();
        if (n < 3) revert InsufficientValidators(n);

        (bytes32 activeEngine, bytes32 activeRuleset) = caseRegistry.activeEngine();
        if (activeEngine == bytes32(0) || activeRuleset == bytes32(0)) revert EngineNotConfigured();
        if (engineHash != activeEngine) revert EngineMismatch();
        if (rulesetHash != activeRuleset) revert RulesetMismatch();

        // setClaim transitions state in CaseRegistry to Committing
        caseRegistry.setClaim(caseId, resultRoot, engineHash, rulesetHash);

        uint32 round = caseRegistry.caseRound(caseId);
        _initRound(caseId, round, n);

        emit ClaimSubmitted(caseId, msg.sender, resultRoot, engineHash, rulesetHash);
    }

    /**
     * @notice Submits a validator's blinded commitment for the active round.
     * @param caseId Identifier of the case.
     * @param commitment Hash of abi.encode(caseId, validator, resultRoot, salt).
     */
    function commit(bytes32 caseId, bytes32 commitment) external {
        if (commitment == bytes32(0)) revert InvalidCommitment();

        CaseRegistry.State state = caseRegistry.caseState(caseId);
        if (state != CaseRegistry.State.Committing) revert InvalidCaseState(caseId, state);

        uint32 round = caseRegistry.caseRound(caseId);
        RoundData storage r = _rounds[caseId][round];

        if (!r.isSnapshotValidator[msg.sender]) {
            revert NotSnapshotValidator(caseId, round, msg.sender);
        }
        if (block.timestamp >= r.commitDeadline) {
            revert CommitDeadlinePassed(r.commitDeadline, block.timestamp);
        }
        if (r.hasCommitted[msg.sender]) {
            revert AlreadyCommitted(caseId, round, msg.sender);
        }

        r.commitments[msg.sender] = commitment;
        r.hasCommitted[msg.sender] = true;

        emit CommitSubmitted(caseId, msg.sender, commitment, round);
    }

    /**
     * @notice Advances case state from Committing to Revealing once commitDeadline has elapsed.
     * @param caseId Identifier of the case.
     */
    function advance(bytes32 caseId) external {
        CaseRegistry.State state = caseRegistry.caseState(caseId);
        if (state != CaseRegistry.State.Committing) revert InvalidCaseState(caseId, state);

        uint32 round = caseRegistry.caseRound(caseId);
        RoundData storage r = _rounds[caseId][round];

        if (block.timestamp < r.commitDeadline) {
            revert CommitWindowActive(r.commitDeadline, block.timestamp);
        }

        caseRegistry.setState(caseId, CaseRegistry.State.Revealing);
    }

    /**
     * @notice Reveals a validator's result root and pre-image salt.
     * @param caseId Identifier of the case.
     * @param resultRoot Result root computed by the validator.
     * @param salt Random salt used during commitment.
     * @param engineHash Pinned engine hash (must match case's pinned hash).
     * @param rulesetHash Pinned ruleset hash (must match case's pinned hash).
     */
    function reveal(
        bytes32 caseId,
        bytes32 resultRoot,
        bytes32 salt,
        bytes32 engineHash,
        bytes32 rulesetHash
    ) external {
        CaseRegistry.State state = caseRegistry.caseState(caseId);
        if (state != CaseRegistry.State.Revealing) revert InvalidCaseState(caseId, state);

        uint32 round = caseRegistry.caseRound(caseId);
        RoundData storage r = _rounds[caseId][round];

        if (!r.isSnapshotValidator[msg.sender]) {
            revert NotSnapshotValidator(caseId, round, msg.sender);
        }
        if (block.timestamp >= r.revealDeadline) {
            revert RevealDeadlinePassed(r.revealDeadline, block.timestamp);
        }
        if (!r.hasCommitted[msg.sender]) {
            revert NoPriorCommitment(caseId, round, msg.sender);
        }
        if (r.hasRevealed[msg.sender]) {
            revert AlreadyRevealed(caseId, round, msg.sender);
        }

        if (engineHash != caseRegistry.engineHash(caseId)) revert EngineMismatch();
        if (rulesetHash != caseRegistry.rulesetHash(caseId)) revert RulesetMismatch();

        bytes32 computedCommitment = keccak256(abi.encode(caseId, msg.sender, resultRoot, salt));
        if (computedCommitment != r.commitments[msg.sender]) {
            revert CommitmentMismatch();
        }

        r.hasRevealed[msg.sender] = true;
        r.validatorRoots[msg.sender] = resultRoot;
        r.revealCounts[resultRoot] += 1;
        r.totalReveals += 1;

        emit RevealSubmitted(caseId, msg.sender, resultRoot, round);
    }

    /**
     * @notice Evaluates quorum reveals and finalizes, expires, or disputes the case.
     * @param caseId Identifier of the case.
     */
    function finalize(bytes32 caseId) external {
        CaseRegistry.State state = caseRegistry.caseState(caseId);
        if (state != CaseRegistry.State.Revealing) revert InvalidCaseState(caseId, state);

        uint32 round = caseRegistry.caseRound(caseId);
        RoundData storage r = _rounds[caseId][round];
        bytes32 cRoot = caseRegistry.claimedRoot(caseId);

        // Condition A: Claim Agreement (qualifying majority on claimedRoot)
        if (r.revealCounts[cRoot] >= r.quorum) {
            caseRegistry.finalizeCase(caseId, cRoot, false);
            emit CaseFinalized(caseId, cRoot, false);
            return;
        }

        // Condition B: Reveal window must have elapsed if agreement not met
        if (block.timestamp <= r.revealDeadline) {
            revert OutcomeNotReady(r.revealDeadline, block.timestamp);
        }

        // Condition C: Evaluate participation (Expired strictly takes precedence over Disputed)
        if (r.totalReveals < r.quorum) {
            caseRegistry.setState(caseId, CaseRegistry.State.Expired);
            emit CaseExpired(caseId, round);
        } else {
            caseRegistry.setState(caseId, CaseRegistry.State.Disputed);
            emit CaseDisputed(caseId, round);
        }
    }

    /**
     * @notice Resolves a Disputed or Expired case by administrator action.
     * @param caseId Identifier of the case.
     * @param action Resolution action (AttestMajority, NewRound, or Reject).
     * @param root Result root to attest (only used for AttestMajority).
     */
    function resolve(
        bytes32 caseId,
        ResolutionAction action,
        bytes32 root
    ) external onlyAdmin {
        CaseRegistry.State state = caseRegistry.caseState(caseId);
        if (state != CaseRegistry.State.Disputed && state != CaseRegistry.State.Expired) {
            revert InvalidCaseState(caseId, state);
        }

        uint32 currentRound = caseRegistry.caseRound(caseId);

        if (action == ResolutionAction.AttestMajority) {
            if (state == CaseRegistry.State.Expired) {
                revert AttestMajorityNotAllowedForExpired();
            }

            RoundData storage r = _rounds[caseId][currentRound];
            if (r.revealCounts[root] < r.quorum) {
                revert QuorumNotReached(r.quorum, r.revealCounts[root]);
            }

            bytes32 cRoot = caseRegistry.claimedRoot(caseId);
            bool contradicted = (root != cRoot);

            caseRegistry.finalizeCase(caseId, root, contradicted);
            emit CaseFinalized(caseId, root, contradicted);
            emit CaseResolved(caseId, action, root);
        } else if (action == ResolutionAction.NewRound) {
            uint256 n = caseRegistry.validatorCount();
            if (n < 3) revert InsufficientValidators(n);

            caseRegistry.incrementRound(caseId);
            uint32 newRound = caseRegistry.caseRound(caseId);

            _initRound(caseId, newRound, n);

            emit CaseResolved(caseId, action, bytes32(0));
        } else if (action == ResolutionAction.Reject) {
            caseRegistry.setState(caseId, CaseRegistry.State.Rejected);
            emit CaseResolved(caseId, action, bytes32(0));
        }
    }

    // --- Internal Helpers ---

    function _initRound(bytes32 caseId, uint32 round, uint256 n) internal {
        address[] memory vals = caseRegistry.validators();
        RoundData storage r = _rounds[caseId][round];

        r.validatorSnapshot = vals;
        r.validatorCount = uint32(n);
        r.quorum = uint32(n / 2 + 1);

        for (uint256 i = 0; i < n; i++) {
            r.isSnapshotValidator[vals[i]] = true;
        }

        uint64 cDeadline = uint64(block.timestamp + commitWindow);
        uint64 rDeadline = uint64(cDeadline + revealWindow);
        r.commitDeadline = cDeadline;
        r.revealDeadline = rDeadline;
    }

    // --- Public Getters ---

    function getValidatorSnapshot(bytes32 caseId, uint32 round) external view returns (address[] memory) {
        return _rounds[caseId][round].validatorSnapshot;
    }

    function isSnapshotValidator(bytes32 caseId, uint32 round, address validator) external view returns (bool) {
        return _rounds[caseId][round].isSnapshotValidator[validator];
    }

    function getRoundParams(bytes32 caseId, uint32 round) external view returns (
        uint32 n,
        uint32 k,
        uint64 commitDeadline,
        uint64 revealDeadline,
        uint32 totalReveals
    ) {
        RoundData storage r = _rounds[caseId][round];
        return (r.validatorCount, r.quorum, r.commitDeadline, r.revealDeadline, r.totalReveals);
    }

    function getCommitment(bytes32 caseId, uint32 round, address validator) external view returns (bytes32) {
        return _rounds[caseId][round].commitments[validator];
    }

    function hasCommitted(bytes32 caseId, uint32 round, address validator) external view returns (bool) {
        return _rounds[caseId][round].hasCommitted[validator];
    }

    function hasRevealed(bytes32 caseId, uint32 round, address validator) external view returns (bool) {
        return _rounds[caseId][round].hasRevealed[validator];
    }

    function getRevealCount(bytes32 caseId, uint32 round, bytes32 root) external view returns (uint32) {
        return _rounds[caseId][round].revealCounts[root];
    }

    function getValidatorRoot(bytes32 caseId, uint32 round, address validator) external view returns (bytes32) {
        return _rounds[caseId][round].validatorRoots[validator];
    }
}
