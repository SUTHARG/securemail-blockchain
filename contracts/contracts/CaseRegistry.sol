// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "./Roles.sol";

/**
 * @title CaseRegistry
 * @notice Central registry for forensic cases, engine releases, validator membership,
 * and report custody hashes.
 */
contract CaseRegistry is Roles {
    enum State {
        None,
        Opened,
        Claimed,
        Committing,
        Revealing,
        Finalized,
        Disputed,
        Expired,
        Rejected
    }

    struct Case {
        address analyst;
        bytes32 pcapHash;
        State state;
        bytes32 claimedRoot;
        bytes32 finalRoot;
        bool contradicted;
        bytes32 engineHash;
        bytes32 rulesetHash;
        bytes32 reportHash;
        uint64 openedAt;
        uint32 round;
    }

    // --- State Variables ---

    uint256 public caseCounter;
    mapping(bytes32 => Case) private _cases;

    bytes32 public activeImageDigest;
    bytes32 public activeRulesetHash;

    address[] private _validators;
    mapping(address => bool) private _isValidator;
    mapping(address => uint256) private _validatorIndex;

    // --- Events ---

    event CaseOpened(
        bytes32 indexed caseId,
        address indexed analyst,
        bytes32 indexed pcapHash,
        uint256 timestamp
    );

    event ReportAnchored(
        bytes32 indexed caseId,
        bytes32 indexed reportHash,
        address indexed analyst,
        uint256 timestamp
    );

    event EngineRegistered(
        bytes32 indexed imageDigest,
        bytes32 indexed rulesetHash,
        uint256 timestamp
    );

    event ValidatorAdded(address indexed validator, uint256 timestamp);
    event ValidatorRemoved(address indexed validator, uint256 timestamp);

    event ClaimRecorded(
        bytes32 indexed caseId,
        bytes32 claimedRoot,
        bytes32 engineHash,
        bytes32 rulesetHash
    );

    event StateChanged(bytes32 indexed caseId, State previousState, State newState);
    event CaseFinalized(bytes32 indexed caseId, bytes32 finalRoot, bool contradicted);
    event CaseRoundIncremented(bytes32 indexed caseId, uint32 newRound);

    // --- Errors ---

    error ZeroAddress();
    error InvalidPcapHash();
    error InvalidReportHash();
    error InvalidEngineHash();
    error CaseNotFound(bytes32 caseId);
    error NotCaseAnalyst(bytes32 caseId, address caller);
    error CaseNotFinalized(bytes32 caseId, State currentState);
    error ReportAlreadyAnchored(bytes32 caseId);
    error ValidatorAlreadyRegistered(address validator);
    error ValidatorNotRegistered(address validator);
    error InvalidCaseState(bytes32 caseId, State currentState);

    constructor() Roles() {}

    // --- Analyst Operations ---

    /**
     * @notice Open a new forensic analysis case for a PCAP file.
     * @dev Restricted to ANALYST_ROLE. Generating the same PCAP twice produces distinct case IDs.
     * @param _pcapHash SHA-256 digest of the PCAP file.
     * @return caseId Unique identifier for the case.
     */
    function openCase(bytes32 _pcapHash) external onlyRole(ANALYST_ROLE) returns (bytes32 caseId) {
        if (_pcapHash == bytes32(0)) revert InvalidPcapHash();

        caseId = keccak256(abi.encode(_pcapHash, msg.sender, caseCounter++));

        Case storage c = _cases[caseId];
        c.analyst = msg.sender;
        c.pcapHash = _pcapHash;
        c.state = State.Opened;
        c.openedAt = uint64(block.timestamp);
        c.round = 1;

        emit CaseOpened(caseId, msg.sender, _pcapHash, block.timestamp);
    }

    /**
     * @notice Anchor the SHA-256 custody digest of the finalized report.
     * @dev Only the case's analyst, only in Finalized state, only once.
     * @param caseId Identifier of the finalized case.
     * @param _reportHash SHA-256 digest of the report document.
     */
    function anchorReport(bytes32 caseId, bytes32 _reportHash) external {
        Case storage c = _cases[caseId];
        if (c.state == State.None) revert CaseNotFound(caseId);
        if (c.analyst != msg.sender) revert NotCaseAnalyst(caseId, msg.sender);
        if (c.state != State.Finalized) revert CaseNotFinalized(caseId, c.state);
        if (c.reportHash != bytes32(0)) revert ReportAlreadyAnchored(caseId);
        if (_reportHash == bytes32(0)) revert InvalidReportHash();

        c.reportHash = _reportHash;
        emit ReportAnchored(caseId, _reportHash, msg.sender, block.timestamp);
    }

    // --- Engine Pinning (Admin Only) ---

    /**
     * @notice Register and pin the active analysis engine release and ruleset hash.
     * @param imageDigest Container image digest of the analysis engine.
     * @param _rulesetHash SHA-256 digest of the active ruleset.
     */
    function registerEngine(bytes32 imageDigest, bytes32 _rulesetHash) external onlyRole(ADMIN_ROLE) {
        if (imageDigest == bytes32(0) || _rulesetHash == bytes32(0)) revert InvalidEngineHash();

        activeImageDigest = imageDigest;
        activeRulesetHash = _rulesetHash;

        emit EngineRegistered(imageDigest, _rulesetHash, block.timestamp);
    }

    /**
     * @notice Return the currently active pinned engine image digest and ruleset hash.
     */
    function activeEngine() external view returns (bytes32 imageDigest, bytes32 _activeRulesetHash) {
        return (activeImageDigest, activeRulesetHash);
    }

    // --- Validator Management (Admin Only) ---

    /**
     * @notice Add a validator address and grant VALIDATOR_ROLE.
     * @param validator Address of the validator.
     */
    function addValidator(address validator) external onlyRole(ADMIN_ROLE) {
        if (validator == address(0)) revert ZeroAddress();
        if (_isValidator[validator]) revert ValidatorAlreadyRegistered(validator);

        _validators.push(validator);
        _isValidator[validator] = true;
        _validatorIndex[validator] = _validators.length - 1;

        grantRole(VALIDATOR_ROLE, validator);

        emit ValidatorAdded(validator, block.timestamp);
    }

    /**
     * @notice Remove a validator address and revoke VALIDATOR_ROLE.
     * @param validator Address of the validator to remove.
     */
    function removeValidator(address validator) external onlyRole(ADMIN_ROLE) {
        if (!_isValidator[validator]) revert ValidatorNotRegistered(validator);

        uint256 idx = _validatorIndex[validator];
        uint256 lastIdx = _validators.length - 1;

        if (idx != lastIdx) {
            address lastVal = _validators[lastIdx];
            _validators[idx] = lastVal;
            _validatorIndex[lastVal] = idx;
        }

        _validators.pop();
        delete _isValidator[validator];
        delete _validatorIndex[validator];

        revokeRole(VALIDATOR_ROLE, validator);

        emit ValidatorRemoved(validator, block.timestamp);
    }

    /**
     * @notice Return the complete list of registered validator addresses.
     */
    function validators() external view returns (address[] memory) {
        return _validators;
    }

    /**
     * @notice Return the count of registered validators.
     */
    function validatorCount() external view returns (uint256) {
        return _validators.length;
    }

    /**
     * @notice Query whether an account is a registered validator.
     */
    function isValidator(address account) external view returns (bool) {
        return _isValidator[account];
    }

    // --- Quorum-Restricted Mutators ---

    /**
     * @notice Store analyst claim details and transition case state.
     * @dev Restricted to QUORUM_ROLE.
     */
    function setClaim(
        bytes32 caseId,
        bytes32 resultRoot,
        bytes32 eHash,
        bytes32 rHash
    ) external onlyRole(QUORUM_ROLE) {
        Case storage c = _cases[caseId];
        if (c.state != State.Opened) revert InvalidCaseState(caseId, c.state);

        c.claimedRoot = resultRoot;
        c.engineHash = eHash;
        c.rulesetHash = rHash;
        c.state = State.Committing;

        emit ClaimRecorded(caseId, resultRoot, eHash, rHash);
        emit StateChanged(caseId, State.Opened, State.Committing);
    }

    /**
     * @notice Transition case state during validation rounds.
     * @dev Restricted to QUORUM_ROLE.
     */
    function setState(bytes32 caseId, State newState) external onlyRole(QUORUM_ROLE) {
        Case storage c = _cases[caseId];
        if (c.state == State.None) revert CaseNotFound(caseId);

        State oldState = c.state;
        c.state = newState;

        emit StateChanged(caseId, oldState, newState);
    }

    /**
     * @notice Finalize a case with its consensus result root.
     * @dev Restricted to QUORUM_ROLE.
     */
    function finalizeCase(
        bytes32 caseId,
        bytes32 fRoot,
        bool wasContradicted
    ) external onlyRole(QUORUM_ROLE) {
        Case storage c = _cases[caseId];
        if (c.state == State.None) revert CaseNotFound(caseId);

        State oldState = c.state;
        c.finalRoot = fRoot;
        c.contradicted = wasContradicted;
        c.state = State.Finalized;

        emit StateChanged(caseId, oldState, State.Finalized);
        emit CaseFinalized(caseId, fRoot, wasContradicted);
    }

    /**
     * @notice Increment the round counter and re-enter Committing state for a new round.
     * @dev Restricted to QUORUM_ROLE.
     */
    function incrementRound(bytes32 caseId) external onlyRole(QUORUM_ROLE) {
        Case storage c = _cases[caseId];
        if (c.state == State.None) revert CaseNotFound(caseId);

        State oldState = c.state;
        c.round += 1;
        c.state = State.Committing;

        emit CaseRoundIncremented(caseId, c.round);
        emit StateChanged(caseId, oldState, State.Committing);
    }

    // --- Public Getters ---

    function getCase(bytes32 caseId) external view returns (Case memory) {
        if (_cases[caseId].state == State.None) revert CaseNotFound(caseId);
        return _cases[caseId];
    }

    function caseExists(bytes32 caseId) external view returns (bool) {
        return _cases[caseId].state != State.None;
    }

    function caseState(bytes32 caseId) external view returns (State) {
        return _cases[caseId].state;
    }

    function claimedRoot(bytes32 caseId) external view returns (bytes32) {
        return _cases[caseId].claimedRoot;
    }

    function finalRoot(bytes32 caseId) external view returns (bytes32) {
        return _cases[caseId].finalRoot;
    }

    function engineHash(bytes32 caseId) external view returns (bytes32) {
        return _cases[caseId].engineHash;
    }

    function rulesetHash(bytes32 caseId) external view returns (bytes32) {
        return _cases[caseId].rulesetHash;
    }

    function reportHash(bytes32 caseId) external view returns (bytes32) {
        return _cases[caseId].reportHash;
    }

    function analyst(bytes32 caseId) external view returns (address) {
        return _cases[caseId].analyst;
    }

    function pcapHash(bytes32 caseId) external view returns (bytes32) {
        return _cases[caseId].pcapHash;
    }

    function caseRound(bytes32 caseId) external view returns (uint32) {
        return _cases[caseId].round;
    }

    function isContradicted(bytes32 caseId) external view returns (bool) {
        return _cases[caseId].contradicted;
    }
}
