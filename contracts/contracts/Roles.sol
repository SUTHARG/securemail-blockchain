// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title Roles
 * @notice Role definitions and initial access control configuration for SecureMailScope.
 */
contract Roles is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant ANALYST_ROLE = keccak256("ANALYST_ROLE");
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");
    bytes32 public constant QUORUM_ROLE = keccak256("QUORUM_ROLE");

    /**
     * @dev Deployer receives ADMIN_ROLE and DEFAULT_ADMIN_ROLE as a demo simplification.
     * ADMIN_ROLE is configured as the admin role for managing analyst, validator, and quorum roles.
     */
    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);

        _setRoleAdmin(ADMIN_ROLE, ADMIN_ROLE);
        _setRoleAdmin(ANALYST_ROLE, ADMIN_ROLE);
        _setRoleAdmin(VALIDATOR_ROLE, ADMIN_ROLE);
        _setRoleAdmin(QUORUM_ROLE, ADMIN_ROLE);
    }
}
