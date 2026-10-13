// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAuthorityModule, Tier} from "../interfaces/IAuthorityModule.sol";

/// @title MockTierModule
/// @notice A module of any tier that accepts every signature: the "backdoor"
///         module the module registry exists to keep out, and a stand-in for a
///         retired tier in tests.
contract MockTierModule is IAuthorityModule {
    Tier private immutable _tier;

    constructor(Tier tier_) {
        _tier = tier_;
    }

    function tier() external view returns (Tier) {
        return _tier;
    }

    function kind() external pure returns (bytes32) {
        return keccak256("mock");
    }

    function isValidSignature(address, bytes32, bytes calldata, bytes calldata) external pure returns (bool) {
        return true;
    }
}
