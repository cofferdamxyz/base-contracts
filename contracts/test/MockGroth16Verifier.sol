// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISelfGroth16Verifier} from "../self/ISelfGroth16Verifier.sol";

/// @title MockGroth16Verifier
/// @notice Always-returns-true verifier for local testing and development.
///         DO NOT use on mainnet.
contract MockGroth16Verifier is ISelfGroth16Verifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[21] calldata
    ) external pure override returns (bool) {
        return true;
    }
}

/// @title RejectingGroth16Verifier
/// @notice Always-returns-false verifier, so tests can exercise the
///         `NullifierRegistry.InvalidProof` branch without constructing a
///         genuinely invalid Groth16 proof.
contract RejectingGroth16Verifier is ISelfGroth16Verifier {
    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[21] calldata
    ) external pure override returns (bool) {
        return false;
    }
}
