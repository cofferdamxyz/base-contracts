// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title ZKPassport's contracts as `CofferdamZKPassportPepperAdapter` reads them
/// @notice Declared here from the deployed ABIs (read on Base mainnet,
///         2026-11-19, against zkpassport-packages 97576ab); no ZKPassport
///         code. The adapter calls the outer-proof verifier itself instead of
///         going through `RootVerifier.verify`, whose sub-verifier accepts
///         only ZKPassport's global OPRF key (decision 0080, the pepper).

/// @notice The state of `RootVerifier` the adapter follows: its pause, the
///         root registry it hands its sub-verifiers, and the sub-verifier and
///         helper registered per circuits version.
interface IZKPassportRootVerifierState {
    function paused() external view returns (bool);
    function rootRegistry() external view returns (address);
    function getSubVerifier(bytes32 version) external view returns (address);
    function getHelper(bytes32 version) external view returns (address);
}

/// @notice A version's `SubVerifier`: its pause, the outer-proof verifier per
///         verification-key hash, and ZKPassport's global OPRF key hash.
interface IZKPassportSubVerifier {
    function paused() external view returns (bool);
    function rootVerifier() external view returns (address);
    function proofVerifiers(bytes32 vkeyHash) external view returns (address);
    function globalOPRFPubKeyHash() external view returns (bytes32);
}

/// @notice `RootRegistry`: whether a root of a registry (1 certificates,
///         2 circuits) was valid at a time. False when paused or unknown.
interface IZKPassportRootRegistry {
    function isRootValid(bytes32 registryId, bytes32 root, uint256 timestamp) external view returns (bool);
}

/// @notice An outer circuit's UltraHonk verifier (`IProofVerifier`).
interface IZKPassportProofVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}
