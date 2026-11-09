// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IZKPassportRootVerifier
/// @notice The part of ZKPassport's `RootVerifier`
///         (`0x1D000001000EFD9a6371f4d90bB8920D5431c0D8` on Base and Ethereum
///         mainnet) that Cofferdam calls. Declared here from the deployed ABI
///         (SDK 0.19.3's `getSolidityVerifierDetails`, checked against Base
///         mainnet on 2026-11-08); no ZKPassport code is vendored.
/// @dev    `verify` is a view whose service configuration comes from the
///         caller, so `ZKPassportEvidenceAdapter` pins it. ZKPassport's admin
///         can swap the sub-verifier and helper of a version without a
///         timelock (decision 0080, Context).
interface IZKPassportRootVerifier {
    struct ProofVerificationData {
        bytes32 vkeyHash;
        bytes proof;
        bytes32[] publicInputs;
    }

    struct ServiceConfig {
        uint256 validityPeriodInSeconds;
        string domain;
        string scope;
        bool devMode;
    }

    struct ProofVerificationParams {
        bytes32 version;
        ProofVerificationData proofVerificationData;
        bytes committedInputs;
        ServiceConfig serviceConfig;
    }

    function verify(ProofVerificationParams calldata params)
        external
        view
        returns (bool valid, bytes32 uniqueIdentifier, address helper);

    function getHelper(bytes32 version) external view returns (address);
}

/// @title IZKPassportHelper
/// @notice The decoding helper `RootVerifier` registers per circuits version
///         (`0xCFC06f8447C4acaB2c855Cf3b73873c5e029921B` for 0.21.1 on Base
///         mainnet, 2026-11-08). Both functions find their section inside the
///         proof's committed inputs; `getBoundData` reverts when the proof has
///         no bind section.
interface IZKPassportHelper {
    struct BoundData {
        address senderAddress;
        uint256 chainId;
        string customData;
    }

    function getBoundData(bytes calldata committedInputs) external view returns (BoundData memory);

    /// @dev True only when the proof's committed lower bound equals `minAge`
    ///      and it has no upper bound (reverts then), as deployed for 0.21.1.
    function isAgeAboveOrEqual(uint8 minAge, bytes calldata committedInputs) external view returns (bool);

    /// @dev True only when the proof's committed lower bound on the expiry
    ///      date equals `date` (seconds) and it has no upper bound.
    function isExpiryDateAfterOrEqual(uint256 date, bytes calldata committedInputs) external view returns (bool);
}
