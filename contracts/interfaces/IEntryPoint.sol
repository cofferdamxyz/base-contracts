// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IEntryPoint
/// @notice Minimal ERC-4337 EntryPoint v0.7 interface — only the functions and
///         structs CofferdamAccount4337 needs. The canonical EntryPoint v0.7 is
///         preinstalled at 0x0000000071727De22E5E9d8BAf0edAc6f37da032 on Base.
///         See: https://eips.ethereum.org/EIPS/eip-4337
interface IEntryPoint {
    /// @notice ERC-4337 v0.7 packed UserOperation. Gas fields are packed into
    ///         uint256 pairs to save calldata cost vs the v0.6 flat struct.
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;  // packed: high 128b = verificationGasLimit, low 128b = callGasLimit
        uint256 preVerificationGas;
        bytes32 gasFees;           // packed: high 128b = maxPriorityFeePerGas, low 128b = maxFeePerGas
        bytes paymasterAndData;    // v0.7 keeps this as bytes for the interface; EntryPoint unpacks internally
        bytes signature;
    }

    /// @notice Validate a user operation. Called by the EntryPoint during the
    ///         simulation/verification phase.
    /// @dev    v0.7: the UserOperation struct is packed, but the IAccount
    ///         interface still includes missingAccountFunds.
    /// @return validationData  An encoded packed value of (sigFailure, validUntil, validAfter).
    ///         0 on success. See ERC-4337 §6.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external payable returns (uint256 validationData);

    /// @notice Deposit ETH for the account's gas balance on the EntryPoint.
    function depositTo(address account) external payable;

    /// @notice Get the account's deposit balance.
    function balanceOf(address account) external view returns (uint256);

    /// @notice Withdraw from the account's deposit.
    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external;

    /// @notice Get the nonce for an account.
    /// @param sender  The account address.
    /// @param key     The nonce key (192-bit).
    /// @return nonce  The current nonce value.
    function getNonce(address sender, uint192 key) external view returns (uint256 nonce);

    /// @notice Compute the keccak256 hash of a packed user operation.
    /// @return userOpHash  The hash used for signature verification.
    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32);

    /// @notice Execute a bundle of user operations. Called by the bundler.
    /// @param ops          Array of packed user operations to execute.
    /// @param beneficiary  Address to receive gas refunds.
    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external;
}
