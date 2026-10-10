// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IEntryPoint} from "../interfaces/IEntryPoint.sol";

/// @title CofferdamPaymaster
/// @notice A stub verifying paymaster for Base. In production this will be
///         replaced by (or delegate to) the CDP Paymaster for sponsored gas and
///         the ERC-7677 USDC ERC-20 paymaster for gas paid in USDC.
///
/// @dev    This stub implements the ERC-4337 v0.7 IPaymaster interface minimally
///         so the account can be tested end-to-end on a local anvil node. It
///         sponsors all userOps unconditionally (no signature verification) —
///         DO NOT use on mainnet.
///
///         Production paths (see README.md → Base Account Integration):
///
///           1. CDP PAYMASTER (recommended, ERC-7677-compliant):
///              Coinbase-hosted, no onchain contract needed. Configure via the
///              Base Account SDK by passing `paymasterService` capability in
///              `wallet_sendCalls`. CDP offers up to $15k in gas credits via
///              the Base Gasless Campaign. Set a contracts allowlist in the CDP
///              dashboard to sponsor only Cofferdam account calls.
///              See: https://docs.base.org/base-account/improve-ux/sponsor-gas/paymasters
///
///           2. USDC ERC-20 PAYMASTER (ERC-7677):
///              Users pay gas in USDC. The paymaster converts USDC → ETH at
///              oracle rate and deposits to the EntryPoint. This would be a
///              custom contract implementing ERC-7677 with a price feed.
///              Cofferdam's "invisible chain" UX means the enterprise sponsors
///              gas via CDP; workers never see gas costs.
///
///           3. THIS STUB (dev/test only):
///              Unconditional sponsorship for local anvil testing. No access
///              control, no signature verification. Never deploy to mainnet.
interface IPaymaster {
    function validatePaymasterUserOp(
        IEntryPoint.PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external view returns (bytes memory context, uint256 validationData);

    // ERC-4337 v0.7 postOp: the canonical EntryPoint
    // (0x0000000071727De22E5E9d8BAf0edAc6f37da032) calls FOUR args. The v0.6
    // 3-arg shape has a different selector, so the EntryPoint's call would not
    // match it and reverts (PostOpReverted), rolling back the whole userOp.
    function postOp(
        uint8 mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) external;
}

contract CofferdamPaymaster is IPaymaster {
    IEntryPoint public immutable ENTRY_POINT;

    /// @notice Deposit ETH to the EntryPoint for this paymaster's balance.
    receive() external payable {
        ENTRY_POINT.depositTo{value: msg.value}(address(this));
    }

    /// @notice Withdraw the paymaster's EntryPoint balance.
    function withdrawTo(address payable withdrawAddress, uint256 amount) external {
        ENTRY_POINT.withdrawTo(withdrawAddress, amount);
    }

    constructor(IEntryPoint entryPoint) {
        ENTRY_POINT = entryPoint;
    }

    /// @notice Sponsor all userOps unconditionally. STUB — production will
    ///         verify the userOp is from a registered Cofferdam account.
    function validatePaymasterUserOp(
        IEntryPoint.PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external view returns (bytes memory context, uint256 validationData) {
        // Only the EntryPoint may call this.
        require(msg.sender == address(ENTRY_POINT), "CofferdamPaymaster: not from EntryPoint");
        return (abi.encode(userOp.sender), 0);
    }

    function postOp(
        uint8 mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) external view {
        require(msg.sender == address(ENTRY_POINT), "CofferdamPaymaster: not from EntryPoint");
        // No-op: the stub sponsors gas with no post-op reconciliation.
    }
}
