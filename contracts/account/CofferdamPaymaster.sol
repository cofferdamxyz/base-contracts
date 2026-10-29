// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IEntryPoint} from "../interfaces/IEntryPoint.sol";

/// @title CofferdamPaymaster
/// @notice The testnet paymaster for Base Sepolia. Mainnet gas goes through
///         the CDP Paymaster (ERC-7677, decision 0017); the deploy scripts
///         refuse to deploy this contract on mainnet.
///
/// @dev    It sponsors a userOp only when both hold:
///           1. `tx.origin` is `relayer`, the plane's relayer EOA that submits
///              `handleOps` for `POST /v1/aa/user-operation` (decision 0012).
///              The relay's policy (factory, paymaster, gas, fee and prefund
///              caps, rate limits) then decides every sponsored op. Without
///              this check anyone could call `EntryPoint.handleOps` directly
///              with an inflated priority fee and themselves as beneficiary,
///              and the EntryPoint would pay them out of this deposit.
///           2. `userOp.sender` runs the account code of the factory this
///              paymaster serves. Accounts of one factory differ only in two
///              immutables OpenZeppelin's EIP712 writes into the code (the
///              account's own address and its cached domain separator), so the
///              paymaster zeroes those 32-byte words (`MASK_OFFSETS`) in a copy
///              of the sender's code and compares its hash with
///              `ACCOUNT_CODE_HASH`. The EntryPoint deploys a new account from
///              `initCode` before it asks the paymaster, so the first op
///              passes too. `scripts/lib/paymaster.ts` derives the hash, the
///              size and the offsets from the deployed factory.
///         Reading `tx.origin` breaks the ERC-7562 rules public bundlers
///         apply, so public bundlers refuse ops that name this paymaster; on
///         Sepolia only the plane's relayer submits them.
///         Ops that never reach the paymaster are unaffected: `recoverHigh`
///         and `finalizeRecovery` are direct calls the plane pays for.
///         Only the owner (the deployer) may change the relayer or withdraw
///         the EntryPoint deposit (decision 0014).
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

contract CofferdamPaymaster is IPaymaster, Ownable {
    IEntryPoint public immutable ENTRY_POINT;
    /// @notice keccak256 of the factory's account runtime code with the
    ///         per-account words at `MASK_OFFSETS` zeroed.
    bytes32 public immutable ACCOUNT_CODE_HASH;
    /// @notice The account runtime code size in bytes.
    uint256 public immutable ACCOUNT_CODE_SIZE;
    /// @notice Up to 16 byte offsets of the per-account 32-byte words, packed
    ///         as uint16 values from the low bits up; `MASK_COUNT` are used.
    uint256 public immutable MASK_OFFSETS;
    uint256 public immutable MASK_COUNT;
    /// @notice The only `tx.origin` this paymaster sponsors: the plane's relayer.
    address public relayer;

    event RelayerChanged(address indexed previousRelayer, address indexed newRelayer);

    error NotEntryPoint();
    error NotRelayer(address origin);
    error NotCofferdamAccount(address sender);
    error ZeroAddress();
    error InvalidAccountCode();

    /// @param entryPoint       The canonical EntryPoint v0.7.
    /// @param relayer_         The plane's relayer EOA.
    /// @param accountCodeHash  The masked account code hash.
    /// @param accountCodeSize  The account runtime code size.
    /// @param maskOffsets      Byte offsets of the per-account 32-byte words.
    constructor(
        IEntryPoint entryPoint,
        address relayer_,
        bytes32 accountCodeHash,
        uint256 accountCodeSize,
        uint16[] memory maskOffsets
    ) Ownable(msg.sender) {
        if (address(entryPoint) == address(0) || relayer_ == address(0)) revert ZeroAddress();
        if (accountCodeHash == bytes32(0) || accountCodeSize < 32 || maskOffsets.length > 16) {
            revert InvalidAccountCode();
        }
        uint256 packed;
        for (uint256 i = 0; i < maskOffsets.length; i++) {
            if (uint256(maskOffsets[i]) + 32 > accountCodeSize) revert InvalidAccountCode();
            packed |= uint256(maskOffsets[i]) << (16 * i);
        }
        ENTRY_POINT = entryPoint;
        ACCOUNT_CODE_HASH = accountCodeHash;
        ACCOUNT_CODE_SIZE = accountCodeSize;
        MASK_OFFSETS = packed;
        MASK_COUNT = maskOffsets.length;
        relayer = relayer_;
        emit RelayerChanged(address(0), relayer_);
    }

    /// @notice Deposit ETH to the EntryPoint for this paymaster's balance.
    receive() external payable {
        ENTRY_POINT.depositTo{value: msg.value}(address(this));
    }

    /// @notice Withdraw the paymaster's EntryPoint balance. Owner only.
    function withdrawTo(address payable withdrawAddress, uint256 amount) external onlyOwner {
        ENTRY_POINT.withdrawTo(withdrawAddress, amount);
    }

    /// @notice Point the paymaster at a new relayer EOA (a rotated
    ///         `RELAYER_PRIVATE_KEY`) without moving the deposit. Owner only.
    function setRelayer(address newRelayer) external onlyOwner {
        if (newRelayer == address(0)) revert ZeroAddress();
        emit RelayerChanged(relayer, newRelayer);
        relayer = newRelayer;
    }

    /// @notice Sponsor a userOp the plane's relayer submits for a Cofferdam
    ///         account; revert for anything else.
    function validatePaymasterUserOp(
        IEntryPoint.PackedUserOperation calldata userOp,
        bytes32,
        uint256
    ) external view returns (bytes memory context, uint256 validationData) {
        if (msg.sender != address(ENTRY_POINT)) revert NotEntryPoint();
        // solhint-disable-next-line avoid-tx-origin
        if (tx.origin != relayer) revert NotRelayer(tx.origin);
        if (!isCofferdamAccount(userOp.sender)) revert NotCofferdamAccount(userOp.sender);
        return (abi.encode(userOp.sender), 0);
    }

    /// @notice Whether `account` runs this paymaster's factory account code.
    function isCofferdamAccount(address account) public view returns (bool) {
        if (account.code.length != ACCOUNT_CODE_SIZE) return false;
        bytes memory code = account.code;
        uint256 packed = MASK_OFFSETS;
        for (uint256 i = 0; i < MASK_COUNT; i++) {
            uint256 offset = (packed >> (16 * i)) & 0xffff;
            assembly {
                mstore(add(add(code, 0x20), offset), 0)
            }
        }
        return keccak256(code) == ACCOUNT_CODE_HASH;
    }

    function postOp(uint8, bytes calldata, uint256, uint256) external view {
        if (msg.sender != address(ENTRY_POINT)) revert NotEntryPoint();
        // No-op: nothing to reconcile after the op.
    }
}
