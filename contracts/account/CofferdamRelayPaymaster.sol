// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IEntryPoint} from "../interfaces/IEntryPoint.sol";
import {IPaymaster} from "./CofferdamPaymaster.sol";

/// @title CofferdamRelayPaymaster
/// @notice The production generation's paymaster (the founder's ruling P9 of
///         2026-11-26, amending decisions 0017 (4) and 0071 (3)): the plane
///         relays every user operation itself on Base mainnet, and this
///         contract, owned by the company Safe from its first block, sponsors
///         only the operations the plane's relayer submits for a Cofferdam
///         account. It carries decision 0071's two checks from the Sepolia
///         `CofferdamPaymaster` and adds what a mainnet deposit needs: the
///         owner as a constructor parameter, two-step ownership, a pause and a
///         per-operation cost cap.
///
/// @dev    `validatePaymasterUserOp` sponsors a userOp only when all hold:
///           1. the paymaster is not paused;
///           2. `tx.origin` is `relayer`, the plane's relayer (on mainnet a CDP
///              Server Wallet account, an EOA the owner can rotate). Every
///              sponsored op has then passed the plane's relay policy. Without
///              this, anyone could call `EntryPoint.handleOps` with an
///              inflated fee and themselves as beneficiary, and the EntryPoint
///              would pay them out of this deposit (decision 0071);
///           3. `maxCost`, the most the EntryPoint may charge this deposit for
///              the op (its gas limits times `maxFeePerGas`, ERC-4337 v0.7), is
///              at most `maxCostPerOp`, so one op cannot spend the deposit;
///           4. `userOp.sender` runs the account code of the factory this
///              paymaster serves: the sender's code with the per-account words
///              at `MASK_OFFSETS` zeroed hashes to `ACCOUNT_CODE_HASH`
///              (`scripts/lib/paymaster.ts` derives the three values from the
///              deployed factory). The EntryPoint deploys a new sender from
///              `initCode` before it asks the paymaster, so a first op passes.
///         Validation returns an empty context, so the EntryPoint never calls
///         `postOp` and charges no unused-postOp penalty.
///
///         Reading `tx.origin` breaks the ERC-7562 rules public bundlers
///         apply, so no public bundler accepts an op naming this paymaster;
///         only the plane bundles them.
///
///         What a stolen relayer credential can still do: submit ops for
///         accounts its holder controls (anyone may deploy a Cofferdam
///         account) and have this deposit pay their gas, at most
///         `maxCostPerOp` each, until the owner pauses, rotates the relayer or
///         withdraws. With the relayer's CDP policy pinning `handleOps`'
///         beneficiary to the relayer itself, the deposit only moves to the
///         relayer (Cofferdam's) and is burnt as gas; without that pin, the
///         beneficiary would be paid up to `maxCostPerOp` an op. The deposit
///         the owner keeps is the bound on either.
contract CofferdamRelayPaymaster is IPaymaster, Ownable2Step {
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
    /// @notice The largest `maxCost` (wei) one sponsored op may carry.
    uint256 public maxCostPerOp;
    /// @notice While true, every op is refused.
    bool public paused;

    event RelayerChanged(address indexed previousRelayer, address indexed newRelayer);
    event MaxCostPerOpChanged(uint256 previousMaxCost, uint256 newMaxCost);
    event PausedSet(bool paused);

    error NotEntryPoint();
    error NotRelayer(address origin);
    error NotCofferdamAccount(address sender);
    error SponsorshipPaused();
    error MaxCostExceeded(uint256 maxCost, uint256 cap);
    error ZeroAddress();
    error ZeroMaxCost();
    error RelayerIsOwner();
    error InvalidAccountCode();
    error RenounceDisabled();

    /// @param entryPoint       The canonical EntryPoint v0.7.
    /// @param owner_           The owner from the first block: the company Safe.
    /// @param relayer_         The plane's relayer EOA.
    /// @param maxCostPerOp_    The largest `maxCost` one op may carry, in wei.
    /// @param accountCodeHash  The masked account code hash.
    /// @param accountCodeSize  The account runtime code size.
    /// @param maskOffsets      Byte offsets of the per-account 32-byte words.
    constructor(
        IEntryPoint entryPoint,
        address owner_,
        address relayer_,
        uint256 maxCostPerOp_,
        bytes32 accountCodeHash,
        uint256 accountCodeSize,
        uint16[] memory maskOffsets
    ) Ownable(owner_) {
        if (address(entryPoint) == address(0) || relayer_ == address(0)) revert ZeroAddress();
        if (relayer_ == owner_) revert RelayerIsOwner();
        if (maxCostPerOp_ == 0) revert ZeroMaxCost();
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
        maxCostPerOp = maxCostPerOp_;
        emit RelayerChanged(address(0), relayer_);
        emit MaxCostPerOpChanged(0, maxCostPerOp_);
    }

    /// @notice Deposit ETH to the EntryPoint for this paymaster's balance.
    receive() external payable {
        ENTRY_POINT.depositTo{value: msg.value}(address(this));
    }

    /// @notice Withdraw from the paymaster's EntryPoint balance. Owner only.
    function withdrawTo(address payable withdrawAddress, uint256 amount) external onlyOwner {
        if (withdrawAddress == address(0)) revert ZeroAddress();
        ENTRY_POINT.withdrawTo(withdrawAddress, amount);
    }

    /// @notice Point the paymaster at a new relayer (a rotated CDP account)
    ///         without moving the deposit. Owner only.
    function setRelayer(address newRelayer) external onlyOwner {
        if (newRelayer == address(0)) revert ZeroAddress();
        if (newRelayer == owner()) revert RelayerIsOwner();
        emit RelayerChanged(relayer, newRelayer);
        relayer = newRelayer;
    }

    /// @notice Set the largest `maxCost` one op may carry. Owner only; the
    ///         pause, not a zero cap, stops sponsorship.
    function setMaxCostPerOp(uint256 newMaxCost) external onlyOwner {
        if (newMaxCost == 0) revert ZeroMaxCost();
        emit MaxCostPerOpChanged(maxCostPerOp, newMaxCost);
        maxCostPerOp = newMaxCost;
    }

    /// @notice Refuse (true) or resume (false) every sponsorship. Owner only.
    function setPaused(bool paused_) external onlyOwner {
        paused = paused_;
        emit PausedSet(paused_);
    }

    /// @notice Ownership cannot be renounced: the deposit could never be
    ///         withdrawn again.
    function renounceOwnership() public view override onlyOwner {
        revert RenounceDisabled();
    }

    /// @notice Sponsor a userOp the plane's relayer submits for a Cofferdam
    ///         account within the cap; revert for anything else.
    function validatePaymasterUserOp(
        IEntryPoint.PackedUserOperation calldata userOp,
        bytes32,
        uint256 maxCost
    ) external view returns (bytes memory context, uint256 validationData) {
        if (msg.sender != address(ENTRY_POINT)) revert NotEntryPoint();
        if (paused) revert SponsorshipPaused();
        // solhint-disable-next-line avoid-tx-origin
        if (tx.origin != relayer) revert NotRelayer(tx.origin);
        uint256 cap = maxCostPerOp;
        if (maxCost > cap) revert MaxCostExceeded(maxCost, cap);
        if (!isCofferdamAccount(userOp.sender)) revert NotCofferdamAccount(userOp.sender);
        // Empty context: the EntryPoint skips `postOp`.
        return ("", 0);
    }

    /// @notice Whether `account` runs this paymaster's factory account code.
    function isCofferdamAccount(address account) public view returns (bool) {
        if (account.code.length != ACCOUNT_CODE_SIZE) return false;
        bytes memory code = account.code;
        uint256 packed = MASK_OFFSETS;
        for (uint256 i = 0; i < MASK_COUNT; i++) {
            uint256 offset = (packed >> (16 * i)) & 0xffff;
            // Inside `code`: the constructor checked offset + 32 <= size.
            assembly ("memory-safe") {
                mstore(add(add(code, 0x20), offset), 0)
            }
        }
        return keccak256(code) == ACCOUNT_CODE_HASH;
    }

    /// @dev Never called: validation returns an empty context.
    function postOp(uint8, bytes calldata, uint256, uint256) external view {
        if (msg.sender != address(ENTRY_POINT)) revert NotEntryPoint();
    }
}
