// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IEntryPoint} from "../../interfaces/IEntryPoint.sol";

// SPIKE (C1, 2026-11-17): a gas measurement for ruling A of the handle and
// income plan (workspace decision 0083 rule 4 against EIP-7702). NOT a design,
// never deployed, not reviewed for production. What a real one-time account
// also needs (0083 rule 4) is left out: the escrow-delegate slot of 0063 and
// anything else beyond one signer, `execute` and ERC-1271.

/// @notice Form (a): a minimal ERC-4337 v0.7 account with one fixed signer,
///         deployed as an ERC-1167 clone whose immutable argument is the
///         signer, from a CREATE2 factory. No storage of its own.
contract SpikeOneTimeAccount {
    IEntryPoint public immutable ENTRY_POINT;

    error NotEntryPoint();
    error CallFailed(bytes reason);

    constructor(IEntryPoint entryPoint) {
        ENTRY_POINT = entryPoint;
    }

    /// @notice The one signer, read from the clone's code.
    function signer() public view returns (address) {
        return abi.decode(Clones.fetchCloneArgs(address(this)), (address));
    }

    function validateUserOp(IEntryPoint.PackedUserOperation calldata op, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        if (msg.sender != address(ENTRY_POINT)) revert NotEntryPoint();
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(userOpHash, op.signature);
        validationData = (err == ECDSA.RecoverError.NoError && recovered == signer()) ? 0 : 1;
        if (missingAccountFunds != 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            ok;
        }
    }

    function execute(address target, uint256 value, bytes calldata data) external {
        if (msg.sender != address(ENTRY_POINT)) revert NotEntryPoint();
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
    }

    /// @notice ERC-1271, so the user can sign for this address.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        return (err == ECDSA.RecoverError.NoError && recovered == signer()) ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    receive() external payable {}
}

/// @notice The CREATE2 factory of form (a): the address depends on the signer
///         only (salt = the signer), so it is known before anything is
///         deployed, and the deploy is lazy, in the first user operation.
contract SpikeOneTimeAccountFactory {
    address public immutable IMPLEMENTATION;

    constructor(IEntryPoint entryPoint) {
        IMPLEMENTATION = address(new SpikeOneTimeAccount(entryPoint));
    }

    function createAccount(address signer) external returns (address account) {
        account = getAddress(signer);
        if (account.code.length != 0) return account;
        return Clones.cloneDeterministicWithImmutableArgs(IMPLEMENTATION, abi.encode(signer), bytes32(uint256(uint160(signer))));
    }

    function getAddress(address signer) public view returns (address) {
        return Clones.predictDeterministicAddressWithImmutableArgs(
            IMPLEMENTATION, abi.encode(signer), bytes32(uint256(uint160(signer)))
        );
    }
}

/// @notice Form (a), the same account deployed in full (no clone), to show
///         what a clone saves.
contract SpikeOneTimeAccountFull {
    IEntryPoint public immutable ENTRY_POINT;
    address public immutable SIGNER;

    error NotEntryPoint();
    error CallFailed(bytes reason);

    constructor(IEntryPoint entryPoint, address signer_) {
        ENTRY_POINT = entryPoint;
        SIGNER = signer_;
    }

    function validateUserOp(IEntryPoint.PackedUserOperation calldata op, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        if (msg.sender != address(ENTRY_POINT)) revert NotEntryPoint();
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(userOpHash, op.signature);
        validationData = (err == ECDSA.RecoverError.NoError && recovered == SIGNER) ? 0 : 1;
        if (missingAccountFunds != 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            ok;
        }
    }

    function execute(address target, uint256 value, bytes calldata data) external {
        if (msg.sender != address(ENTRY_POINT)) revert NotEntryPoint();
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        return (err == ECDSA.RecoverError.NoError && recovered == SIGNER) ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    receive() external payable {}
}

/// @notice A CREATE2 deployer for the full form.
contract SpikeOneTimeAccountFullFactory {
    IEntryPoint public immutable ENTRY_POINT;

    constructor(IEntryPoint entryPoint) {
        ENTRY_POINT = entryPoint;
    }

    function createAccount(address signer) external returns (address account) {
        account = getAddress(signer);
        if (account.code.length != 0) return account;
        return address(new SpikeOneTimeAccountFull{salt: bytes32(uint256(uint160(signer)))}(ENTRY_POINT, signer));
    }

    function getAddress(address signer) public view returns (address) {
        bytes32 h = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                bytes32(uint256(uint160(signer))),
                keccak256(abi.encodePacked(type(SpikeOneTimeAccountFull).creationCode, abi.encode(ENTRY_POINT, signer)))
            )
        );
        return address(uint160(uint256(h)));
    }
}

/// @notice Form (b): the code a scheme 1 stealth EOA delegates to under
///         EIP-7702. The EOA's own key is the signer (`address(this)`), so no
///         argument and no deploy. Two ways in: an ERC-4337 v0.7 user
///         operation (the bundler's type-4 transaction carries the
///         authorization), or a direct call any relayer sends with the EOA's
///         signature over the call and a nonce kept in the EOA's storage.
contract Spike7702Delegate {
    IEntryPoint public immutable ENTRY_POINT;

    /// @dev ERC-7201 slot for the direct-call nonce, so a later delegation to
    ///      other code does not collide with it.
    bytes32 private constant NONCE_SLOT = keccak256(abi.encode(uint256(keccak256("cofferdam.spike.7702.nonce")) - 1));

    error NotAuthorised();
    error BadSignature();
    error Expired();
    error CallFailed(bytes reason);

    constructor(IEntryPoint entryPoint) {
        ENTRY_POINT = entryPoint;
    }

    function validateUserOp(IEntryPoint.PackedUserOperation calldata op, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        if (msg.sender != address(ENTRY_POINT)) revert NotAuthorised();
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(userOpHash, op.signature);
        validationData = (err == ECDSA.RecoverError.NoError && recovered == address(this)) ? 0 : 1;
        if (missingAccountFunds != 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            ok;
        }
    }

    function execute(address target, uint256 value, bytes calldata data) external {
        if (msg.sender != address(ENTRY_POINT) && msg.sender != address(this)) revert NotAuthorised();
        _call(target, value, data);
    }

    /// @notice A relayed call signed by the EOA's key.
    function executeSigned(address target, uint256 value, bytes calldata data, uint256 deadline, bytes calldata signature)
        external
    {
        if (block.timestamp > deadline) revert Expired();
        uint256 nonce = directNonce();
        bytes32 h = keccak256(abi.encode(block.chainid, address(this), nonce, target, value, keccak256(data), deadline));
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(h, signature);
        if (err != ECDSA.RecoverError.NoError || recovered != address(this)) revert BadSignature();
        bytes32 slot = NONCE_SLOT;
        assembly {
            sstore(slot, add(nonce, 1))
        }
        _call(target, value, data);
    }

    function directNonce() public view returns (uint256 n) {
        bytes32 slot = NONCE_SLOT;
        assembly {
            n := sload(slot)
        }
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        return (err == ECDSA.RecoverError.NoError && recovered == address(this)) ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    function _call(address target, uint256 value, bytes calldata data) private {
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        if (!ok) revert CallFailed(ret);
    }

    receive() external payable {}
}

/// @notice A paymaster that sponsors everything, so the measured user
///         operations carry a paymaster's overhead as Cofferdam's would
///         (without its signature check).
contract SpikeSponsorAllPaymaster {
    IEntryPoint public immutable ENTRY_POINT;

    constructor(IEntryPoint entryPoint) {
        ENTRY_POINT = entryPoint;
    }

    function validatePaymasterUserOp(IEntryPoint.PackedUserOperation calldata, bytes32, uint256)
        external
        view
        returns (bytes memory context, uint256 validationData)
    {
        require(msg.sender == address(ENTRY_POINT), "entrypoint");
        return ("", 0);
    }

    function postOp(uint8, bytes calldata, uint256, uint256) external {}

    function deposit() external payable {
        ENTRY_POINT.depositTo{value: msg.value}(address(this));
    }
}
