// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IAuthorityModule} from "../interfaces/IAuthorityModule.sol";
import {IEntryPoint} from "../interfaces/IEntryPoint.sol";
import {CofferdamAccount4337} from "./CofferdamAccount4337.sol";

/// @title CofferdamAccountFactory4337
/// @notice CREATE2 factory for counterfactual CofferdamAccount4337 deployment.
///         The account address is deterministic from (factory, entryPoint,
///         initialModule, initialConfig, salt) — the same inputs always produce
///         the same address, enabling gas-sponsored deployment before the user
///         has any onchain presence.
///         Uses the preinstalled ERC-4337 EntryPoint v0.7 on Base.
///
/// @dev    The factory deploys via `CREATE2` using a user-supplied `salt`. The
///         account constructor takes (entryPoint, initialModule, initialConfig),
///         so the counterfactual address is:
///
///           keccak256(0xff, factory, salt, keccak256(initCode))[12:]
///
///         where initCode = abi.encodePacked(
///           type(CofferdamAccount4337).creationCode,
///           abi.encode(entryPoint, initialModule, initialConfig)
///         )
///
contract CofferdamAccountFactory4337 {
    /// @notice The canonical ERC-4337 EntryPoint v0.7.
    IEntryPoint public immutable ENTRY_POINT;

    event AccountDeployed(address indexed account, address indexed initialModule, bytes32 salt);

    constructor(IEntryPoint entryPoint) {
        ENTRY_POINT = entryPoint;
    }

    /// @notice Compute the counterfactual address for a given configuration + salt.
    /// @param initialModule  The bootstrap authority module (passkey or session).
    /// @param initialConfig  Per-account material for the module.
    /// @param salt           User-supplied CREATE2 salt.
    function getAddress(
        IAuthorityModule initialModule,
        bytes memory initialConfig,
        bytes32 salt
    ) public view returns (address) {
        bytes memory initCode = abi.encodePacked(
            type(CofferdamAccount4337).creationCode,
            abi.encode(ENTRY_POINT, initialModule, initialConfig)
        );
        return Create2.computeAddress(bytes32(salt), keccak256(initCode), address(this));
    }

    /// @notice Deploy (or re-deploy) an account. Idempotent — if the account
    ///         already exists at the computed address, this is a no-op.
    /// @param initialModule  The bootstrap authority module.
    /// @param initialConfig  Per-account material for the module.
    /// @param salt           User-supplied CREATE2 salt.
    function deployAccount(
        IAuthorityModule initialModule,
        bytes memory initialConfig,
        bytes32 salt
    ) public returns (CofferdamAccount4337) {
        address addr = getAddress(initialModule, initialConfig, salt);
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(addr)
        }
        if (codeSize > 0) {
            return CofferdamAccount4337(payable(addr));
        }

        bytes memory initCode = abi.encodePacked(
            type(CofferdamAccount4337).creationCode,
            abi.encode(ENTRY_POINT, initialModule, initialConfig)
        );
        CofferdamAccount4337 account = CofferdamAccount4337(
            payable(Create2.deploy(0, bytes32(salt), initCode))
        );
        emit AccountDeployed(address(account), address(initialModule), salt);
        return account;
    }
}
