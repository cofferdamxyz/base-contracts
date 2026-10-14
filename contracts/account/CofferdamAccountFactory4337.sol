// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IAuthorityModule, Permission} from "../interfaces/IAuthorityModule.sol";
import {IEntryPoint} from "../interfaces/IEntryPoint.sol";
import {CofferdamAccount4337} from "./CofferdamAccount4337.sol";
import {CofferdamModuleRegistry} from "../registry/CofferdamModuleRegistry.sol";
import {CofferdamCeremonyAttesterRegistry} from "../registry/CofferdamCeremonyAttesterRegistry.sol";

/// @title CofferdamAccountFactory4337
/// @notice CREATE2 factory for counterfactual CofferdamAccount4337 deployment.
///         The account address is deterministic from (factory, entryPoint,
///         module registry, ceremony registry, initialModule, initialConfig,
///         initialPermission, salt) — the same inputs always produce the same
///         address, enabling gas-sponsored deployment before the user has any
///         onchain presence. The factory pins the module registry and the
///         ceremony attester registry into every account (decision 0016).
///
/// @dev    initCode = abi.encodePacked(
///           type(CofferdamAccount4337).creationCode,
///           abi.encode(entryPoint, moduleRegistry, ceremonyAttesters,
///                      initialModule, initialConfig, initialPermission)
///         )
///         address  = keccak256(0xff, factory, salt, keccak256(initCode))[12:]
contract CofferdamAccountFactory4337 {
    /// @notice The canonical ERC-4337 EntryPoint v0.7.
    IEntryPoint public immutable ENTRY_POINT;
    CofferdamModuleRegistry public immutable MODULE_REGISTRY;
    CofferdamCeremonyAttesterRegistry public immutable CEREMONY_ATTESTERS;

    event AccountDeployed(address indexed account, address indexed initialModule, bytes32 salt);

    constructor(
        IEntryPoint entryPoint,
        CofferdamModuleRegistry moduleRegistry,
        CofferdamCeremonyAttesterRegistry ceremonyAttesters
    ) {
        ENTRY_POINT = entryPoint;
        MODULE_REGISTRY = moduleRegistry;
        CEREMONY_ATTESTERS = ceremonyAttesters;
    }

    /// @notice Compute the counterfactual address for a given configuration + salt.
    function getAddress(
        IAuthorityModule initialModule,
        bytes memory initialConfig,
        Permission memory initialPermission,
        bytes32 salt
    ) public view returns (address) {
        return Create2.computeAddress(
            salt, keccak256(_initCode(initialModule, initialConfig, initialPermission)), address(this)
        );
    }

    /// @notice Deploy an account. Idempotent — if the account already exists
    ///         at the computed address, this is a no-op.
    function deployAccount(
        IAuthorityModule initialModule,
        bytes memory initialConfig,
        Permission memory initialPermission,
        bytes32 salt
    ) public returns (CofferdamAccount4337) {
        address addr = getAddress(initialModule, initialConfig, initialPermission, salt);
        if (addr.code.length > 0) {
            return CofferdamAccount4337(payable(addr));
        }
        CofferdamAccount4337 account = CofferdamAccount4337(
            payable(Create2.deploy(0, salt, _initCode(initialModule, initialConfig, initialPermission)))
        );
        emit AccountDeployed(address(account), address(initialModule), salt);
        return account;
    }

    function _initCode(IAuthorityModule initialModule, bytes memory initialConfig, Permission memory initialPermission)
        private
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            type(CofferdamAccount4337).creationCode,
            abi.encode(ENTRY_POINT, MODULE_REGISTRY, CEREMONY_ATTESTERS, initialModule, initialConfig, initialPermission)
        );
    }
}
