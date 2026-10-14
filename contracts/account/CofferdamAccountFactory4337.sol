// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Create2} from "@openzeppelin/contracts/utils/Create2.sol";
import {IAuthorityModule, Permission} from "../interfaces/IAuthorityModule.sol";
import {IEntryPoint} from "../interfaces/IEntryPoint.sol";
import {CofferdamAccount4337} from "./CofferdamAccount4337.sol";
import {CofferdamModuleRegistry} from "../registry/CofferdamModuleRegistry.sol";
import {CofferdamCeremonyAttesterRegistry} from "../registry/CofferdamCeremonyAttesterRegistry.sol";
import {NullifierRegistry} from "../self/NullifierRegistry.sol";

/// @title CofferdamAccountFactory4337
/// @notice CREATE2 factory for counterfactual CofferdamAccount4337 deployment.
///         The account address is deterministic from (factory, entryPoint,
///         module registry, ceremony registry, nullifier registry, recovery
///         delay, initialModule, initialConfig, initialPermission, salt) — the
///         same inputs always produce the same address, enabling
///         gas-sponsored deployment before the user has any onchain presence.
///         The factory pins the module registry and the ceremony attester
///         registry (decision 0016), and the nullifier registry and the
///         hard-recovery delay (decision 0023) into every account.
///
/// @dev    initCode = abi.encodePacked(
///           type(CofferdamAccount4337).creationCode,
///           abi.encode(entryPoint, moduleRegistry, ceremonyAttesters,
///                      nullifierRegistry, recoveryDelay,
///                      initialModule, initialConfig, initialPermission)
///         )
///         address  = keccak256(0xff, factory, salt, keccak256(initCode))[12:]
///
///         The account's creation code is larger than what fits beside the
///         factory's own code under the 24,576-byte runtime limit (EIP-170),
///         so the constructor writes it into two data contracts
///         (`ACCOUNT_CODE_A`, `ACCOUNT_CODE_B`: a STOP byte followed by one
///         half each) and the factory reads them back with EXTCODECOPY. Their
///         addresses are immutables, so `deployAccount` reads no factory
///         storage during ERC-4337 validation.
contract CofferdamAccountFactory4337 {
    /// @notice The canonical ERC-4337 EntryPoint v0.7.
    IEntryPoint public immutable ENTRY_POINT;
    CofferdamModuleRegistry public immutable MODULE_REGISTRY;
    CofferdamCeremonyAttesterRegistry public immutable CEREMONY_ATTESTERS;
    NullifierRegistry public immutable NULLIFIER_REGISTRY;
    /// @notice Hard-recovery delay pinned into every account: 72 hours on
    ///         mainnet, 0 on testnets (decision 0023).
    uint256 public immutable RECOVERY_DELAY;

    /// @notice The two halves of `type(CofferdamAccount4337).creationCode`.
    address public immutable ACCOUNT_CODE_A;
    address public immutable ACCOUNT_CODE_B;
    uint256 private immutable LEN_A;
    uint256 private immutable LEN_B;

    event AccountDeployed(address indexed account, address indexed initialModule, bytes32 salt);

    error ZeroAddress();
    error CodeStoreFailed();

    constructor(
        IEntryPoint entryPoint,
        CofferdamModuleRegistry moduleRegistry,
        CofferdamCeremonyAttesterRegistry ceremonyAttesters,
        NullifierRegistry nullifierRegistry,
        uint256 recoveryDelay
    ) {
        if (address(nullifierRegistry) == address(0)) revert ZeroAddress();
        ENTRY_POINT = entryPoint;
        MODULE_REGISTRY = moduleRegistry;
        CEREMONY_ATTESTERS = ceremonyAttesters;
        NULLIFIER_REGISTRY = nullifierRegistry;
        RECOVERY_DELAY = recoveryDelay;

        bytes memory code = type(CofferdamAccount4337).creationCode;
        uint256 lenA = code.length / 2;
        uint256 lenB = code.length - lenA;
        ACCOUNT_CODE_A = _store(code, 0, lenA);
        ACCOUNT_CODE_B = _store(code, lenA, lenB);
        LEN_A = lenA;
        LEN_B = lenB;
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
        bytes memory initCode = _initCode(initialModule, initialConfig, initialPermission);
        address addr = Create2.computeAddress(salt, keccak256(initCode), address(this));
        if (addr.code.length > 0) {
            return CofferdamAccount4337(payable(addr));
        }
        CofferdamAccount4337 account = CofferdamAccount4337(payable(Create2.deploy(0, salt, initCode)));
        emit AccountDeployed(address(account), address(initialModule), salt);
        return account;
    }

    /// @notice The account's full creation code, reassembled from the halves.
    function accountCreationCode() public view returns (bytes memory code) {
        (address a, address b, uint256 lenA, uint256 lenB) = (ACCOUNT_CODE_A, ACCOUNT_CODE_B, LEN_A, LEN_B);
        code = new bytes(lenA + lenB);
        assembly {
            extcodecopy(a, add(code, 0x20), 1, lenA)
            extcodecopy(b, add(add(code, 0x20), lenA), 1, lenB)
        }
    }

    function _initCode(IAuthorityModule initialModule, bytes memory initialConfig, Permission memory initialPermission)
        private
        view
        returns (bytes memory)
    {
        return abi.encodePacked(
            accountCreationCode(),
            abi.encode(
                ENTRY_POINT,
                MODULE_REGISTRY,
                CEREMONY_ATTESTERS,
                NULLIFIER_REGISTRY,
                RECOVERY_DELAY,
                initialModule,
                initialConfig,
                initialPermission
            )
        );
    }

    /// @dev Deploy a data contract whose runtime code is a STOP byte followed
    ///      by `code[offset:offset+len]`, so it can never run as a contract.
    function _store(bytes memory code, uint256 offset, uint256 len) private returns (address pointer) {
        // Creation code (10 bytes): PUSH2 size, DUP1, PUSH1 0x0a,
        // RETURNDATASIZE (0), CODECOPY, RETURNDATASIZE (0), RETURN; then the
        // runtime (STOP + data) at offset 0x0a.
        bytes memory runtime = new bytes(len + 1);
        assembly {
            mcopy(add(runtime, 0x21), add(add(code, 0x20), offset), len)
        }
        bytes memory creation = abi.encodePacked(hex"61", uint16(len + 1), hex"80600a3d393df3", runtime);
        assembly {
            pointer := create(0, add(creation, 0x20), mload(creation))
        }
        if (pointer == address(0)) revert CodeStoreFailed();
    }
}
