// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISelfGroth16Verifier} from "./ISelfGroth16Verifier.sol";
import {SelfAttesterRegistry} from "./SelfAttesterRegistry.sol";
import {SelfPublicSignals} from "./SelfPublicSignals.sol";

/// @title NullifierRegistry
/// @notice One-shot binding from a Self.xyz passport-derived nullifier to a
///         Cofferdam account address. Enforces the "one passport = one account"
///         rule that powers Cofferdam's sybil resistance.
/// @dev    This contract is pure Solidity.
///         The `verifyAndBind` entrypoint composes three independent security
///         checks:
///           1. Public-signal sanity: attestation ID matches E_PASSPORT, and the
///              proof's `userIdentifier` field equals the target `account`.
///           2. TEE attestation: the attester signature recovers to a key
///              currently allow-listed in `SelfAttesterRegistry`.
///           3. Groth16 proof: the deployed `Verifier_vc_and_disclose` accepts
///              the proof.
contract NullifierRegistry {
    ISelfGroth16Verifier public immutable verifier;
    SelfAttesterRegistry public immutable attesterRegistry;
    uint256 public immutable expectedScope;

    mapping(uint256 => address) public nullifierToAccount;
    mapping(address => uint256) public accountToNullifier;

    event NullifierBound(
        address indexed account,
        uint256 indexed nullifier,
        uint256 attestationId,
        uint256 scope
    );

    error ZeroAddress();
    error WrongAttestationId(uint256 expected, uint256 got);
    error WrongScope(uint256 expected, uint256 got);
    error UserIdentifierMismatch(address expected, address got);
    error AccountAlreadyBound(address account, uint256 boundNullifier);
    error NullifierAlreadyBound(uint256 nullifier, address boundAccount);
    error UntrustedAttester();
    error InvalidProof();

    constructor(
        address _verifier,
        address _attesterRegistry,
        uint256 _expectedScope
    ) {
        if (_verifier == address(0)) revert ZeroAddress();
        if (_attesterRegistry == address(0)) revert ZeroAddress();
        verifier = ISelfGroth16Verifier(_verifier);
        attesterRegistry = SelfAttesterRegistry(_attesterRegistry);
        expectedScope = _expectedScope;
    }

    function verifyAndBind(
        address account,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[21] calldata pubSignals,
        bytes calldata attesterSig
    ) external {
        if (account == address(0)) revert ZeroAddress();

        uint256 attestationId = pubSignals[SelfPublicSignals.ATTESTATION_ID];
        if (attestationId != SelfPublicSignals.E_PASSPORT_ATTESTATION_ID) {
            revert WrongAttestationId(SelfPublicSignals.E_PASSPORT_ATTESTATION_ID, attestationId);
        }

        uint256 scope = pubSignals[SelfPublicSignals.SCOPE];
        if (scope != expectedScope) revert WrongScope(expectedScope, scope);

        uint256 userIdentifier = pubSignals[SelfPublicSignals.USER_IDENTIFIER];
        if (userIdentifier != uint256(uint160(account))) {
            revert UserIdentifierMismatch(account, address(uint160(userIdentifier)));
        }

        uint256 nullifier = pubSignals[SelfPublicSignals.NULLIFIER];
        uint256 existingForAccount = accountToNullifier[account];
        if (existingForAccount != 0) {
            revert AccountAlreadyBound(account, existingForAccount);
        }
        address existingForNullifier = nullifierToAccount[nullifier];
        if (existingForNullifier != address(0)) {
            revert NullifierAlreadyBound(nullifier, existingForNullifier);
        }

        bytes32 msgHash = attesterMessageHash(account, pubSignals);
        if (!attesterRegistry.verifyAttesterSig(msgHash, attesterSig)) {
            revert UntrustedAttester();
        }

        if (!verifier.verifyProof(a, b, c, pubSignals)) revert InvalidProof();

        nullifierToAccount[nullifier] = account;
        accountToNullifier[account] = nullifier;

        emit NullifierBound(account, nullifier, attestationId, scope);
    }

    function isAccountBound(address account) external view returns (bool) {
        return accountToNullifier[account] != 0;
    }

    function isNullifierBound(uint256 nullifier) external view returns (bool) {
        return nullifierToAccount[nullifier] != address(0);
    }

    function attesterMessageHash(address account, uint256[21] calldata pubSignals)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                block.chainid,
                address(this),
                account,
                pubSignals
            )
        );
    }
}
