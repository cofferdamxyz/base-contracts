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
///           1. Public-signal sanity: attestation ID matches E_PASSPORT, the
///              scope matches `expectedScope`, and the proof's `userIdentifier`
///              signal is the commitment Self derives over `userContextData`,
///              whose embedded user ID is the target `account`.
///           2. TEE attestation: the attester signature recovers to a key
///              currently allow-listed in `SelfAttesterRegistry`.
///           3. Groth16 proof: the deployed `Verifier_vc_and_disclose` accepts
///              the proof.
contract NullifierRegistry {
    ISelfGroth16Verifier public immutable verifier;
    SelfAttesterRegistry public immutable attesterRegistry;
    uint256 public immutable expectedScope;

    /// @notice `destChainID` that the app declares in its `SelfApp` config and
    ///         that Self folds into the `userIdentifier` commitment. This is
    ///         Self's own destination-chain field, NOT the chain this registry
    ///         is deployed on — they are unrelated, and for Cofferdam it is
    ///         Celo's 42220 while this contract lives on Base.
    ///         Must equal `SelfApp.chainID` in
    ///         `cofferdam-app/src/features/self/selfAppConfig.ts`.
    uint256 public immutable selfDestChainId;

    mapping(uint256 => address) public nullifierToAccount;
    mapping(address => uint256) public accountToNullifier;

    event NullifierBound(
        address indexed account,
        uint256 indexed nullifier,
        uint256 attestationId,
        uint256 scope
    );

    error ZeroAddress();
    error ZeroScope();
    error ZeroDestChainId();
    error WrongAttestationId(uint256 expected, uint256 got);
    error WrongScope(uint256 expected, uint256 got);
    error UserIdentifierMismatch(address expected, address got);
    error MalformedUserContext(uint256 length);
    error WrongDestChainId(uint256 expected, uint256 got);
    error UserIdentifierCommitmentMismatch(uint256 expected, uint256 got);
    error AccountAlreadyBound(address account, uint256 boundNullifier);
    error NullifierAlreadyBound(uint256 nullifier, address boundAccount);
    error UntrustedAttester();
    error InvalidProof();

    constructor(
        address _verifier,
        address _attesterRegistry,
        uint256 _expectedScope,
        uint256 _selfDestChainId
    ) {
        if (_verifier == address(0)) revert ZeroAddress();
        if (_attesterRegistry == address(0)) revert ZeroAddress();
        // Both of the following are immutable and can never legitimately be 0:
        // a 0 scope reverts WrongScope on every real proof, and a 0 dest chain
        // id can never match Self's `SelfApp.chainID`. Reverting here turns a
        // silently-bricked deploy into a failed transaction.
        if (_expectedScope == 0) revert ZeroScope();
        if (_selfDestChainId == 0) revert ZeroDestChainId();
        verifier = ISelfGroth16Verifier(_verifier);
        attesterRegistry = SelfAttesterRegistry(_attesterRegistry);
        expectedScope = _expectedScope;
        selfDestChainId = _selfDestChainId;
    }

    /// @param userContextData The exact preimage Self hashed to produce the
    ///        proof's `userIdentifier` signal. Layout is
    ///        `abi.encodePacked(bytes32(destChainId), bytes32(userId), userDefinedData)`.
    ///        It needs no separate integrity guarantee: any tampering changes
    ///        the recomputed commitment and fails against the proof.
    function verifyAndBind(
        address account,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[21] calldata pubSignals,
        bytes calldata userContextData,
        bytes calldata attesterSig
    ) external {
        if (account == address(0)) revert ZeroAddress();

        uint256 attestationId = pubSignals[SelfPublicSignals.ATTESTATION_ID];
        if (attestationId != SelfPublicSignals.E_PASSPORT_ATTESTATION_ID) {
            revert WrongAttestationId(SelfPublicSignals.E_PASSPORT_ATTESTATION_ID, attestationId);
        }

        uint256 scope = pubSignals[SelfPublicSignals.SCOPE];
        if (scope != expectedScope) revert WrongScope(expectedScope, scope);

        _checkUserContext(account, pubSignals[SelfPublicSignals.USER_IDENTIFIER], userContextData);

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

    /// @notice Verify that `userContextData` is the preimage of the proof's
    ///         `userIdentifier` signal AND that it commits to `account`.
    /// @dev    Self computes the signal as
    ///         `uint160(ripemd160(sha256(userContextData)))` — see
    ///         `calculateUserIdentifierHash` in `self/common/src/utils/hash.ts`.
    ///         Checking only the recomputed hash would be insufficient: it
    ///         proves the preimage is authentic but not that it names the
    ///         account being bound, so the embedded user ID is compared too.
    function _checkUserContext(
        address account,
        uint256 userIdentifier,
        bytes calldata userContextData
    ) internal view {
        if (userContextData.length < 64) revert MalformedUserContext(userContextData.length);

        uint256 ctxChainId = uint256(bytes32(userContextData[0:32]));
        if (ctxChainId != selfDestChainId) {
            revert WrongDestChainId(selfDestChainId, ctxChainId);
        }

        // Self left-pads the user ID to 32 bytes, so an address-shaped ID is
        // exactly `bytes32(uint256(uint160(account)))`. Comparing the full word
        // also rejects IDs that merely share the low 20 bytes (e.g. a UUID).
        bytes32 ctxUserId = bytes32(userContextData[32:64]);
        if (ctxUserId != bytes32(uint256(uint160(account)))) {
            revert UserIdentifierMismatch(account, address(uint160(uint256(ctxUserId))));
        }

        uint256 commitment = uint256(uint160(ripemd160(abi.encodePacked(sha256(userContextData)))));
        if (commitment != userIdentifier) {
            revert UserIdentifierCommitmentMismatch(commitment, userIdentifier);
        }
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
