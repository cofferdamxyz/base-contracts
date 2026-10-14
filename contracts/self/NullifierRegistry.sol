// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ISelfGroth16Verifier} from "./ISelfGroth16Verifier.sol";
import {SelfAttesterRegistry} from "./SelfAttesterRegistry.sol";
import {SelfPublicSignals} from "./SelfPublicSignals.sol";

/// @title NullifierRegistry
/// @notice Binding from a Self.xyz passport-derived nullifier to a Cofferdam
///         account address. Enforces the "one passport = one account" rule
///         that powers Cofferdam's sybil resistance. `verifyAndBind` is the
///         first bind; `rebind` (decision 0022) moves a bound nullifier to a
///         new account on a fresh proof, so a person who lost their device, or
///         whose account was created on retired contracts, recovers their
///         identity. At any time a nullifier maps to exactly one account.
/// @dev    This contract is pure Solidity.
///         The `verifyAndBind` and `rebind` entrypoints compose three
///         independent security checks:
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

    /// @notice Seconds a `rebind` waits before `finalizeRebind` may apply it;
    ///         0 applies it in the same call. During the wait the currently
    ///         bound account may `cancelRebind`, the veto against a stolen
    ///         passport plus recovery phrase. 72 hours on mainnet (decision
    ///         0022), 0 on testnets.
    uint256 public immutable rebindDelay;

    /// @dev Domain tag of the rebind attestation, so a bind signature never
    ///      replays as a rebind.
    bytes32 private constant REBIND_TAG = keccak256("cofferdam-rebind-v1");

    struct PendingRebind {
        address newAccount;
        uint48 readyAt;
    }

    mapping(uint256 => address) public nullifierToAccount;
    mapping(address => uint256) public accountToNullifier;
    /// @notice Rebind attestations consumed per nullifier; the attester signs
    ///         the current value, so every rebind signature is single-use.
    mapping(uint256 => uint256) public rebindCount;
    /// @notice The rebind waiting for `rebindDelay`, if any.
    mapping(uint256 => PendingRebind) public pendingRebind;

    event NullifierBound(
        address indexed account,
        uint256 indexed nullifier,
        uint256 attestationId,
        uint256 scope
    );
    event NullifierRebound(
        address indexed oldAccount,
        address indexed newAccount,
        uint256 indexed nullifier,
        uint256 epoch
    );
    event RebindRequested(
        address indexed oldAccount,
        address indexed newAccount,
        uint256 indexed nullifier,
        uint256 epoch,
        uint48 readyAt
    );
    event RebindCancelled(address indexed account, uint256 indexed nullifier, address newAccount);

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
    error NullifierNotBound(uint256 nullifier);
    error SameAccount(address account);
    error NoPendingRebind(uint256 nullifier);
    error RebindNotReady(uint48 readyAt);
    error NotBoundAccount(address caller, address bound);

    constructor(
        address _verifier,
        address _attesterRegistry,
        uint256 _expectedScope,
        uint256 _selfDestChainId,
        uint256 _rebindDelay
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
        rebindDelay = _rebindDelay;
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
        uint256 nullifier = _checkSignals(account, pubSignals, userContextData);
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
        emit NullifierBound(
            account, nullifier, pubSignals[SelfPublicSignals.ATTESTATION_ID], pubSignals[SelfPublicSignals.SCOPE]
        );
    }

    // ── Rebind (decision 0022) ───────────────────────────────────────────────

    /// @notice Move a bound nullifier to `newAccount` on a fresh `disclose`
    ///         proof whose `userContextData` names `newAccount`. The proof,
    ///         the public-signal checks and the attester co-sign are the same
    ///         as `verifyAndBind`; the attester signs `rebindMessageHash` with
    ///         the current `rebindCount`, consumed here. With `rebindDelay`
    ///         zero the move applies at once; otherwise it waits for
    ///         `finalizeRebind`, and the currently bound account may
    ///         `cancelRebind` meanwhile. A later request replaces a pending one.
    function rebind(
        address newAccount,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[21] calldata pubSignals,
        bytes calldata userContextData,
        bytes calldata attesterSig
    ) external {
        uint256 nullifier = _checkSignals(newAccount, pubSignals, userContextData);
        address oldAccount = nullifierToAccount[nullifier];
        if (oldAccount == address(0)) revert NullifierNotBound(nullifier);
        if (oldAccount == newAccount) revert SameAccount(newAccount);
        uint256 existingForAccount = accountToNullifier[newAccount];
        if (existingForAccount != 0) revert AccountAlreadyBound(newAccount, existingForAccount);

        uint256 epoch = rebindCount[nullifier];
        bytes32 msgHash = rebindMessageHash(newAccount, pubSignals, epoch);
        if (!attesterRegistry.verifyAttesterSig(msgHash, attesterSig)) revert UntrustedAttester();
        if (!verifier.verifyProof(a, b, c, pubSignals)) revert InvalidProof();
        rebindCount[nullifier] = epoch + 1;

        if (rebindDelay == 0) {
            delete pendingRebind[nullifier];
            _applyRebind(nullifier, oldAccount, newAccount, epoch);
            return;
        }
        uint48 readyAt = uint48(block.timestamp + rebindDelay);
        pendingRebind[nullifier] = PendingRebind({newAccount: newAccount, readyAt: readyAt});
        emit RebindRequested(oldAccount, newAccount, nullifier, epoch, readyAt);
    }

    /// @notice Apply a pending rebind once `rebindDelay` has passed. Anyone
    ///         may call it; the authorisation happened in `rebind`.
    function finalizeRebind(uint256 nullifier) external {
        PendingRebind memory pending = pendingRebind[nullifier];
        if (pending.newAccount == address(0)) revert NoPendingRebind(nullifier);
        if (block.timestamp < pending.readyAt) revert RebindNotReady(pending.readyAt);
        address oldAccount = nullifierToAccount[nullifier];
        if (oldAccount == address(0)) revert NullifierNotBound(nullifier);
        uint256 existingForAccount = accountToNullifier[pending.newAccount];
        if (existingForAccount != 0) revert AccountAlreadyBound(pending.newAccount, existingForAccount);
        delete pendingRebind[nullifier];
        _applyRebind(nullifier, oldAccount, pending.newAccount, rebindCount[nullifier] - 1);
    }

    /// @notice The currently bound account vetoes a pending rebind of its
    ///         nullifier. Called from the account itself (an `execute` self-call
    ///         signed by its High authority).
    function cancelRebind(uint256 nullifier) external {
        address bound = nullifierToAccount[nullifier];
        if (msg.sender != bound) revert NotBoundAccount(msg.sender, bound);
        PendingRebind memory pending = pendingRebind[nullifier];
        if (pending.newAccount == address(0)) revert NoPendingRebind(nullifier);
        delete pendingRebind[nullifier];
        emit RebindCancelled(bound, nullifier, pending.newAccount);
    }

    /// @notice What the attester signs (EIP-191) to co-sign a rebind: distinct
    ///         from `attesterMessageHash` by the tag and bound to `epoch`.
    function rebindMessageHash(address newAccount, uint256[21] calldata pubSignals, uint256 epoch)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(block.chainid, address(this), REBIND_TAG, newAccount, pubSignals, epoch));
    }

    function _applyRebind(uint256 nullifier, address oldAccount, address newAccount, uint256 epoch) private {
        accountToNullifier[oldAccount] = 0;
        nullifierToAccount[nullifier] = newAccount;
        accountToNullifier[newAccount] = nullifier;
        emit NullifierRebound(oldAccount, newAccount, nullifier, epoch);
    }

    /// @dev The public-signal and user-context checks shared by `verifyAndBind`
    ///      and `rebind`; returns the proof's nullifier.
    function _checkSignals(address account, uint256[21] calldata pubSignals, bytes calldata userContextData)
        private
        view
        returns (uint256 nullifier)
    {
        if (account == address(0)) revert ZeroAddress();
        uint256 attestationId = pubSignals[SelfPublicSignals.ATTESTATION_ID];
        if (attestationId != SelfPublicSignals.E_PASSPORT_ATTESTATION_ID) {
            revert WrongAttestationId(SelfPublicSignals.E_PASSPORT_ATTESTATION_ID, attestationId);
        }
        uint256 scope = pubSignals[SelfPublicSignals.SCOPE];
        if (scope != expectedScope) revert WrongScope(expectedScope, scope);
        _checkUserContext(account, pubSignals[SelfPublicSignals.USER_IDENTIFIER], userContextData);
        return pubSignals[SelfPublicSignals.NULLIFIER];
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
