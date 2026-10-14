// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAuthorityModule, Tier, Permission} from "../interfaces/IAuthorityModule.sol";
import {AuthorityManagerBase} from "./AuthorityManagerBase.sol";
import {IEntryPoint} from "../interfaces/IEntryPoint.sol";
import {CofferdamModuleRegistry} from "../registry/CofferdamModuleRegistry.sol";
import {CofferdamCeremonyAttesterRegistry} from "../registry/CofferdamCeremonyAttesterRegistry.sol";
import {NullifierRegistry} from "../self/NullifierRegistry.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title CofferdamAccount4337
/// @notice A multi-authority ERC-4337 smart account for Base. The onchain enforcer
///         of the tiered-authority model in `cofferdam-sdk/IDENTITY_LAYER_DESIGN.md`
///         §2.5 and decisions 0015 / 0016 / 0023 in the `cofferdam` repository.
///
/// @dev    Every authentication method plugs in behind one `IAuthorityModule`
///         ABI, and every module must be on the `CofferdamModuleRegistry` the
///         factory pins into the account.
///
///         ERC-4337 flow:
///           1. Bundler submits UserOperation to EntryPoint
///           2. EntryPoint calls `validateUserOp` → we decode the authorityId
///              from the signature prefix, authenticate via the module, check
///              the call against the authority's tier, return validationData
///           3. EntryPoint calls `execute` / `executeBatch` / a management
///              function → we perform it
///
///         Tiers (enforced in `validateUserOp` against `userOp.callData`):
///           - High     (`cofferdam.xyz` passkey) → may make any call.
///           - Partner  (partner-RP passkey) and
///             Managed  (employer bridge key)    → may `execute` /
///                         `executeBatch` only calls their `Permission` lists
///                         (never the account itself, value within the cap),
///                         and may sign the co-signed `enrollFirstHigh` while
///                         no High exists. Nothing else: no authority changes,
///                         no ERC-1271.
///           - LowUntrusted is retired: no module of that tier can be installed.
///
///         Before High exists, two more paths exist, each needing a Cofferdam
///         ceremony co-sign from `CofferdamCeremonyAttesterRegistry`:
///           - `enrollFirstHigh`: Partner/Managed signs the op, the new
///             `cofferdam.xyz` passkey signs `firstHighChallenge`, and the
///             attester signs `ceremonyHash`.
///           - Partner recovery: `userOp.signature` uses authorityId
///             `RECOVERY_AUTHORITY_ID`, the new Partner passkey signs the
///             userOpHash, the partner backend signs the recovery, and the
///             attester co-signs; the call is `replacePartnerAuthority`.
///         Once High exists both are closed for good and only High may add or
///         revoke authorities.
///
///         After High exists (decision 0023):
///           - Probation: a High added by another High may transact at once,
///             but its userOps that call the account itself (add, revoke,
///             cancel a recovery) carry `validAfter` = the end of its
///             `PROBATION_PERIOD`; any older High may revoke it meanwhile.
///           - Hard recovery: `recoverHigh` is a direct call (relayed by the
///             plane, never a userOp) authorised by evidence instead of a
///             signature: a fresh Self `disclose` proof for this account whose
///             nullifier is the one `NULLIFIER_REGISTRY` binds to it, the new
///             `cofferdam.xyz` passkey's assertion, and the Self attester's
///             and the ceremony attester's co-signs on the ceremony nonce.
///             After `RECOVERY_DELAY` anyone may `finalizeRecovery`, which
///             revokes every High and installs the new one; until then any
///             surviving mature High may `cancelRecovery`.
///
///         SIGNATURE ENCODING for validateUserOp:
///           abi.encodePacked(uint256 authorityId, bytes userSignature)
///         The first 32 bytes select which authority to use; the rest is passed
///         to the module's `isValidSignature`.
contract CofferdamAccount4337 is AuthorityManagerBase, EIP712 {
    /// @notice The canonical ERC-4337 EntryPoint v0.7.
    ///         0x0000000071727De22E5E9d8BAf0edAc6f37da032 on Base.
    IEntryPoint public immutable ENTRY_POINT;

    /// @notice The allowlist of authority modules this account may install.
    CofferdamModuleRegistry public immutable MODULE_REGISTRY;

    /// @notice The keys that co-sign first-High enrolment, Partner recovery and
    ///         hard recovery.
    CofferdamCeremonyAttesterRegistry public immutable CEREMONY_ATTESTERS;

    /// @notice The Self.xyz nullifier registry: hard recovery checks the proof
    ///         through it and reads this account's binding from it.
    NullifierRegistry public immutable NULLIFIER_REGISTRY;

    /// @notice Seconds `recoverHigh` waits before `finalizeRecovery` may apply
    ///         it; 0 applies it in the same call. 72 hours on mainnet, 0 on
    ///         testnets (decision 0023), pinned by the factory.
    uint256 public immutable RECOVERY_DELAY;

    /// @notice `userOp.signature` authorityId selecting the Partner recovery
    ///         format (see `replacePartnerAuthority`).
    uint256 public constant RECOVERY_AUTHORITY_ID = type(uint256).max;

    /// @notice Ceremony actions bound into `ceremonyHash`.
    bytes32 public constant ACTION_ENROLL_FIRST_HIGH = keccak256("enroll-first-high");
    bytes32 public constant ACTION_REPLACE_PARTNER = keccak256("replace-partner");
    bytes32 public constant ACTION_RECOVER_HIGH = keccak256("recover-high");

    bytes32 private constant CEREMONY_TAG = keccak256("cofferdam-ceremony-v1");
    bytes32 private constant FIRST_HIGH_CHALLENGE_TAG = keccak256("cofferdam-first-high-v1");
    bytes32 private constant PARTNER_RECOVERY_TAG = keccak256("cofferdam-partner-recovery-v1");
    bytes32 private constant RECOVERY_CHALLENGE_TAG = keccak256("cofferdam-recover-high-v1");

    /// @dev EIP-712 type wrapping an ERC-1271 digest so a signature is only
    ///      valid for this account on this chain.
    bytes32 private constant MESSAGE_TYPEHASH = keccak256("CofferdamAccountMessage(bytes32 hash)");

    /// @dev ERC-4337 validationData for a signature that does not verify.
    uint256 private constant SIG_VALIDATION_FAILED = 1;

    /// @notice Single-use counter for ceremony attestations and the first-High
    ///         challenge; incremented by every consumed attestation.
    uint256 public ceremonyNonce;

    /// @notice A Cofferdam ceremony co-sign, valid in `[notBefore, expiry]`.
    ///         `notBefore` carries the 72-hour cooldown after a recovery.
    struct CeremonyAttestation {
        uint48 notBefore;
        uint48 expiry;
        bytes signature;
    }

    /// @notice The partner backend's vouch for a recovery, signed (EIP-191) by
    ///         the `partnerSigner` in the old Partner config over
    ///         `partnerRecoveryHash`.
    struct PartnerRecovery {
        uint48 recoveredAt;
        bytes signature;
    }

    /// @notice A Self.xyz `vc_and_disclose` proof with the `userContextData`
    ///         preimage of its `userIdentifier` signal (see `NullifierRegistry`).
    struct SelfProof {
        uint256[2] a;
        uint256[2][2] b;
        uint256[2] c;
        uint256[21] pubSignals;
        bytes userContextData;
    }

    /// @notice A hard recovery waiting for `RECOVERY_DELAY`.
    struct PendingRecovery {
        IAuthorityModule module;
        uint48 readyAt;
        uint256 nullifier;
        bytes config;
    }

    PendingRecovery internal _pendingRecovery;

    event FirstHighEnrolled(uint256 indexed signerAuthorityId, uint256 indexed highAuthorityId);
    event PartnerAuthorityReplaced(uint256 indexed oldAuthorityId, uint256 indexed newAuthorityId);
    event RecoveryRequested(address indexed module, bytes32 indexed configHash, uint48 readyAt);
    event RecoveryCancelled(address indexed module, bytes32 indexed configHash);
    event HighRecovered(uint256 indexed highAuthorityId);

    error NotFromEntryPoint();
    error ZeroAddress();
    error HighAlreadyExists();
    error InvalidNewKeyAssertion();
    error InvalidPartnerRecovery();
    error CeremonyNotActive();
    error UntrustedCeremonyAttester();
    error NoHighToRecover();
    error NotBoundIdentity();
    error NoPendingRecovery();
    error RecoveryNotReady(uint48 readyAt);

    modifier onlyEntryPoint() {
        if (msg.sender != address(ENTRY_POINT)) revert NotFromEntryPoint();
        _;
    }

    /// @dev Management functions run either as the userOp's top-level call
    ///      (EntryPoint) or through `execute` to self (High only, enforced in
    ///      validation).
    modifier onlyEntryPointOrSelf() {
        if (msg.sender != address(ENTRY_POINT) && msg.sender != address(this)) revert NotFromEntryPoint();
        _;
    }

    // ── Constructor ──────────────────────────────────────────────────────────

    /// @notice Bootstrap the account with authority 0: a High passkey (created
    ///         on a Cofferdam surface), a Partner passkey (created in the
    ///         partner app) or a Managed bridge key (enterprise onboarding).
    /// @param entryPoint         The canonical ERC-4337 EntryPoint address.
    /// @param moduleRegistry     The module allowlist (pinned by the factory).
    /// @param ceremonyAttesters  The ceremony co-sign registry (pinned by the factory).
    /// @param nullifierRegistry  The Self.xyz nullifier registry (pinned by the factory).
    /// @param recoveryDelay      The hard-recovery delay in seconds (pinned by the factory).
    /// @param initialModule      The genesis authority module.
    /// @param initialConfig      Per-account material for that module.
    /// @param initialPermission  The genesis grant for Partner / Managed;
    ///                           empty for High.
    constructor(
        IEntryPoint entryPoint,
        CofferdamModuleRegistry moduleRegistry,
        CofferdamCeremonyAttesterRegistry ceremonyAttesters,
        NullifierRegistry nullifierRegistry,
        uint256 recoveryDelay,
        IAuthorityModule initialModule,
        bytes memory initialConfig,
        Permission memory initialPermission
    ) EIP712("Cofferdam Account", "1") {
        if (address(entryPoint) == address(0)) revert ZeroAddress();
        if (address(moduleRegistry) == address(0) || address(ceremonyAttesters) == address(0)) revert ZeroAddress();
        if (address(nullifierRegistry) == address(0)) revert ZeroAddress();
        ENTRY_POINT = entryPoint;
        MODULE_REGISTRY = moduleRegistry;
        CEREMONY_ATTESTERS = ceremonyAttesters;
        NULLIFIER_REGISTRY = nullifierRegistry;
        RECOVERY_DELAY = recoveryDelay;
        _initFirstAuthority(initialModule, initialConfig, initialPermission);
    }

    function _isAllowedModule(IAuthorityModule module) internal view override returns (bool) {
        return MODULE_REGISTRY.isAllowedModule(address(module));
    }

    // ── ERC-4337 entrypoints ──────────────────────────────────────────────────

    /// @notice ERC-4337 v0.7 validation. Called by the EntryPoint.
    /// @dev    Signature format: abi.encodePacked(uint256 authorityId, bytes userSig).
    ///         Returns SIG_VALIDATION_FAILED when the module rejects the
    ///         signature (so bundlers can estimate gas with a dummy signature)
    ///         and reverts on every other failure: unknown or inactive
    ///         authority, or a call the tier may not make. For Partner and
    ///         Managed the result carries `validUntil` = the permission's expiry;
    ///         for a probationary High's call to the account itself it carries
    ///         `validAfter` = the end of its probation (no TIMESTAMP opcode in
    ///         validation: the EntryPoint enforces the window).
    function validateUserOp(
        IEntryPoint.PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external payable onlyEntryPoint returns (uint256 validationData) {
        bytes calldata sig = userOp.signature;
        require(sig.length >= 32, "CofferdamAccount4337: signature too short");
        uint256 authorityId;
        assembly {
            authorityId := calldataload(sig.offset)
        }
        bytes calldata userSig;
        assembly {
            userSig.offset := add(sig.offset, 32)
            userSig.length := sub(sig.length, 32)
        }

        if (authorityId == RECOVERY_AUTHORITY_ID) {
            validationData = _validatePartnerRecovery(userOp.callData, userOpHash, userSig);
        } else {
            Authority storage a = _authorities[authorityId];
            if (address(a.module) == address(0)) revert UnknownAuthority(authorityId);
            if (!a.active) revert InactiveAuthority(authorityId);
            if (!a.module.isValidSignature(address(this), userOpHash, a.config, userSig)) {
                validationData = SIG_VALIDATION_FAILED;
            } else {
                (uint48 validUntil, uint48 validAfter) = _checkCallPolicy(a.tier, authorityId, userOp.callData);
                validationData = (uint256(validUntil) << 160) | (uint256(validAfter) << 208);
            }
        }

        // Pay the EntryPoint the missing funds (v0.7 still requires this).
        if (missingAccountFunds > 0) {
            (bool success,) = address(ENTRY_POINT).call{value: missingAccountFunds}("");
            require(success, "CofferdamAccount4337: deposit failed");
        }
    }

    /// @dev Tier gate on the userOp's top-level call; returns `validUntil`
    ///      (0 = no limit) and `validAfter`. High may do anything; a High that
    ///      was added by another High gets `validAfter` = its probation end on
    ///      any call that reaches the account itself (decision 0023). Partner
    ///      and Managed may
    ///      `execute` / `executeBatch` calls their permission lists, until it
    ///      expires, and may call `enrollFirstHigh` naming themselves while no
    ///      High exists (not subject to expiry, so an expired grant never
    ///      strands funds: the upgrade still needs the Cofferdam co-sign).
    function _checkCallPolicy(Tier t, uint256 authorityId, bytes calldata callData)
        internal
        view
        returns (uint48 validUntil, uint48 validAfter)
    {
        if (t == Tier.High) {
            uint48 probationEnds = _probationEnds[authorityId];
            if (probationEnds != 0 && _callsSelf(callData)) return (0, probationEnds);
            return (0, 0);
        }
        if (t != Tier.Partner && t != Tier.LowManaged) revert TierNotPermitted(t);
        if (callData.length < 4) revert TierNotPermitted(t);

        bytes4 selector = bytes4(callData[:4]);
        if (selector == this.execute.selector) {
            (address target, uint256 value, bytes memory data) = abi.decode(callData[4:], (address, uint256, bytes));
            _checkPermittedCall(authorityId, target, value, data);
            return (_permissions[authorityId].expiry, 0);
        }
        if (selector == this.executeBatch.selector) {
            (address[] memory targets, uint256[] memory values, bytes[] memory data) =
                abi.decode(callData[4:], (address[], uint256[], bytes[]));
            if (targets.length != values.length || targets.length != data.length) revert TierNotPermitted(t);
            for (uint256 i = 0; i < targets.length; i++) {
                _checkPermittedCall(authorityId, targets[i], values[i], data[i]);
            }
            return (_permissions[authorityId].expiry, 0);
        }
        if (selector == this.enrollFirstHigh.selector && !upgradeLocked) {
            (uint256 signerId) = abi.decode(callData[4:], (uint256));
            if (signerId == authorityId) return (0, 0);
        }
        revert TierNotPermitted(t);
    }

    /// @dev Whether a userOp's top-level call reaches the account itself: any
    ///      selector other than `execute` / `executeBatch` (the management
    ///      functions), or an `execute` / `executeBatch` naming this account.
    function _callsSelf(bytes calldata callData) private view returns (bool) {
        if (callData.length < 4) return true;
        bytes4 selector = bytes4(callData[:4]);
        if (selector == this.execute.selector) {
            (address target) = abi.decode(callData[4:], (address));
            return target == address(this);
        }
        if (selector == this.executeBatch.selector) {
            (address[] memory targets) = abi.decode(callData[4:], (address[]));
            for (uint256 i = 0; i < targets.length; i++) {
                if (targets[i] == address(this)) return true;
            }
            return false;
        }
        return true;
    }

    /// @notice Execute a single call. Called by the EntryPoint after validation.
    function execute(address target, uint256 value, bytes calldata data) external onlyEntryPoint {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 0x20), mload(result))
            }
        }
    }

    /// @notice Execute a batch of calls. Called by the EntryPoint after validation.
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata data
    ) external onlyEntryPoint {
        require(targets.length == values.length && targets.length == data.length, "CofferdamAccount4337: array length mismatch");
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, bytes memory result) = targets[i].call{value: values[i]}(data[i]);
            if (!success) {
                assembly {
                    revert(add(result, 0x20), mload(result))
                }
            }
        }
    }

    // ── Authority management (High only, enforced in validateUserOp) ─────────

    /// @notice Add an authority: a backup High passkey (≤ MAX_PASSKEYS), or a
    ///         Partner / Managed grant with its permission. Only High may call
    ///         this (as the userOp's call, or through `execute` to self), and
    ///         only once out of probation. A High added here is probationary
    ///         for `PROBATION_PERIOD` (decision 0023).
    /// @param newModule   A module listed in `MODULE_REGISTRY`.
    /// @param newConfig   Per-account material for that module.
    /// @param permission  Empty for High; the grant for Partner / Managed.
    function addAuthority(IAuthorityModule newModule, bytes calldata newConfig, Permission calldata permission)
        external
        onlyEntryPointOrSelf
        returns (uint256 authorityId)
    {
        return _addAuthority(newModule, newConfig, permission, true);
    }

    /// @notice Deactivate an authority. Only a High out of probation may call
    ///         this. The last active High authority can never be revoked.
    function revokeAuthority(uint256 targetId) external onlyEntryPointOrSelf {
        _revokeAuthorityRecord(targetId);
    }

    // ── First High (decision 0016) ───────────────────────────────────────────

    /// @notice Enrol the first High (`cofferdam.xyz`) passkey on a Partner or
    ///         Managed account. Three signatures in one operation:
    ///           1. the userOp is signed by `signerId` (Partner or Managed),
    ///              checked in `validateUserOp`;
    ///           2. `highAssertion`: the new passkey's assertion over
    ///              `firstHighChallenge(ceremonyNonce)`, verified by its module
    ///              (`WebAuthnPasskeyAuthority` pins `rpIdHash` and UV);
    ///           3. `attestation`: a Cofferdam ceremony co-sign over
    ///              `ceremonyHash(ACTION_ENROLL_FIRST_HIGH, keccak256(highConfig),
    ///              partnerId, ceremonyNonce, notBefore, expiry)`.
    /// @dev    Only reachable from the EntryPoint after `validateUserOp`
    ///         accepted `signerId` for this call; a High self-call would find
    ///         `upgradeLocked` set.
    function enrollFirstHigh(
        uint256 signerId,
        IAuthorityModule highModule,
        bytes calldata highConfig,
        bytes calldata highAssertion,
        CeremonyAttestation calldata attestation
    ) external onlyEntryPointOrSelf returns (uint256 highAuthorityId) {
        if (upgradeLocked) revert HighAlreadyExists();
        Authority storage signer = _authorities[signerId];
        if (!signer.active || (signer.tier != Tier.Partner && signer.tier != Tier.LowManaged)) {
            revert TierNotPermitted(signer.tier);
        }
        if (highModule.tier() != Tier.High) revert TierNotPermitted(highModule.tier());
        if (!_isAllowedModule(highModule)) revert ModuleNotAllowed(address(highModule));

        uint256 nonce = ceremonyNonce;
        if (!highModule.isValidSignature(address(this), firstHighChallenge(nonce), highConfig, highAssertion)) {
            revert InvalidNewKeyAssertion();
        }
        _consumeCeremony(ACTION_ENROLL_FIRST_HIGH, keccak256(highConfig), _partnerIdOf(signer), attestation);

        Permission memory none;
        highAuthorityId = _addAuthority(highModule, highConfig, none, false);
        emit FirstHighEnrolled(signerId, highAuthorityId);
    }

    /// @notice The digest the new High passkey signs in `enrollFirstHigh`:
    ///         `(account, chainId, nonce)` under a domain tag.
    function firstHighChallenge(uint256 nonce) public view returns (bytes32) {
        return keccak256(abi.encode(FIRST_HIGH_CHALLENGE_TAG, block.chainid, address(this), nonce));
    }

    // ── Partner recovery before High (decision 0016) ─────────────────────────

    /// @notice Replace the Partner authority `oldId` with a new partner-RP
    ///         passkey after the user recovered their partner account (lost
    ///         device). Only while no High exists. The userOp uses the recovery
    ///         signature format: authorityId `RECOVERY_AUTHORITY_ID` followed by
    ///         the NEW passkey's assertion over the userOpHash. Validation also
    ///         checks `recovery` (the partner backend's vouch); this function
    ///         checks the Cofferdam co-sign over `ceremonyHash(
    ///         ACTION_REPLACE_PARTNER, keccak256(newConfig), partnerId, ...)`.
    ///         The new authority keeps the old permission, partner and RP.
    function replacePartnerAuthority(
        uint256 oldId,
        bytes calldata newConfig,
        PartnerRecovery calldata, /* recovery: checked in validateUserOp */
        CeremonyAttestation calldata attestation
    ) external onlyEntryPoint returns (uint256 newId) {
        if (upgradeLocked) revert HighAlreadyExists();
        Authority storage old = _authorities[oldId];
        if (old.tier != Tier.Partner) revert InvalidPartnerRecovery();
        _consumeCeremony(ACTION_REPLACE_PARTNER, keccak256(newConfig), _partnerIdOf(old), attestation);
        newId = _replaceAuthority(oldId, newConfig);
        emit PartnerAuthorityReplaced(oldId, newId);
    }

    /// @notice The digest the partner backend signs (EIP-191) to vouch for a
    ///         recovery of authority `oldId` to `keccak256(newConfig)`.
    function partnerRecoveryHash(uint256 oldId, bytes32 newConfigHash, uint48 recoveredAt)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(PARTNER_RECOVERY_TAG, block.chainid, address(this), oldId, newConfigHash, recoveredAt)
        );
    }

    /// @dev Validation of the recovery format. Reads only this account's
    ///      storage and calls the old authority's (stateless) module, so it
    ///      stays within ERC-7562. Griefing it needs the partner backend key.
    function _validatePartnerRecovery(bytes calldata callData, bytes32 userOpHash, bytes calldata newKeySig)
        internal
        view
        returns (uint256)
    {
        if (upgradeLocked) revert HighAlreadyExists();
        if (callData.length < 4 || bytes4(callData[:4]) != this.replacePartnerAuthority.selector) {
            revert InvalidPartnerRecovery();
        }
        (uint256 oldId, bytes memory newConfig, PartnerRecovery memory recovery,) =
            abi.decode(callData[4:], (uint256, bytes, PartnerRecovery, CeremonyAttestation));

        Authority storage old = _authorities[oldId];
        if (!old.active || old.tier != Tier.Partner) revert InvalidPartnerRecovery();
        if (old.config.length != 160 || newConfig.length != 160) revert InvalidPartnerRecovery();

        // Same RP, partner and partner backend key; only the passkey changes.
        (,, bytes32 rpIdHash, bytes32 partnerId, address partnerSigner) =
            abi.decode(old.config, (bytes32, bytes32, bytes32, bytes32, address));
        (,, bytes32 newRpIdHash, bytes32 newPartnerId, address newPartnerSigner) =
            abi.decode(newConfig, (bytes32, bytes32, bytes32, bytes32, address));
        if (newRpIdHash != rpIdHash || newPartnerId != partnerId || newPartnerSigner != partnerSigner) {
            revert InvalidPartnerRecovery();
        }

        // The partner backend vouches for this recovery.
        bytes32 h = MessageHashUtils.toEthSignedMessageHash(
            partnerRecoveryHash(oldId, keccak256(newConfig), recovery.recoveredAt)
        );
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(h, recovery.signature);
        if (err != ECDSA.RecoverError.NoError || recovered != partnerSigner) revert InvalidPartnerRecovery();

        // The new partner passkey signs the userOp.
        if (!old.module.isValidSignature(address(this), userOpHash, newConfig, newKeySig)) {
            return SIG_VALIDATION_FAILED;
        }
        return 0;
    }

    // ── Hard recovery (decision 0023) ────────────────────────────────────────

    /// @notice Replace every High passkey with `newModule` / `newConfig` on the
    ///         evidence of the bound person, for an account whose High
    ///         passkeys are lost. Anyone may submit it (the plane relays it as
    ///         a direct call; the proof check is not allowed in ERC-4337
    ///         validation). It needs, all bound to `ceremonyNonce`:
    ///           1. `newKeyAssertion`: the new passkey's assertion over
    ///              `recoveryChallenge(nonce)`, verified by its module
    ///              (`WebAuthnPasskeyAuthority` pins `cofferdam.xyz` and UV);
    ///           2. `proof`: a fresh Self `disclose` proof whose
    ///              `userContextData` names this account and whose nullifier
    ///              is `NULLIFIER_REGISTRY.accountToNullifier(this)`, with
    ///              `selfAttesterSig` over `NULLIFIER_REGISTRY.
    ///              recoveryMessageHash(this, pubSignals, nonce)` (the Self
    ///              attester signs behind its Celo gate);
    ///           3. `attestation`: the ceremony attester's co-sign over
    ///              `ceremonyHash(ACTION_RECOVER_HIGH, keccak256(newConfig), 0,
    ///              nonce, notBefore, expiry)`.
    ///         With `RECOVERY_DELAY` zero the recovery applies at once;
    ///         otherwise it waits for `finalizeRecovery`. A later request
    ///         replaces a pending one. Funds, grants and the identity binding
    ///         stay. Only accounts that have had a High and bound Self.
    function recoverHigh(
        IAuthorityModule newModule,
        bytes calldata newConfig,
        bytes calldata newKeyAssertion,
        SelfProof calldata proof,
        bytes calldata selfAttesterSig,
        CeremonyAttestation calldata attestation
    ) external {
        if (!upgradeLocked) revert NoHighToRecover();
        if (newModule.tier() != Tier.High) revert TierNotPermitted(newModule.tier());
        if (!_isAllowedModule(newModule)) revert ModuleNotAllowed(address(newModule));

        uint256 nonce = ceremonyNonce;
        if (!newModule.isValidSignature(address(this), recoveryChallenge(nonce), newConfig, newKeyAssertion)) {
            revert InvalidNewKeyAssertion();
        }
        uint256 nullifier = NULLIFIER_REGISTRY.provenNullifier(
            address(this), proof.a, proof.b, proof.c, proof.pubSignals, proof.userContextData, nonce, selfAttesterSig
        );
        if (nullifier == 0 || nullifier != NULLIFIER_REGISTRY.accountToNullifier(address(this))) {
            revert NotBoundIdentity();
        }
        _consumeCeremony(ACTION_RECOVER_HIGH, keccak256(newConfig), bytes32(0), attestation);

        if (RECOVERY_DELAY == 0) {
            delete _pendingRecovery;
            _applyRecovery(newModule, newConfig);
            return;
        }
        uint48 readyAt = uint48(block.timestamp + RECOVERY_DELAY);
        _pendingRecovery =
            PendingRecovery({module: newModule, readyAt: readyAt, nullifier: nullifier, config: newConfig});
        emit RecoveryRequested(address(newModule), keccak256(newConfig), readyAt);
    }

    /// @notice Apply a pending recovery once `RECOVERY_DELAY` has passed.
    ///         Anyone may call it; the authorisation happened in
    ///         `recoverHigh`. The identity must still be bound here.
    function finalizeRecovery() external returns (uint256 highAuthorityId) {
        PendingRecovery memory p = _pendingRecovery;
        if (address(p.module) == address(0)) revert NoPendingRecovery();
        if (block.timestamp < p.readyAt) revert RecoveryNotReady(p.readyAt);
        if (NULLIFIER_REGISTRY.accountToNullifier(address(this)) != p.nullifier) revert NotBoundIdentity();
        delete _pendingRecovery;
        return _applyRecovery(p.module, p.config);
    }

    /// @notice Veto a pending recovery: the answer to a stolen passport plus
    ///         recovery phrase. High only, as the userOp's call or through
    ///         `execute` to self; a probationary High cannot.
    function cancelRecovery() external onlyEntryPointOrSelf {
        PendingRecovery memory p = _pendingRecovery;
        if (address(p.module) == address(0)) revert NoPendingRecovery();
        delete _pendingRecovery;
        emit RecoveryCancelled(address(p.module), keccak256(p.config));
    }

    /// @notice The pending recovery, if any (`module` zero when none).
    function pendingRecovery()
        external
        view
        returns (address module, uint48 readyAt, uint256 nullifier, bytes memory config)
    {
        PendingRecovery storage p = _pendingRecovery;
        return (address(p.module), p.readyAt, p.nullifier, p.config);
    }

    /// @notice The digest the new High passkey signs in `recoverHigh`:
    ///         `(account, chainId, nonce)` under its own domain tag.
    function recoveryChallenge(uint256 nonce) public view returns (bytes32) {
        return keccak256(abi.encode(RECOVERY_CHALLENGE_TAG, block.chainid, address(this), nonce));
    }

    /// @dev Revoke every High and install the recovered one, which is not
    ///      probationary: the delay already ran.
    function _applyRecovery(IAuthorityModule module, bytes memory config) private returns (uint256 highAuthorityId) {
        _revokeAllHigh();
        Permission memory none;
        highAuthorityId = _addAuthority(module, config, none, false);
        emit HighRecovered(highAuthorityId);
    }

    // ── Ceremony attestations ────────────────────────────────────────────────

    /// @notice What a Cofferdam ceremony attester signs (EIP-191), for this
    ///         account on this chain.
    function ceremonyHash(
        bytes32 action,
        bytes32 newKeyHash,
        bytes32 partnerId,
        uint256 nonce,
        uint48 notBefore,
        uint48 expiry
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                CEREMONY_TAG, block.chainid, address(this), action, newKeyHash, partnerId, nonce, notBefore, expiry
            )
        );
    }

    /// @dev Check the attestation's window and signer, and spend the nonce.
    function _consumeCeremony(
        bytes32 action,
        bytes32 newKeyHash,
        bytes32 partnerId,
        CeremonyAttestation calldata att
    ) private {
        if (block.timestamp < att.notBefore || block.timestamp > att.expiry) revert CeremonyNotActive();
        uint256 nonce = ceremonyNonce;
        bytes32 h = ceremonyHash(action, newKeyHash, partnerId, nonce, att.notBefore, att.expiry);
        ceremonyNonce = nonce + 1;
        if (!CEREMONY_ATTESTERS.verifyAttesterSig(h, att.signature)) revert UntrustedCeremonyAttester();
    }

    /// @dev The partner id of a Partner authority (word 3 of its config), or 0
    ///      for Managed.
    function _partnerIdOf(Authority storage a) private view returns (bytes32 partnerId) {
        if (a.tier != Tier.Partner) return bytes32(0);
        (,,, partnerId,) = abi.decode(a.config, (bytes32, bytes32, bytes32, bytes32, address));
    }

    // ── ERC-1271 (isValidSignature) for off-chain signature verification ──────

    /// @notice ERC-1271 signature validation. Allows off-chain / cross-contract
    ///         signature checks (e.g. ERC-2612 permit, SIWE).
    /// @dev    Signature format as validateUserOp:
    ///         abi.encodePacked(uint256 authorityId, bytes userSig).
    ///
    ///         The authority must sign `replaySafeHash(digest)`, not `digest`
    ///         itself, so a signature for one account (or chain) cannot be
    ///         replayed on another account sharing the same passkey. Only High
    ///         authorities can produce a valid signature (decision 0016): a
    ///         Partner or Managed ERC-1271 signature could authorise a Permit
    ///         or Permit2 pull and move funds outside its permission.
    ///
    ///         ERC-6492 COUNTERFACTUAL SUPPORT: before deployment, signatures
    ///         can be wrapped in an ERC-6492 envelope (magicBytes, factory,
    ///         factoryCallData, this function's signature); the verifier
    ///         deploys the account, then calls this function.
    function isValidSignature(bytes32 digest, bytes calldata sig) external view returns (bytes4) {
        if (sig.length < 32) return bytes4(0xffffffff);
        uint256 authorityId;
        assembly {
            authorityId := calldataload(sig.offset)
        }
        bytes calldata userSig;
        assembly {
            userSig.offset := add(sig.offset, 32)
            userSig.length := sub(sig.length, 32)
        }
        Authority storage a = _authorities[authorityId];
        if (address(a.module) == address(0) || !a.active || a.tier != Tier.High) return bytes4(0xffffffff);
        if (a.module.isValidSignature(address(this), replaySafeHash(digest), a.config, userSig)) {
            return 0x1626ba7e; // ERC-1271 magic value
        }
        return bytes4(0xffffffff);
    }

    /// @notice The hash an authority signs for ERC-1271: `digest` wrapped in
    ///         EIP-712 typed data `CofferdamAccountMessage(bytes32 hash)` under
    ///         this account's domain (name "Cofferdam Account", version "1",
    ///         chainId, verifyingContract = this account).
    function replaySafeHash(bytes32 digest) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(MESSAGE_TYPEHASH, digest)));
    }

    // ── Receive ──────────────────────────────────────────────────────────────

    receive() external payable {}
}
