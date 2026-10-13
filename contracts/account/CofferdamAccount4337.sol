// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAuthorityModule, Tier, Permission} from "../interfaces/IAuthorityModule.sol";
import {AuthorityManagerBase} from "./AuthorityManagerBase.sol";
import {IEntryPoint} from "../interfaces/IEntryPoint.sol";
import {CofferdamModuleRegistry} from "../registry/CofferdamModuleRegistry.sol";
import {CofferdamCeremonyAttesterRegistry} from "../registry/CofferdamCeremonyAttesterRegistry.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/// @title CofferdamAccount4337
/// @notice A multi-authority ERC-4337 smart account for Base. The onchain enforcer
///         of the tiered-authority model in `cofferdam-sdk/IDENTITY_LAYER_DESIGN.md`
///         §2.5 and decisions 0015 / 0016 in the `cofferdam` repository.
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

    /// @notice The keys that co-sign first-High enrolment and Partner recovery.
    CofferdamCeremonyAttesterRegistry public immutable CEREMONY_ATTESTERS;

    /// @notice `userOp.signature` authorityId selecting the Partner recovery
    ///         format (see `replacePartnerAuthority`).
    uint256 public constant RECOVERY_AUTHORITY_ID = type(uint256).max;

    /// @notice Ceremony actions bound into `ceremonyHash`.
    bytes32 public constant ACTION_ENROLL_FIRST_HIGH = keccak256("enroll-first-high");
    bytes32 public constant ACTION_REPLACE_PARTNER = keccak256("replace-partner");

    bytes32 private constant CEREMONY_TAG = keccak256("cofferdam-ceremony-v1");
    bytes32 private constant FIRST_HIGH_CHALLENGE_TAG = keccak256("cofferdam-first-high-v1");
    bytes32 private constant PARTNER_RECOVERY_TAG = keccak256("cofferdam-partner-recovery-v1");

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

    event FirstHighEnrolled(uint256 indexed signerAuthorityId, uint256 indexed highAuthorityId);
    event PartnerAuthorityReplaced(uint256 indexed oldAuthorityId, uint256 indexed newAuthorityId);

    error NotFromEntryPoint();
    error ZeroAddress();
    error HighAlreadyExists();
    error InvalidNewKeyAssertion();
    error InvalidPartnerRecovery();
    error CeremonyNotActive();
    error UntrustedCeremonyAttester();

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
    /// @param initialModule      The genesis authority module.
    /// @param initialConfig      Per-account material for that module.
    /// @param initialPermission  The genesis grant for Partner / Managed;
    ///                           empty for High.
    constructor(
        IEntryPoint entryPoint,
        CofferdamModuleRegistry moduleRegistry,
        CofferdamCeremonyAttesterRegistry ceremonyAttesters,
        IAuthorityModule initialModule,
        bytes memory initialConfig,
        Permission memory initialPermission
    ) EIP712("Cofferdam Account", "1") {
        if (address(entryPoint) == address(0)) revert ZeroAddress();
        if (address(moduleRegistry) == address(0) || address(ceremonyAttesters) == address(0)) revert ZeroAddress();
        ENTRY_POINT = entryPoint;
        MODULE_REGISTRY = moduleRegistry;
        CEREMONY_ATTESTERS = ceremonyAttesters;
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
    ///         Managed the result carries `validUntil` = the permission's expiry.
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
                validationData = uint256(_checkCallPolicy(a.tier, authorityId, userOp.callData)) << 160;
            }
        }

        // Pay the EntryPoint the missing funds (v0.7 still requires this).
        if (missingAccountFunds > 0) {
            (bool success,) = address(ENTRY_POINT).call{value: missingAccountFunds}("");
            require(success, "CofferdamAccount4337: deposit failed");
        }
    }

    /// @dev Tier gate on the userOp's top-level call; returns `validUntil`
    ///      (0 = no limit). High may do anything. Partner and Managed may
    ///      `execute` / `executeBatch` calls their permission lists, until it
    ///      expires, and may call `enrollFirstHigh` naming themselves while no
    ///      High exists (not subject to expiry, so an expired grant never
    ///      strands funds: the upgrade still needs the Cofferdam co-sign).
    function _checkCallPolicy(Tier t, uint256 authorityId, bytes calldata callData)
        internal
        view
        returns (uint48 validUntil)
    {
        if (t == Tier.High) return 0;
        if (t != Tier.Partner && t != Tier.LowManaged) revert TierNotPermitted(t);
        if (callData.length < 4) revert TierNotPermitted(t);

        bytes4 selector = bytes4(callData[:4]);
        if (selector == this.execute.selector) {
            (address target, uint256 value, bytes memory data) = abi.decode(callData[4:], (address, uint256, bytes));
            _checkPermittedCall(authorityId, target, value, data);
            return _permissions[authorityId].expiry;
        }
        if (selector == this.executeBatch.selector) {
            (address[] memory targets, uint256[] memory values, bytes[] memory data) =
                abi.decode(callData[4:], (address[], uint256[], bytes[]));
            if (targets.length != values.length || targets.length != data.length) revert TierNotPermitted(t);
            for (uint256 i = 0; i < targets.length; i++) {
                _checkPermittedCall(authorityId, targets[i], values[i], data[i]);
            }
            return _permissions[authorityId].expiry;
        }
        if (selector == this.enrollFirstHigh.selector && !upgradeLocked) {
            (uint256 signerId) = abi.decode(callData[4:], (uint256));
            if (signerId == authorityId) return 0;
        }
        revert TierNotPermitted(t);
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
    ///         this (as the userOp's call, or through `execute` to self).
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

    /// @notice Deactivate an authority. Only High may call this. The last
    ///         active High authority can never be revoked.
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
