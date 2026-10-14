// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAuthorityModule, Tier, Permission} from "../interfaces/IAuthorityModule.sol";

/// @title AuthorityManagerBase
/// @notice The chain-agnostic core of Cofferdam's tiered-authority model: the
///         authority registry, the passkey cap, the last-High guard, the
///         probation of newly added High passkeys (decision 0023) and the
///         per-authority permissions of the scoped tiers (Partner, Managed).
///         Specified in `cofferdam-sdk/IDENTITY_LAYER_DESIGN.md` §2.5 and
///         decisions 0015 / 0016 in the `cofferdam` repository. It is free of
///         any *execution* or *replay-scheme* opinion:
///
///           - `CofferdamAccount4337` — an ERC-4337 account whose replay
///                                       protection is the EntryPoint nonce and
///                                       whose signed digest is the userOpHash.
///
/// @dev    Modules are stateless singletons (see `IAuthorityModule`); all
///         per-account key material lives here in each `Authority.config` blob,
///         and what a scoped authority may call lives in `_permissions`.
///         This base owns ONLY: storage layout, the authority lifecycle
///         primitives (`_addAuthority`, `_revokeAuthorityRecord`), permission
///         storage and its call check, and the `_authenticate` module
///         dispatch. Subclasses own how a `digest` is formed, where the nonce
///         comes from, which modules are allowed and how calls are executed.
abstract contract AuthorityManagerBase {
    // ── Authority storage ──────────────────────────────────────────────────

    struct Authority {
        IAuthorityModule module;
        Tier tier;
        bool active;
        bytes config;
    }

    uint8 public constant MAX_PASSKEYS = 3;

    /// @notice Upper bound on `(target, selector)` plus `(codeHash, selector)`
    ///         pairs in one permission, so the check in `validateUserOp` has
    ///         bounded gas.
    uint256 public constant MAX_PERMISSION_ENTRIES = 16;

    /// @notice How long a High passkey added by another High stays
    ///         probationary (decision 0023): it may transact, but its userOps
    ///         that change the account itself (add, revoke, cancel a
    ///         recovery) are valid only after this period, and any older High
    ///         may revoke it meanwhile. Pinned by the factory: 72 hours on
    ///         mainnet, short on testnets.
    uint48 public immutable PROBATION_PERIOD;

    /// @dev `extcodehash` of an account that exists but has no code.
    bytes32 private constant EMPTY_CODE_HASH = keccak256("");

    mapping(uint256 => Authority) internal _authorities;
    uint256 public authorityCount;

    /// @notice Number of active High-tier (passkey) authorities. Capped at
    ///         MAX_PASSKEYS; the last one can never be revoked.
    uint8 public passkeyCount;

    /// @notice True once a High authority has existed on this account. From
    ///         then on only High may add or revoke authorities, and the
    ///         Partner/Managed first-High and recovery paths are closed for good.
    bool public upgradeLocked;

    /// @dev What each Partner / Managed authority may call (decision 0016).
    mapping(uint256 => Permission) internal _permissions;

    /// @dev When a probationary High authority matures (decision 0023); 0 for
    ///      every authority that never was probationary.
    mapping(uint256 => uint48) internal _probationEnds;

    // ── Events ───────────────────────────────────────────────────────────────

    event AuthorityAdded(uint256 indexed authorityId, address indexed module, Tier tier, bytes32 kind);
    event AuthorityRevoked(uint256 indexed authorityId);
    event PermissionGranted(uint256 indexed authorityId, bytes32 permissionHash, uint48 expiry);

    // ── Errors ─────────────────────────────────────────────────────────────

    error ZeroModule();
    error ModuleNotAllowed(address module);
    error UnknownAuthority(uint256 authorityId);
    error InactiveAuthority(uint256 authorityId);
    error InvalidAuthoritySignature(uint256 authorityId);
    error TierNotPermitted(Tier tier);
    error PasskeyCapReached();
    error LastHighAuthority();
    error InvalidPermission();
    error CallNotPermitted(address target, bytes4 selector);

    constructor(uint48 probationPeriod) {
        PROBATION_PERIOD = probationPeriod;
    }

    // ── Views ──────────────────────────────────────────────────────────────

    function getAuthority(uint256 authorityId)
        external
        view
        returns (address module, Tier tier, bool active, bytes memory config)
    {
        Authority storage a = _authorities[authorityId];
        return (address(a.module), a.tier, a.active, a.config);
    }

    /// @notice When a High authority added by another High leaves probation;
    ///         0 for the genesis High, a first High, a recovered High and every
    ///         other tier.
    function probationEndsAt(uint256 authorityId) external view returns (uint48) {
        return _probationEnds[authorityId];
    }

    /// @notice The permission of a Partner or Managed authority (empty for High).
    function getPermission(uint256 authorityId) external view returns (Permission memory) {
        return _permissions[authorityId];
    }

    // ── Hooks for the concrete account ───────────────────────────────────────

    /// @dev Whether `module` may be installed as an authority (module registry).
    function _isAllowedModule(IAuthorityModule module) internal view virtual returns (bool);

    // ── Initialisation ───────────────────────────────────────────────────────

    /// @notice Seed authority 0: a High passkey (created on a Cofferdam
    ///         surface), a Partner passkey (created in the partner app) or a
    ///         Managed bridge key (enterprise onboarding). A genesis grant has
    ///         no High signer behind it, so its permission carries no value.
    function _initFirstAuthority(
        IAuthorityModule initialModule,
        bytes memory initialConfig,
        Permission memory initialPermission
    ) internal {
        _addAuthority(initialModule, initialConfig, initialPermission, false);
    }

    // ── Authority lifecycle primitives ────────────────────────────────────────

    /// @dev Verify `signature` authorises `digest` under authority `authorityId`,
    ///      returning the authority's tier. Reverts on unknown/inactive/invalid.
    ///      `signature` is `memory` so both a calldata-sourced custom execute and
    ///      a decoded ERC-4337 userOp signature can call it.
    function _authenticate(uint256 authorityId, bytes32 digest, bytes memory signature)
        internal
        view
        returns (Tier)
    {
        Authority storage a = _authorities[authorityId];
        if (address(a.module) == address(0)) revert UnknownAuthority(authorityId);
        if (!a.active) revert InactiveAuthority(authorityId);
        if (!a.module.isValidSignature(address(this), digest, a.config, signature)) {
            revert InvalidAuthoritySignature(authorityId);
        }
        return a.tier;
    }

    /// @dev Append an authority record. The module must be on the allowlist and
    ///      report High, Partner or LowManaged (LowUntrusted is retired,
    ///      decision 0016). High is capped at MAX_PASSKEYS and latches
    ///      `upgradeLocked`. Partner and Managed carry a permission, validated
    ///      here; `byHigh` says whether a High signer authorised the grant
    ///      (only then may a Managed permission carry value, and a High added
    ///      that way starts its `PROBATION_PERIOD`).
    function _addAuthority(
        IAuthorityModule module,
        bytes memory config,
        Permission memory permission,
        bool byHigh
    ) internal returns (uint256 id) {
        if (address(module) == address(0)) revert ZeroModule();
        if (!_isAllowedModule(module)) revert ModuleNotAllowed(address(module));
        Tier t = module.tier();
        if (t != Tier.High && t != Tier.Partner && t != Tier.LowManaged) revert TierNotPermitted(t);

        id = authorityCount;
        if (t == Tier.High) {
            if (permission.targets.length != 0 || permission.selectors.length != 0) revert InvalidPermission();
            if (permission.valueCap != 0 || permission.expiry != 0) revert InvalidPermission();
            if (passkeyCount >= MAX_PASSKEYS) revert PasskeyCapReached();
            passkeyCount++;
            upgradeLocked = true;
            if (byHigh) _probationEnds[id] = uint48(block.timestamp) + PROBATION_PERIOD;
        } else {
            _checkPermissionShape(t, permission, byHigh);
            _permissions[id] = permission;
            emit PermissionGranted(id, keccak256(abi.encode(permission)), permission.expiry);
        }

        _authorities[id] = Authority({module: module, tier: t, active: true, config: config});
        authorityCount = id + 1;
        emit AuthorityAdded(id, address(module), t, module.kind());
    }

    /// @dev Deactivate an authority record; decrements the passkey count if the
    ///      target was an active passkey. Reverts if the target never existed or
    ///      is the last active High authority (the account would be frozen:
    ///      no other tier may add authorities once High has existed).
    function _revokeAuthorityRecord(uint256 targetId) internal {
        Authority storage target = _authorities[targetId];
        if (address(target.module) == address(0)) revert UnknownAuthority(targetId);

        if (target.active && target.tier == Tier.High) {
            if (passkeyCount <= 1) revert LastHighAuthority();
            passkeyCount--;
        }
        target.active = false;
        emit AuthorityRevoked(targetId);
    }

    /// @dev Deactivate every active High authority, bypassing the last-High
    ///      guard. Only for hard recovery, which installs a new High in the
    ///      same call (decision 0023).
    function _revokeAllHigh() internal {
        uint256 n = authorityCount;
        for (uint256 i = 0; i < n; i++) {
            Authority storage a = _authorities[i];
            if (a.active && a.tier == Tier.High) {
                a.active = false;
                emit AuthorityRevoked(i);
            }
        }
        passkeyCount = 0;
    }

    /// @dev Replace authority `oldId` with a new record on the same module
    ///      and tier, carrying the same permission (a re-key: the key changes,
    ///      what it may do does not). Used by the pre-High Partner recovery.
    function _replaceAuthority(uint256 oldId, bytes memory newConfig) internal returns (uint256 newId) {
        Authority storage old = _authorities[oldId];
        if (address(old.module) == address(0)) revert UnknownAuthority(oldId);
        if (!old.active) revert InactiveAuthority(oldId);
        old.active = false;
        emit AuthorityRevoked(oldId);

        newId = authorityCount;
        _authorities[newId] = Authority({module: old.module, tier: old.tier, active: true, config: newConfig});
        _permissions[newId] = _permissions[oldId];
        authorityCount = newId + 1;
        emit AuthorityAdded(newId, address(old.module), old.tier, old.module.kind());
        Permission memory p = _permissions[newId];
        emit PermissionGranted(newId, keccak256(abi.encode(p)), p.expiry);
    }

    // ── Permissions ───────────────────────────────────────────────────────────

    /// @dev Grant-time rules for a Partner / Managed permission.
    function _checkPermissionShape(Tier t, Permission memory p, bool byHigh) private view {
        uint256 n = p.targets.length;
        uint256 m = p.codeHashes.length;
        if (n != p.selectors.length || m != p.codeSelectors.length) revert InvalidPermission();
        if (n + m == 0 || n + m > MAX_PERMISSION_ENTRIES) revert InvalidPermission();
        for (uint256 i = 0; i < n; i++) {
            address target = p.targets[i];
            if (target == address(0) || target == address(this)) revert InvalidPermission();
            if (_isAssetMovingSelector(p.selectors[i])) revert InvalidPermission();
        }
        for (uint256 i = 0; i < m; i++) {
            bytes32 h = p.codeHashes[i];
            // Not "no account" (0), not "account without code", not this account's own code.
            if (h == bytes32(0) || h == EMPTY_CODE_HASH || h == address(this).codehash) revert InvalidPermission();
            if (_isAssetMovingSelector(p.codeSelectors[i])) revert InvalidPermission();
        }
        if (p.expiry != 0 && p.expiry <= block.timestamp) revert InvalidPermission();
        if (t == Tier.Partner) {
            // Partner: zero value and always expiring.
            if (p.valueCap != 0 || p.expiry == 0) revert InvalidPermission();
        } else if (p.valueCap != 0 && !byHigh) {
            // Managed: value only when a High signer granted it.
            revert InvalidPermission();
        }
    }

    /// @dev Check one call made by a Partner / Managed authority against its
    ///      permission. Never the account itself; value within the cap; the
    ///      `(target, selector)` pair, or the target's `(codeHash, selector)`
    ///      pair, must be listed. The code hash is read only when no address
    ///      entry matches; ERC-7562 allows EXTCODEHASH of a deployed contract.
    function _checkPermittedCall(uint256 authorityId, address target, uint256 value, bytes memory data)
        internal
        view
    {
        bytes4 selector = bytes4(data);
        if (target == address(this) || data.length < 4) revert CallNotPermitted(target, selector);
        Permission storage p = _permissions[authorityId];
        if (value > p.valueCap) revert CallNotPermitted(target, selector);
        uint256 n = p.targets.length;
        for (uint256 i = 0; i < n; i++) {
            if (p.targets[i] == target && p.selectors[i] == selector) return;
        }
        uint256 m = p.codeHashes.length;
        if (m != 0) {
            bytes32 h = target.codehash;
            for (uint256 i = 0; i < m; i++) {
                if (p.codeHashes[i] == h && p.codeSelectors[i] == selector) return;
            }
        }
        revert CallNotPermitted(target, selector);
    }

    /// @dev Selectors that move or approve tokens (ERC-20, ERC-721, ERC-1155,
    ///      ERC-777, ERC-677, Permit2). A scoped authority may never list them,
    ///      whatever the target (decision 0016). The allowlist is the real
    ///      control; this is a floor under it.
    function _isAssetMovingSelector(bytes4 s) internal pure returns (bool) {
        return s == 0xa9059cbb // transfer(address,uint256)
            || s == 0x095ea7b3 // approve(address,uint256)
            || s == 0x23b872dd // transferFrom(address,address,uint256)
            || s == 0x39509351 // increaseAllowance(address,uint256)
            || s == 0xd505accf // permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
            || s == 0xa22cb465 // setApprovalForAll(address,bool)
            || s == 0x42842e0e // safeTransferFrom(address,address,uint256)
            || s == 0xb88d4fde // safeTransferFrom(address,address,uint256,bytes)
            || s == 0xf242432a // safeTransferFrom(address,address,uint256,uint256,bytes)
            || s == 0x2eb2c2d6 // safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)
            || s == 0x9bd9bbc6 // send(address,uint256,bytes)
            || s == 0x62ad1b83 // operatorSend(address,address,uint256,bytes,bytes)
            || s == 0x959b8c3f // authorizeOperator(address)
            || s == 0x4000aea0 // transferAndCall(address,uint256,bytes)
            || s == 0xcae9ca51 // approveAndCall(address,uint256,bytes)
            || s == 0x87517c45 // Permit2 approve(address,address,uint160,uint48)
            || s == 0x36c78516; // Permit2 transferFrom(address,address,uint160,address)
    }
}
