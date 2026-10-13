// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title Authority tiers
/// @notice On-chain mirror of the off-chain tiered-authority model in
///         `cofferdam-sdk/packages/core/src/types.ts` (`AuthorityTier`) and the
///         spec in `cofferdam-sdk/IDENTITY_LAYER_DESIGN.md` §2.5.
///
///         The tier of the authority that signs a transaction decides what that
///         transaction may do (enforced by `CofferdamAccount4337`, decisions
///         0015 and 0016 in the `cofferdam` repository):
///
///           LowUntrusted  — RETIRED (decision 0016). A consumer-server key is
///                           never an account authority; the account rejects
///                           any module that reports this tier. The value is
///                           kept so the enum numbering does not move.
///           LowManaged    — the employer IdP bridge (e.g. Polis SSO), a
///                           server-held key. Scoped by a `Permission` like
///                           Partner; coexists with High (OR semantics).
///           High          — a `cofferdam.xyz` passkey (P-256, Secure Enclave /
///                           StrongBox, UV), created and used only on Cofferdam
///                           surfaces. May sign anything.
///           Partner       — the user's own passkey on a partner app's RP.
///                           Scoped by a `Permission`: allowlisted job calls,
///                           zero value, no authority changes, no ERC-1271.
enum Tier {
    None,
    LowUntrusted,
    LowManaged,
    High,
    Partner
}

/// @notice What a Partner or Managed authority may call, fixed when the
///         authority is granted and stored on the account (decision 0016:
///         the grant the user approved is what the chain enforces; no
///         Cofferdam key can widen it).
/// @param targets   `targets[i]` may be called with selector `selectors[i]`.
/// @param selectors Parallel to `targets`.
/// @param valueCap  Maximum ETH value per call. Always 0 for Partner and for
///                  any grant made without a High signer.
/// @param expiry    Unix time after which the authority's userOps are invalid
///                  (returned as `validUntil`). 0 = no expiry, allowed for
///                  Managed only.
struct Permission {
    address[] targets;
    bytes4[] selectors;
    uint256 valueCap;
    uint48 expiry;
}

/// @title IAuthorityModule
/// @notice The single, uniform ABI every authentication mode plugs into so that
///         any consumer app on a legacy auth method (local password, Google /
///         Apple OAuth, Polis SSO JWT, …) can bootstrap a Base smart account and
///         migrate to a hardware passkey through one common path.
///
/// @dev    Modules are **stateless singletons**. All per-account key material
///         lives in the `CofferdamAccount4337` as an opaque `config` blob, which
///         the account passes back to the module on every validation. This keeps a
///         module deployable once and shared by every account, and keeps the
///         account self-contained (one storage read, no cross-contract key
///         lookup). A module encapsulates exactly one decision: "given this
///         account's stored config, is `signature` a valid authorisation of
///         `digest`?" — be it a P-256 WebAuthn assertion, an ECDSA session-signer
///         signature standing in for a verified JWT, or a future post-quantum
///         Dilithium signature. The account never learns how; it only sees a bool.
///
///         This interface is chain-agnostic by design.
interface IAuthorityModule {
    /// @notice The trust tier this module's authorities carry on an account.
    /// @dev    A module's tier is fixed at deploy time. MUST NOT read storage:
    ///         the account records the tier when an authority is added and
    ///         enforces it on every userOp, so a tier that could change later
    ///         would let a module be granted as one tier and behave as
    ///         another. Return a constant or an immutable.
    function tier() external view returns (Tier);

    /// @notice Stable identifier of the authority kind, e.g.
    ///         `keccak256("passkey")`, `keccak256("session")`. Mirrors the SDK's
    ///         `AuthorityKind`. Used for off-chain indexing + UI labelling.
    function kind() external pure returns (bytes32);

    /// @notice Validate `signature` over `digest` against this account's stored
    ///         `config` for this authority.
    /// @param  account   The `CofferdamAccount4337` whose authority is being checked.
    ///                    Passed so a module MAY bind validation to the account
    ///                    (e.g. domain separation) if it chooses.
    /// @param  digest    32-byte message the signature must cover.
    /// @param  config    Opaque per-account authority material the account stored
    ///                    at `addAuthority` time (e.g. abi.encode(qx,qy) for a
    ///                    passkey, abi.encode(signer) for a session key).
    /// @param  signature Authorisation produced by the off-chain authority.
    /// @return ok        True iff the signature is a valid authorisation.
    function isValidSignature(
        address account,
        bytes32 digest,
        bytes calldata config,
        bytes calldata signature
    ) external view returns (bool ok);
}
