// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAuthorityModule, Tier} from "../interfaces/IAuthorityModule.sol";

/// @title SessionKeyAuthority
/// @notice The Managed-tier bridge: the employer IdP (e.g. Polis SSO) vouches
///         for the worker with a server-held ECDSA key registered on the
///         account. Always `Tier.LowManaged`.
///
/// @dev    On-chain RS256/JWT verification is expensive and brittle, and the
///         employer's bridge ALREADY authenticated the worker through the IdP.
///         So instead of re-verifying the JWT on-chain, this module trusts a
///         per-account **session signer**: the bridge key registered as the
///         account's authority `config`. After the IdP login the bridge signs
///         the account's userOpHash with that key; this module recovers the
///         signer and checks it matches.
///
///         What a Managed authority may call is the account's decision, not
///         this module's: a `Permission` of allowlisted company calls, scoped
///         like Partner (decision 0016). It coexists with a later High passkey
///         (OR semantics, IDENTITY_LAYER_DESIGN.md §3.10). Revocation is SCIM
///         on the IdP side plus `revokeAuthority` by High on-chain.
///
///         A consumer app's server key is never an account authority (decision
///         0016): the former `Tier.LowUntrusted` deployment of this module is
///         retired, and the account rejects that tier.
///
///         This contract is pure Solidity (no imports beyond the interface).
contract SessionKeyAuthority is IAuthorityModule {
    /// @dev secp256k1 group order / 2; signatures with s above this are rejected
    ///      to prevent signature malleability (EIP-2).
    uint256 private constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    bytes32 public constant KIND_POLIS_SSO = keccak256("polis_sso");

    /// @inheritdoc IAuthorityModule
    function tier() external pure returns (Tier) {
        return Tier.LowManaged;
    }

    /// @inheritdoc IAuthorityModule
    function kind() external pure returns (bytes32) {
        return KIND_POLIS_SSO;
    }

    /// @inheritdoc IAuthorityModule
    /// @param account   Bound into the signed message for domain separation, so
    ///                  a session-signer signature for one account can never be
    ///                  replayed against another account sharing the same signer.
    /// @param config    abi.encode(address sessionSigner) — the server key.
    /// @param signature 65-byte ECDSA signature (r,s,v) over the EIP-191
    ///                  personal_sign of keccak256(account, digest).
    function isValidSignature(
        address account,
        bytes32 digest,
        bytes calldata config,
        bytes calldata signature
    ) external pure returns (bool) {
        if (config.length != 32) return false;
        if (signature.length != 65) return false;
        address sessionSigner = abi.decode(config, (address));
        if (sessionSigner == address(0)) return false;

        // Bind to the account for domain separation, then EIP-191 personal_sign.
        bytes32 bound = keccak256(abi.encode(account, digest));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", bound));

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        // EIP-2 malleability guard + valid recovery id.
        if (uint256(s) > HALF_N) return false;
        if (v != 27 && v != 28) return false;

        address recovered = ecrecover(ethHash, v, r, s);
        return recovered != address(0) && recovered == sessionSigner;
    }
}
