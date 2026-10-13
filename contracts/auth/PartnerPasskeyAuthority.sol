// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";
import {IAuthorityModule, Tier} from "../interfaces/IAuthorityModule.sol";

/// @title PartnerPasskeyAuthority
/// @notice Partner-tier authority (decision 0016): the user's own passkey on a
///         partner app's RP (OffshoreSync included), created inside the partner
///         app with no Cofferdam install. It lets an account start inside the
///         partner app and sign that partner's job-pipeline calls.
///
/// @dev    The account, not this module, decides what a Partner authority may
///         do: allowlisted `(target, selector)` calls with zero value, never
///         the account itself, never token transfers or approvals, no
///         authority changes and no ERC-1271 (see the account's
///         `Permission`). This module answers only "did this partner passkey
///         sign this digest?".
///
///         CONFIG. `abi.encode(bytes32 qx, bytes32 qy, bytes32 rpIdHash,
///         bytes32 partnerId, address partnerSigner)`:
///           - `qx, qy`       the passkey's P-256 public key;
///           - `rpIdHash`     `sha256(partner RP ID)`, checked against every
///                            assertion's `authenticatorData`;
///           - `partnerId`    the partner's id in Cofferdam's partner
///                            registry, bound into ceremony attestations;
///           - `partnerSigner` the partner backend's ECDSA key that signs a
///                            recovery (`CofferdamAccount4337.
///                            replacePartnerAuthority`). Kept per account so
///                            the account can check it during validation
///                            without reading another contract's storage.
///
///         SIGNATURE. `abi.encode(WebAuthn.WebAuthnAuth)`, challenge = the raw
///         32 bytes of `digest`, UP and UV required (as for High).
contract PartnerPasskeyAuthority is IAuthorityModule {
    bytes32 public constant KIND = keccak256("partner_passkey");

    /// @notice Byte length of a valid config (five 32-byte words).
    uint256 public constant CONFIG_LENGTH = 160;

    /// @inheritdoc IAuthorityModule
    function tier() external pure returns (Tier) {
        return Tier.Partner;
    }

    /// @inheritdoc IAuthorityModule
    function kind() external pure returns (bytes32) {
        return KIND;
    }

    /// @inheritdoc IAuthorityModule
    function isValidSignature(
        address, /* account */
        bytes32 digest,
        bytes calldata config,
        bytes calldata signature
    ) external view returns (bool) {
        if (config.length != CONFIG_LENGTH) return false;
        (bytes32 qx, bytes32 qy, bytes32 rpIdHash) = abi.decode(config[:96], (bytes32, bytes32, bytes32));

        (bool ok, WebAuthn.WebAuthnAuth calldata auth) = WebAuthn.tryDecodeAuth(signature);
        if (!ok) return false;
        if (auth.authenticatorData.length < 37) return false;
        if (bytes32(auth.authenticatorData[0:32]) != rpIdHash) return false;

        return WebAuthn.verify(abi.encodePacked(digest), auth, qx, qy, true);
    }

    /// @notice Decode a Partner config.
    function decodeConfig(bytes calldata config)
        external
        pure
        returns (bytes32 qx, bytes32 qy, bytes32 rpIdHash, bytes32 partnerId, address partnerSigner)
    {
        return abi.decode(config, (bytes32, bytes32, bytes32, bytes32, address));
    }
}
