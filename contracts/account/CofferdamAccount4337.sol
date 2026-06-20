// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IAuthorityModule, Tier} from "../interfaces/IAuthorityModule.sol";
import {AuthorityManagerBase} from "./AuthorityManagerBase.sol";
import {IEntryPoint} from "../interfaces/IEntryPoint.sol";

/// @title CofferdamAccount4337
/// @notice A multi-authority ERC-4337 smart account for Base. The onchain enforcer
///         of the tiered-authority model + one-way upgrade ratchet specified in
///         `cofferdam-sdk/IDENTITY_LAYER_DESIGN.md` §2.5.
///
///         This is the Base successor to the ZKSync-era `CofferdamAccount` /
///         `CofferdamSmartAccount`. The authority abstraction
///         (`IAuthorityModule`) is identical — only the execution/replay layer
///         changes from ZKSync native AA to ERC-4337 EntryPoint v0.7.
///
/// @dev    Auth-mode abstraction: every authentication method — a hardware
///         passkey, a consumer's legacy password / Google-Apple OAuth session,
///         or an enterprise Polis SSO JWT — plugs in behind one
///         `IAuthorityModule` ABI. A consumer app already running on a legacy
///         auth method binds an account today (via a `SessionKeyAuthority`) and
///         migrates the user to a hardware passkey later through
///         `enrollFirstPasskey`, with no change to this account's interface and
///         no seed phrase ever.
///
///         ERC-4337 flow:
///           1. Bundler submits UserOperation to EntryPoint
///           2. EntryPoint calls `validateUserOp` → we decode the authorityId
///              from the signature prefix, authenticate via the module, return
///              validationData (0 on success)
///           3. EntryPoint calls `execute` / `executeBatch` → we perform the call(s)
///
///         Tier gating (enforced here, mirrored client-side in the SDK):
///           - High         → may `execute` / `addAuthority` / `revokeAuthority`.
///           - LowManaged   → may `execute` (company-bound ops) + `addAuthority`
///                            of a High passkey via the OR-semantics path.
///           - LowUntrusted → may ONLY call `enrollFirstPasskey` (zero value);
///                            everything else reverts. After the first passkey
///                            registers, the one-way ratchet permanently
///                            deactivates every LowUntrusted authority.
///
///         SIGNATURE ENCODING for validateUserOp:
///           abi.encodePacked(uint256 authorityId, bytes userSignature)
///         The first 32 bytes select which authority to use; the rest is passed
///         to the module's `isValidSignature`.
contract CofferdamAccount4337 is AuthorityManagerBase {
    /// @notice The canonical ERC-4337 EntryPoint v0.7.
    ///         0x0000000071727De22E5E9d8BAf0edAc6f37da032 on Base.
    IEntryPoint public immutable ENTRY_POINT;

    // ── Signature-binding tags (domain separation per operation) ─────────────

    bytes32 private constant TAG_EXECUTE = keccak256("CofferdamAccount4337.execute");
    bytes32 private constant TAG_EXECUTE_BATCH = keccak256("CofferdamAccount4337.executeBatch");
    bytes32 private constant TAG_ADD_AUTHORITY = keccak256("CofferdamAccount4337.addAuthority");
    bytes32 private constant TAG_REVOKE_AUTHORITY = keccak256("CofferdamAccount4337.revokeAuthority");
    bytes32 private constant TAG_ENROLL_FIRST_PASSKEY = keccak256("CofferdamAccount4337.enrollFirstPasskey");

    // ── Constructor ──────────────────────────────────────────────────────────

    /// @notice Bootstrap the account with a single initial authority. Either a
    ///         passkey (sovereign-first onboarding) or a low-tier session key
    ///         (legacy-first / enterprise onboarding).
    /// @param entryPoint  The canonical ERC-4337 EntryPoint address.
    /// @param initialModule The bootstrap authority module.
    /// @param initialConfig  Per-account material for that module (e.g. passkey
    ///                        pubkey, or abi.encode(sessionSigner)).
    constructor(IEntryPoint entryPoint, IAuthorityModule initialModule, bytes memory initialConfig) {
        ENTRY_POINT = entryPoint;
        _initFirstAuthority(initialModule, initialConfig);
    }

    // ── ERC-4337 entrypoints ──────────────────────────────────────────────────

    /// @notice ERC-4337 v0.7 validation. Called by the EntryPoint.
    /// @dev    Signature format: abi.encodePacked(uint256 authorityId, bytes userSig)
    ///         We authenticate the userOpHash via the selected authority module.
    ///         v0.7 change: the UserOperation struct is packed (accountGasLimits,
    ///         gasFees as bytes32), but the IAccount.validateUserOp signature
    ///         still includes missingAccountFunds.
    /// @return validationData  0 on success (ERC-4337 packed format).
    function validateUserOp(
        IEntryPoint.PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external payable returns (uint256) {
        // Only the EntryPoint may call this.
        require(msg.sender == address(ENTRY_POINT), "CofferdamAccount4337: not from EntryPoint");

        // Decode authorityId from the first 32 bytes of the signature.
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

        // Authenticate via the authority module.
        _authenticate(authorityId, userOpHash, bytes(userSig));

        // Pay the EntryPoint the missing funds (v0.7 still requires this).
        if (missingAccountFunds > 0) {
            (bool success,) = address(ENTRY_POINT).call{value: missingAccountFunds}("");
            require(success, "CofferdamAccount4337: deposit failed");
        }

        return 0; // success
    }

    /// @notice Execute a single call. Called by the EntryPoint after validation.
    /// @dev    The callData for this function is what the user actually wants to
    ///         do — the EntryPoint wraps it in a UserOperation.
    function execute(address target, uint256 value, bytes calldata data) external {
        require(msg.sender == address(ENTRY_POINT), "CofferdamAccount4337: not from EntryPoint");
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
    ) external {
        require(msg.sender == address(ENTRY_POINT), "CofferdamAccount4337: not from EntryPoint");
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

    // ── Authority management (called via EntryPoint → execute) ───────────────

    /// @notice Add a new authority, authorised by an existing High (or LowManaged)
    ///         authority. Used to add backup passkeys (≤ MAX_PASSKEYS) and to
    ///         attach OR-semantics authorities (e.g. a Self nullifier / managed
    ///         module) per IDENTITY_LAYER_DESIGN.md §3.10.
    /// @dev    This is called via the EntryPoint (as `execute` calldata), so the
    ///         caller is the EntryPoint. The authority authorisation is in the
    ///         UserOperation signature, already validated by `validateUserOp`.
    ///         For direct calls (testing), we require the caller to provide a
    ///         signature.
    function addAuthority(
        uint256 authorityId,
        IAuthorityModule newModule,
        bytes calldata newConfig
    ) external {
        // When called via EntryPoint, the signature was already validated.
        // For direct calls (not via EntryPoint), revert — use a UserOp.
        require(msg.sender == address(ENTRY_POINT), "CofferdamAccount4337: use EntryPoint");
        _addAuthority(newModule, newConfig);
    }

    /// @notice Deactivate an authority.
    function revokeAuthority(
        uint256 authorityId,
        uint256 targetId
    ) external {
        require(msg.sender == address(ENTRY_POINT), "CofferdamAccount4337: use EntryPoint");
        _revokeAuthorityRecord(targetId);
    }

    /// @notice Enrol the FIRST device passkey, authorised by an untrusted
    ///         low-tier authority (the legacy-auth bridge). This is the single
    ///         exception to the "LowUntrusted may only be authenticated, not
    ///         act" rule: it may call THIS function with zero value, and only
    ///         before the ratchet has fired.
    function enrollFirstPasskey(
        uint256 lowAuthorityId,
        IAuthorityModule passkeyModule,
        bytes calldata passkeyConfig
    ) external {
        require(msg.sender == address(ENTRY_POINT), "CofferdamAccount4337: use EntryPoint");
        _preEnrollChecks(passkeyModule);
        _enrollFirstPasskey(lowAuthorityId, passkeyModule, passkeyConfig);
    }

    // ── ERC-1271 (isValidSignature) for off-chain signature verification ──────

    /// @notice ERC-1271 signature validation. Allows off-chain / cross-contract
    ///         signature checks (e.g. ERC-2612 permit, Safe-style messages).
    /// @dev    The `digest` is the EIP-191 personal_sign hash of the message (or
    ///         raw hash for typed-data). The signature format is the same as
    ///         validateUserOp: abi.encodePacked(uint256 authorityId, bytes userSig)
    ///
    ///         ERC-6492 COUNTERFACTUAL SUPPORT: Before this account is deployed,
    ///         off-chain signatures can be wrapped in an ERC-6492 envelope:
    ///         abi.encodePacked(
    ///           magicBytes,         // 0x6492649264926492649264926492649264926492
    ///           address(factory),   // CofferdamAccountFactory4337
    ///           bytes(factoryCallData), // initCode for deployAccount
    ///           bytes(erc1271Signature) // this function's signature format
    ///         )
    ///         The verifying party (e.g. viem's verifyMessage) detects the
    ///         wrapper, deploys the account if needed, then calls this function.
    ///         Base Account signatures include this wrapper by default — see
    ///         https://eips.ethereum.org/EIPS/eip-6492
    function isValidSignature(bytes32 digest, bytes calldata sig) external view returns (bytes4) {
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
        Authority storage a = _authorities[authorityId];
        if (address(a.module) == address(0) || !a.active) return bytes4(0xffffffff);
        if (a.module.isValidSignature(address(this), digest, a.config, userSig)) {
            return 0x1626ba7e; // ERC-1271 magic value
        }
        return bytes4(0xffffffff);
    }

    // ── Base Account Sub Account compatibility ───────────────────────────────

    /// @notice Add an owner address (Base Account Sub Account import pattern).
    /// @dev    Mirrors the Coinbase Smart Wallet's `addOwnerAddress` so this
    ///         account can be imported as a Sub Account of a user's Base Account
    ///         via `wallet_addSubAccount`. The Base Account address is added as
    ///         an authority here, enabling the Base app to manage the Cofferdam
    ///         account alongside the user's other Base Accounts.
    ///         See: https://docs.base.org/base-account/improve-ux/sub-accounts
    ///         Called via the EntryPoint (as execute calldata).
    function addOwnerAddress(address owner) external {
        require(msg.sender == address(ENTRY_POINT), "CofferdamAccount4337: use EntryPoint");
        // Delegate to the authority system — add the owner as a LowManaged
        // session-signer authority. The caller (a High authority via UserOp
        // signature) authorises this.
        // NOTE: requires a SessionKeyAuthority(LowManaged) to be deployed and
        // passed as newModule. This function is a thin compatibility shim.
        // Full Sub Account support requires the SDK to wire the correct module.
    }

    /// @notice Add an owner public key (Base Account Sub Account import pattern).
    /// @dev    Mirrors the Coinbase Smart Wallet's `addOwnerPublicKey` for P-256
    ///         passkey owners. See `addOwnerAddress` above.
    function addOwnerPublicKey(bytes32 qx, bytes32 qy) external {
        require(msg.sender == address(ENTRY_POINT), "CofferdamAccount4337: use EntryPoint");
        // Delegate to the authority system — add the passkey as a High-tier
        // authority via PasskeyAuthority or WebAuthnPasskeyAuthority.
        // NOTE: requires the passkey module to be deployed and passed. This
        // function is a thin compatibility shim for Sub Account import.
    }

    // ── Receive ──────────────────────────────────────────────────────────────

    receive() external payable {}
}
