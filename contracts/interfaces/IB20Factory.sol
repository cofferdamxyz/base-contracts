// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title IB20Factory
/// @notice Interface for the B20Factory singleton precompile, introduced in the
///         Beryl hardfork (Sepolia 2026-06-18, mainnet 2026-06-25).
///         B20 tokens are ERC-20 compatible but implemented as Rust precompiles,
///         making them faster and cheaper than standard EVM ERC-20s.
/// @dev    See: https://docs.base.org/base-chain/specs/upgrades/beryl/b20
interface IB20Factory {
    /// @notice B20 token variants.
    /// @dev    ASSET: configurable decimals (6-18), rebase multiplier, announcements.
    ///         STABLECOIN: fixed 6 decimals, self-declared fiat currency code.
    enum Variant {
        ASSET,
        STABLECOIN
    }

    /// @notice Create a new B20 token via the singleton factory.
    /// @param  variant   ASSET or STABLECOIN
    /// @param  salt      Caller-chosen entropy for deterministic address derivation
    /// @param  params    ABI-encoded, variant-specific creation struct
    /// @param  initCalls Optional post-creation calls (bypass role gates during bootstrap)
    /// @return token     The deployed B20 token address
    function createB20(
        Variant variant,
        bytes32 salt,
        bytes calldata params,
        bytes[] calldata initCalls
    ) external returns (address token);

    /// @notice Compute the deterministic address for a B20 token before creation.
    function getB20Address(Variant variant, address deployer, bytes32 salt) external view returns (address);

    /// @notice Check if an address is a deployed B20 token.
    function isB20(address addr) external view returns (bool);

    /// @notice Check if a B20 token has been initialized (created via factory).
    function isB20Initialized(address addr) external view returns (bool);
}

/// @title IB20Token
/// @notice Minimal interface for interacting with deployed B20 tokens.
///         B20 implements full ERC-20 selector parity — this interface adds
///         the B20-specific compliance and memo features on top.
/// @dev    See: https://docs.base.org/base-chain/specs/upgrades/beryl/b20
interface IB20Token {
    // ── ERC-20 surface (selector parity with standard ERC-20) ────────────────
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);

    // ── B20 memo variants ────────────────────────────────────────────────────
    /// @notice Transfer with a bytes32 memo for off-chain reference (e.g. payroll period ID).
    function transferWithMemo(address to, uint256 amount, bytes32 memo) external returns (bool);

    /// @notice transferFrom with a bytes32 memo.
    function transferFromWithMemo(address from, address to, uint256 amount, bytes32 memo) external returns (bool);

    // ── B20 mint / burn ──────────────────────────────────────────────────────
    function mint(address to, uint256 amount) external;
    function mintWithMemo(address to, uint256 amount, bytes32 memo) external;
    function burn(uint256 amount) external;
    function burnWithMemo(uint256 amount, bytes32 memo) external;

    /// @notice Freeze-and-seize: burn from a blocked account. Requires BURN_BLOCKED_ROLE.
    ///         Target must be denied by TRANSFER_SENDER_POLICY.
    function burnBlocked(address account, uint256 amount) external;

    // ── B20 batch mint (Asset variant) ───────────────────────────────────────
    function batchMint(address[] calldata recipients, uint256[] calldata amounts) external;

    // ── B20 pause (granular) ─────────────────────────────────────────────────
    /// @notice Pausable features as a bitmask.
    enum PausableFeature {
        TRANSFER,
        MINT,
        BURN
    }

    function pause(PausableFeature features) external;
    function unpause(PausableFeature features) external;

    // ── B20 policy integration ───────────────────────────────────────────────
    /// @notice Policy scopes for transfer gating.
    enum PolicyScope {
        TRANSFER_SENDER_POLICY,
        TRANSFER_RECEIVER_POLICY,
        TRANSFER_EXECUTOR_POLICY,
        MINT_RECEIVER_POLICY
    }

    function policyId(PolicyScope scope) external view returns (uint64);
    function updatePolicy(PolicyScope scope, uint64 policyId_) external;

    // ── B20 supply cap ───────────────────────────────────────────────────────
    function updateSupplyCap(uint128 newCap) external;

    // ── B20 ERC-2612 permit (built-in) ───────────────────────────────────────
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    // ── B20 stablecoin variant only ──────────────────────────────────────────
    /// @notice Self-declared ISO-style currency code (e.g. "USD"). Stablecoin variant only.
    function currency() external view returns (string memory);

    // ── B20 asset variant only ───────────────────────────────────────────────
    /// @notice WAD-precision rebase multiplier. Asset variant only.
    function multiplier() external view returns (uint256);
    function scaledBalanceOf(address account) external view returns (uint256);
    function updateMultiplier(uint256 newMultiplier) external;
}

/// @title IPolicyRegistry
/// @notice Singleton precompile for managing B20 transfer policies (allowlists/blocklists).
interface IPolicyRegistry {
    enum PolicyType {
        BLOCKLIST,
        ALLOWLIST
    }

    /// @notice Create a new policy with an admin and type.
    function createPolicy(address admin, PolicyType policyType) external returns (uint64 policyId);

    /// @notice Create a policy with initial member set.
    function createPolicyWithAccounts(
        address admin,
        PolicyType policyType,
        address[] calldata accounts
    ) external returns (uint64 policyId);

    /// @notice Update blocklist membership (batched).
    function updateBlocklist(uint64 policyId, bool block, address[] calldata accounts) external;

    /// @notice Update allowlist membership (batched).
    function updateAllowlist(uint64 policyId, bool allow, address[] calldata accounts) external;

    /// @notice Check if an account is authorized under a policy. Never reverts.
    function isAuthorized(uint64 policyId, address account) external view returns (bool);

    /// @notice Check if a policy exists.
    function policyExists(uint64 policyId) external view returns (bool);

    /// @notice Get the current admin of a policy.
    function policyAdmin(uint64 policyId) external view returns (address);

    /// @notice Two-step admin transfer: stage new admin.
    function stageUpdateAdmin(uint64 policyId, address newAdmin) external;

    /// @notice Two-step admin transfer: accept by pending admin.
    function finalizeUpdateAdmin(uint64 policyId) external;

    /// @notice Permanently freeze a policy.
    function renounceAdmin(uint64 policyId) external;
}
