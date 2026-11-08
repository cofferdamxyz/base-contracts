// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IIdentityEvidenceAdapter} from "./IIdentityEvidenceAdapter.sol";

/// @title CofferdamIdentityRegistry
/// @notice Binding from a person's identifier to one Cofferdam account,
///         provider-agnostic (decision 0080, the successor of Self's
///         `NullifierRegistry`). One identifier per account and one account per
///         identifier: Cofferdam's sybil resistance.
///         - The account itself calls (`msg.sender` is the account), so its
///           consent is on-chain.
///         - Every proof is bound to an action digest over a tag per action,
///           the chain id, this registry, the account and the account's nonce
///           here; the nonce is consumed on success, so a proof is single-use.
///         - `bind` is the first binding. `relink` moves an account to a new
///           identifier (a renewed passport) and retires the old identifier
///           for good. `requestRebind` moves an identifier to a new account
///           (decision 0022) after `REBIND_DELAY`, which the bound account may
///           veto with `cancelRebind`.
///         - Evidence is checked by an adapter from an allowlist; the owner
///           adds an adapter only after `ADAPTER_DELAY`, so the proof check can
///           change without a new account generation and never without notice.
///         - A pause and a test allowlist of accounts.
/// @dev    The owner is the Cofferdam Inc. Safe on the production generation
///         and the founder's Ledger on the throwaway test generation (decision
///         0080, T3), with a two-step transfer. On Base mainnet (chain 8453)
///         both delays are at least 72 hours; the check is on the chain id, so
///         a fork of mainnet enforces it too.
///         Today's accounts call `provenNullifier`, which this registry does not
///         have: an account generation pinned to it binds and rebinds, but its
///         `recoverHigh` reverts until the generation that takes
///         `bytes evidence` (decision 0080, 7).
contract CofferdamIdentityRegistry {
    // ── Constants ────────────────────────────────────────────────────────────

    uint256 public constant BASE_MAINNET_CHAIN_ID = 8453;
    /// @notice The least `REBIND_DELAY` and `ADAPTER_DELAY` on Base mainnet.
    uint256 public constant MIN_MAINNET_DELAY = 72 hours;
    /// @notice Bound on both delays, so a typo cannot freeze rebinds or
    ///         adapter changes for years.
    uint256 public constant MAX_DELAY = 30 days;

    /// @notice Action tags folded into the digest a proof must carry, one per
    ///         action, so a proof made for one action never serves another.
    ///         `keccak256("cofferdam-identity-recover-v1")` is reserved for the
    ///         account generation whose hard recovery takes `bytes evidence`.
    bytes32 public constant BIND = keccak256("cofferdam-identity-bind-v1");
    bytes32 public constant REBIND = keccak256("cofferdam-identity-rebind-v1");
    bytes32 public constant RELINK = keccak256("cofferdam-identity-relink-v1");

    // ── Immutables ───────────────────────────────────────────────────────────

    /// @notice The one identifier derivation this registry accepts
    ///         (`IIdentityEvidenceAdapter.identifierKind`).
    bytes32 public immutable IDENTIFIER_KIND;
    /// @notice The one scope this registry accepts (`IIdentityEvidenceAdapter.scopeId`).
    bytes32 public immutable SCOPE_ID;
    /// @notice Seconds a rebind waits before `finalizeRebind`; 0 applies it in
    ///         the request.
    uint256 public immutable REBIND_DELAY;
    /// @notice Seconds between `proposeAdapter` and `activateAdapter`.
    uint256 public immutable ADAPTER_DELAY;

    // ── Admin state ──────────────────────────────────────────────────────────

    address public owner;
    address public pendingOwner;
    /// @notice While set, nothing binds, relinks or rebinds; `cancelRebind`
    ///         stays open so a bound account can always veto.
    bool public paused;
    /// @notice While set, only `isTestAccount` accounts bind, relink or rebind.
    bool public allowlistOnly;
    mapping(address => bool) public isTestAccount;

    /// @notice Adapters whose evidence the registry accepts now.
    mapping(address => bool) public isAdapter;
    /// @notice When a proposed adapter may be activated; 0 when none is pending.
    mapping(address => uint256) public adapterReadyAt;

    // ── Bindings ─────────────────────────────────────────────────────────────

    mapping(bytes32 => address) public identifierToAccount;
    mapping(address => bytes32) public accountToIdentifier;
    /// @notice Identifiers left behind by `relink`; never bound again.
    mapping(bytes32 => bool) public isRetired;
    /// @notice The nonce the account's next proof must be bound to.
    mapping(address => uint256) public nonces;

    struct PendingRebind {
        address oldAccount;
        address newAccount;
        uint48 readyAt;
    }

    /// @notice The rebind of an identifier waiting for `REBIND_DELAY`, if any.
    mapping(bytes32 => PendingRebind) public pendingRebind;

    // ── Events ───────────────────────────────────────────────────────────────

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event PausedSet(bool paused);
    event AllowlistOnlySet(bool allowlistOnly);
    event TestAccountSet(address indexed account, bool allowed);
    event AdapterProposed(address indexed adapter, uint256 readyAt);
    event AdapterProposalCancelled(address indexed adapter);
    event AdapterActivated(address indexed adapter);
    event AdapterRemoved(address indexed adapter);

    event Bound(address indexed account, bytes32 indexed identifier, address indexed adapter, uint256 nonce);
    event Relinked(
        address indexed account, bytes32 indexed oldIdentifier, bytes32 indexed newIdentifier, address adapter, uint256 nonce
    );
    event IdentifierRetired(bytes32 indexed identifier);
    event RebindRequested(
        address indexed oldAccount, address indexed newAccount, bytes32 indexed identifier, uint256 nonce, uint48 readyAt
    );
    event Rebound(address indexed oldAccount, address indexed newAccount, bytes32 indexed identifier);
    event RebindCancelled(address indexed account, bytes32 indexed identifier, address newAccount);

    // ── Errors ───────────────────────────────────────────────────────────────

    error NotOwner();
    error NotPendingOwner();
    error ZeroAddress();
    error ZeroValue();
    error DelayTooShort(uint256 delay, uint256 minimum);
    error DelayTooLong(uint256 delay, uint256 maximum);
    error Paused();
    error NotTestAccount(address account);
    error UnknownAction(bytes32 action);
    error AdapterNotActive(address adapter);
    error AdapterAlreadyActive(address adapter);
    error AdapterNotProposed(address adapter);
    error AdapterNotReady(uint256 readyAt);
    error WrongIdentifierKind(bytes32 expected, bytes32 got);
    error WrongScope(bytes32 expected, bytes32 got);
    error ZeroIdentifier();
    error RetiredIdentifier(bytes32 identifier);
    error AccountAlreadyBound(address account, bytes32 identifier);
    error IdentifierAlreadyBound(bytes32 identifier, address account);
    error AccountNotBound(address account);
    error IdentifierNotBound(bytes32 identifier);
    error SameIdentifier(bytes32 identifier);
    error SameAccount(address account);
    error NoPendingRebind(bytes32 identifier);
    error RebindNotReady(uint48 readyAt);
    error RebindStale(bytes32 identifier);
    error NotBoundAccount(address caller, address bound);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @param _owner The Safe (production) or the founder's Ledger (test generation).
    /// @param identifierKind The one identifier derivation accepted, never 0.
    /// @param scopeId The one scope accepted, never 0.
    /// @param rebindDelay Decision 0022's delay; at least 72 hours on Base mainnet.
    /// @param adapterDelay The adapter allowlist's timelock; at least 72 hours on Base mainnet.
    /// @param initialAdapters Active from deployment, visible in the constructor arguments.
    /// @param _allowlistOnly Start with the test allowlist on.
    /// @param testAccounts Accounts on the test allowlist from deployment.
    constructor(
        address _owner,
        bytes32 identifierKind,
        bytes32 scopeId,
        uint256 rebindDelay,
        uint256 adapterDelay,
        address[] memory initialAdapters,
        bool _allowlistOnly,
        address[] memory testAccounts
    ) {
        if (_owner == address(0)) revert ZeroAddress();
        if (identifierKind == bytes32(0) || scopeId == bytes32(0)) revert ZeroValue();
        _checkDelay(rebindDelay);
        _checkDelay(adapterDelay);
        IDENTIFIER_KIND = identifierKind;
        SCOPE_ID = scopeId;
        REBIND_DELAY = rebindDelay;
        ADAPTER_DELAY = adapterDelay;
        owner = _owner;
        emit OwnershipTransferred(address(0), _owner);
        for (uint256 i = 0; i < initialAdapters.length; i++) {
            _checkAdapterShape(initialAdapters[i]);
            if (isAdapter[initialAdapters[i]]) revert AdapterAlreadyActive(initialAdapters[i]);
            isAdapter[initialAdapters[i]] = true;
            emit AdapterActivated(initialAdapters[i]);
        }
        allowlistOnly = _allowlistOnly;
        emit AllowlistOnlySet(_allowlistOnly);
        for (uint256 i = 0; i < testAccounts.length; i++) {
            if (testAccounts[i] == address(0)) revert ZeroAddress();
            isTestAccount[testAccounts[i]] = true;
            emit TestAccountSet(testAccounts[i], true);
        }
    }

    // ── Account actions (msg.sender is the account) ──────────────────────────

    /// @notice First binding of the calling account to the identifier the
    ///         evidence proves. The proof must be bound to
    ///         `digest(BIND, msg.sender)`.
    function bind(address adapter, bytes calldata evidence) external {
        address account = msg.sender;
        (bytes32 identifier,) = _check(BIND, account, adapter, evidence);
        uint256 nonce = nonces[account]++;
        identifierToAccount[identifier] = account;
        accountToIdentifier[account] = identifier;
        emit Bound(account, identifier, adapter, nonce);
    }

    /// @notice Move the calling account's binding to a new identifier (a
    ///         renewed document) and retire the old identifier for good, so the
    ///         old document can never open a second account. The proof must be
    ///         bound to `digest(RELINK, msg.sender)`. A pending rebind of the
    ///         old identifier is dropped with it.
    function relink(address adapter, bytes calldata evidence) external {
        address account = msg.sender;
        (bytes32 newIdentifier,) = _check(RELINK, account, adapter, evidence);
        bytes32 oldIdentifier = accountToIdentifier[account];
        uint256 nonce = nonces[account]++;
        isRetired[oldIdentifier] = true;
        delete identifierToAccount[oldIdentifier];
        delete pendingRebind[oldIdentifier];
        identifierToAccount[newIdentifier] = account;
        accountToIdentifier[account] = newIdentifier;
        emit IdentifierRetired(oldIdentifier);
        emit Relinked(account, oldIdentifier, newIdentifier, adapter, nonce);
    }

    /// @notice Move a bound identifier to the calling, unbound account (decision
    ///         0022: a lost device, or an account on retired contracts). The
    ///         proof must be bound to `digest(REBIND, msg.sender)`. With
    ///         `REBIND_DELAY` zero the move applies at once; otherwise it waits
    ///         for `finalizeRebind`, and the bound account may `cancelRebind`
    ///         meanwhile. A later request replaces a pending one.
    function requestRebind(address adapter, bytes calldata evidence) external {
        address newAccount = msg.sender;
        (bytes32 identifier, address oldAccount) = _check(REBIND, newAccount, adapter, evidence);
        uint256 nonce = nonces[newAccount]++;
        if (REBIND_DELAY == 0) {
            delete pendingRebind[identifier];
            emit RebindRequested(oldAccount, newAccount, identifier, nonce, uint48(block.timestamp));
            _move(identifier, oldAccount, newAccount);
            return;
        }
        uint48 readyAt = uint48(block.timestamp + REBIND_DELAY);
        pendingRebind[identifier] = PendingRebind({oldAccount: oldAccount, newAccount: newAccount, readyAt: readyAt});
        emit RebindRequested(oldAccount, newAccount, identifier, nonce, readyAt);
    }

    /// @notice Apply a pending rebind once `REBIND_DELAY` has passed. Anyone may
    ///         call it; the authorisation happened in `requestRebind`. Fails if
    ///         the identifier or either account changed meanwhile.
    function finalizeRebind(bytes32 identifier) external {
        if (paused) revert Paused();
        PendingRebind memory p = pendingRebind[identifier];
        if (p.newAccount == address(0)) revert NoPendingRebind(identifier);
        if (block.timestamp < p.readyAt) revert RebindNotReady(p.readyAt);
        if (identifierToAccount[identifier] != p.oldAccount) revert RebindStale(identifier);
        bytes32 existing = accountToIdentifier[p.newAccount];
        if (existing != bytes32(0)) revert AccountAlreadyBound(p.newAccount, existing);
        delete pendingRebind[identifier];
        _move(identifier, p.oldAccount, p.newAccount);
    }

    /// @notice The bound account vetoes a pending rebind of its identifier
    ///         (an `execute` self-call signed by its High authority). Open while
    ///         paused.
    function cancelRebind(bytes32 identifier) external {
        address bound = identifierToAccount[identifier];
        if (msg.sender != bound) revert NotBoundAccount(msg.sender, bound);
        PendingRebind memory p = pendingRebind[identifier];
        if (p.newAccount == address(0)) revert NoPendingRebind(identifier);
        delete pendingRebind[identifier];
        emit RebindCancelled(bound, identifier, p.newAccount);
    }

    // ── Views ────────────────────────────────────────────────────────────────

    function isAccountBound(address account) external view returns (bool) {
        return accountToIdentifier[account] != bytes32(0);
    }

    function isIdentifierBound(bytes32 identifier) external view returns (bool) {
        return identifierToAccount[identifier] != address(0);
    }

    /// @notice The digest the next proof of `account` for `action` must be
    ///         bound to: `keccak256(abi.encode(action, block.chainid,
    ///         address(this), account, nonces[account]))`, where `action` is
    ///         `BIND`, `REBIND` or `RELINK` (each the keccak256 of its tag).
    function digest(bytes32 action, address account) public view returns (bytes32) {
        return keccak256(abi.encode(action, block.chainid, address(this), account, nonces[account]));
    }

    /// @notice Pre-flight for `eth_call`: run every check `bind`, `relink` or
    ///         `requestRebind` would run for `account` (the account that will
    ///         call) and return the identifier, or revert with the same error
    ///         the transaction would. `counterpart` is the account the
    ///         identifier is bound to now (REBIND) or `account` (RELINK).
    function check(bytes32 action, address account, address adapter, bytes calldata evidence)
        external
        view
        returns (bytes32 identifier, address counterpart)
    {
        return _check(action, account, adapter, evidence);
    }

    // ── Owner ────────────────────────────────────────────────────────────────

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        address previous = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(previous, owner);
    }

    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit PausedSet(_paused);
    }

    function setAllowlistOnly(bool _allowlistOnly) external onlyOwner {
        allowlistOnly = _allowlistOnly;
        emit AllowlistOnlySet(_allowlistOnly);
    }

    function setTestAccount(address account, bool allowed) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        isTestAccount[account] = allowed;
        emit TestAccountSet(account, allowed);
    }

    /// @notice Start the timelock for a new adapter. Its kind and scope must be
    ///         this registry's. Re-proposing restarts the clock.
    function proposeAdapter(address adapter) external onlyOwner {
        _checkAdapterShape(adapter);
        if (isAdapter[adapter]) revert AdapterAlreadyActive(adapter);
        uint256 readyAt = block.timestamp + ADAPTER_DELAY;
        adapterReadyAt[adapter] = readyAt;
        emit AdapterProposed(adapter, readyAt);
    }

    function cancelAdapterProposal(address adapter) external onlyOwner {
        if (adapterReadyAt[adapter] == 0) revert AdapterNotProposed(adapter);
        delete adapterReadyAt[adapter];
        emit AdapterProposalCancelled(adapter);
    }

    function activateAdapter(address adapter) external onlyOwner {
        uint256 readyAt = adapterReadyAt[adapter];
        if (readyAt == 0) revert AdapterNotProposed(adapter);
        if (block.timestamp < readyAt) revert AdapterNotReady(readyAt);
        delete adapterReadyAt[adapter];
        isAdapter[adapter] = true;
        emit AdapterActivated(adapter);
    }

    /// @notice Stop accepting an adapter's evidence at once: a removal only
    ///         narrows what binds, so it needs no timelock. Bindings it made stay.
    function removeAdapter(address adapter) external onlyOwner {
        if (!isAdapter[adapter]) revert AdapterNotActive(adapter);
        isAdapter[adapter] = false;
        emit AdapterRemoved(adapter);
    }

    // ── Internals ────────────────────────────────────────────────────────────

    /// @dev Every check of an account action, shared by the actions and the
    ///      `check` view. Returns the proven identifier and, for REBIND, the
    ///      account it is bound to now (for RELINK, `account`).
    function _check(bytes32 action, address account, address adapter, bytes calldata evidence)
        private
        view
        returns (bytes32 identifier, address counterpart)
    {
        if (paused) revert Paused();
        if (account == address(0)) revert ZeroAddress();
        if (allowlistOnly && !isTestAccount[account]) revert NotTestAccount(account);
        if (action != BIND && action != REBIND && action != RELINK) revert UnknownAction(action);
        if (!isAdapter[adapter]) revert AdapterNotActive(adapter);
        _checkAdapterShape(adapter);

        identifier = IIdentityEvidenceAdapter(adapter).verify(account, digest(action, account), evidence);
        if (identifier == bytes32(0)) revert ZeroIdentifier();
        if (isRetired[identifier]) revert RetiredIdentifier(identifier);

        bytes32 accountId = accountToIdentifier[account];
        address holder = identifierToAccount[identifier];
        if (action == BIND) {
            if (accountId != bytes32(0)) revert AccountAlreadyBound(account, accountId);
            if (holder != address(0)) revert IdentifierAlreadyBound(identifier, holder);
        } else if (action == RELINK) {
            if (accountId == bytes32(0)) revert AccountNotBound(account);
            if (accountId == identifier) revert SameIdentifier(identifier);
            if (holder != address(0)) revert IdentifierAlreadyBound(identifier, holder);
            counterpart = account;
        } else {
            if (holder == address(0)) revert IdentifierNotBound(identifier);
            if (holder == account) revert SameAccount(account);
            if (accountId != bytes32(0)) revert AccountAlreadyBound(account, accountId);
            counterpart = holder;
        }
    }

    function _move(bytes32 identifier, address oldAccount, address newAccount) private {
        delete accountToIdentifier[oldAccount];
        identifierToAccount[identifier] = newAccount;
        accountToIdentifier[newAccount] = identifier;
        emit Rebound(oldAccount, newAccount, identifier);
    }

    function _checkAdapterShape(address adapter) private view {
        if (adapter == address(0)) revert ZeroAddress();
        bytes32 kind = IIdentityEvidenceAdapter(adapter).identifierKind();
        if (kind != IDENTIFIER_KIND) revert WrongIdentifierKind(IDENTIFIER_KIND, kind);
        bytes32 scope = IIdentityEvidenceAdapter(adapter).scopeId();
        if (scope != SCOPE_ID) revert WrongScope(SCOPE_ID, scope);
    }

    function _checkDelay(uint256 delay) private view {
        if (delay > MAX_DELAY) revert DelayTooLong(delay, MAX_DELAY);
        if (block.chainid == BASE_MAINNET_CHAIN_ID && delay < MIN_MAINNET_DELAY) {
            revert DelayTooShort(delay, MIN_MAINNET_DELAY);
        }
    }
}
