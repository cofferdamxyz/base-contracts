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
///           identifier (a renewed passport) and retires the old identifier,
///           which never binds or relinks again. `requestRebind` moves an
///           identifier to a new account (decision 0022) after `REBIND_DELAY`,
///           which the bound account may veto with `cancelRebind`.
///         - A retired identifier stays claimable (decision 0080 P4): its
///           holder may `requestRebind` it, and the claim waits for the
///           owner's `ruleRetiredClaim`, never a timer and never a veto: the
///           account that retired it answers with evidence to the owner.
///           Claims are kept per claimant, so none blocks or replaces another.
///           The contract cannot tell a
///           holder whose passport someone else bound and then relinked away
///           from the same person claiming their own old passport for a second
///           account, so a person decides. Relink is refused while a rebind of
///           the account's identifier is pending, so it never escapes a claim.
///         - Evidence is checked by an adapter from an allowlist; the owner
///           adds an adapter only after `ADAPTER_DELAY`, so the proof check can
///           change without a new account generation and never without notice.
///         - A pause and a test allowlist of accounts.
/// @dev    The owner is the Cofferdam Inc. Safe on the production generation;
///         on the throwaway test generation `zkp-test-1` it is a throwaway Safe
///         the CofferdamDev wallet signs for (decision 0080, the M2 dev-key
///         exception to T3), with a two-step transfer. On Base mainnet (chain 8453)
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
    /// @notice How long a proposed adapter stays activatable after its delay;
    ///         an older proposal must be made again, with fresh notice.
    uint256 public constant ADAPTER_GRACE = 7 days;

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
    /// @notice Identifiers left behind by `relink`: never bound or relinked to
    ///         again; claimable only through `requestRebind` and the owner's
    ///         `ruleRetiredClaim`.
    mapping(bytes32 => bool) public isRetired;
    /// @notice The account whose `relink` retired an identifier: the party a
    ///         claim on it is ruled against (`ruleRetiredClaim`).
    mapping(bytes32 => address) public retiredBy;
    /// @notice The nonce the account's next proof must be bound to.
    mapping(address => uint256) public nonces;

    struct PendingRebind {
        address oldAccount;
        address newAccount;
        uint48 readyAt;
        /// @dev The adapter whose evidence authorised it; removing the adapter
        ///      voids the rebinds it authorised.
        address adapter;
    }

    /// @notice The rebind of an identifier waiting for `REBIND_DELAY`, if any.
    mapping(bytes32 => PendingRebind) public pendingRebind;
    /// @notice Claims on a retired identifier, one per claimant
    ///         (`oldAccount` is the account that retired it), each waiting for
    ///         the owner's `ruleRetiredClaim`. None blocks or replaces another.
    mapping(bytes32 => mapping(address => PendingRebind)) public retiredClaims;

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
    event RetiredClaimRuled(
        bytes32 indexed identifier, address indexed retiredBy, address indexed claimant, bool awarded
    );

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
    error AdapterProposalExpired(uint256 expiredAt);
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
    error RebindPending(bytes32 identifier);
    error RetiredNeedsRuling(bytes32 identifier);
    error NotRetired(bytes32 identifier);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @param _owner The Safe (production) or a throwaway Safe (test generation).
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
    ///         renewed document) and retire the old identifier, so the old
    ///         document can never open a second account by `bind`. The proof
    ///         must be bound to `digest(RELINK, msg.sender)`. Refused while a
    ///         rebind of the old identifier is pending: the account answers the
    ///         claim first (`RebindPending`).
    /// @dev    It applies at once on the account's own call, so an honest
    ///         renewal never waits. The retired identifier stays claimable by
    ///         its holder (`requestRebind`, then `ruleRetiredClaim`), so
    ///         someone who bound another person's passport cannot lock that
    ///         person out by relinking away (decision 0080 P4). Decision 0080
    ///         (7) also puts the recovery key's signature on relink; this
    ///         registry has no recovery key yet (0080 build order, step 4).
    function relink(address adapter, bytes calldata evidence) external {
        address account = msg.sender;
        (bytes32 newIdentifier,) = _check(RELINK, account, adapter, evidence);
        bytes32 oldIdentifier = accountToIdentifier[account];
        uint256 nonce = nonces[account]++;
        isRetired[oldIdentifier] = true;
        retiredBy[oldIdentifier] = account;
        delete identifierToAccount[oldIdentifier];
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
    ///         A retired identifier may be claimed the same way: `oldAccount`
    ///         is the account that retired it. The claim never applies at once,
    ///         never by `finalizeRebind` and is never vetoed: only the owner's
    ///         `ruleRetiredClaim` resolves it, an award after `REBIND_DELAY`.
    ///         Each claimant's claim is kept apart (`retiredClaims`), so no
    ///         claim blocks or replaces another's, and nobody restarts a
    ///         holder's clock.
    function requestRebind(address adapter, bytes calldata evidence) external {
        address newAccount = msg.sender;
        (bytes32 identifier, address oldAccount) = _check(REBIND, newAccount, adapter, evidence);
        uint256 nonce = nonces[newAccount]++;
        uint48 readyAt = uint48(block.timestamp + REBIND_DELAY);
        if (isRetired[identifier]) {
            retiredClaims[identifier][newAccount] =
                PendingRebind({oldAccount: oldAccount, newAccount: newAccount, readyAt: readyAt, adapter: adapter});
            emit RebindRequested(oldAccount, newAccount, identifier, nonce, readyAt);
            return;
        }
        if (REBIND_DELAY == 0) {
            delete pendingRebind[identifier];
            emit RebindRequested(oldAccount, newAccount, identifier, nonce, uint48(block.timestamp));
            _move(identifier, oldAccount, newAccount);
            return;
        }
        pendingRebind[identifier] =
            PendingRebind({oldAccount: oldAccount, newAccount: newAccount, readyAt: readyAt, adapter: adapter});
        emit RebindRequested(oldAccount, newAccount, identifier, nonce, readyAt);
    }

    /// @notice Apply a pending rebind once `REBIND_DELAY` has passed. Anyone may
    ///         call it; the authorisation happened in `requestRebind`. Fails if
    ///         the identifier or either account changed meanwhile, if the
    ///         adapter that checked the evidence was removed since, or if the
    ///         new account left the test allowlist while it is on. A claim on a
    ///         retired identifier waits for `ruleRetiredClaim` instead.
    function finalizeRebind(bytes32 identifier) external {
        if (paused) revert Paused();
        if (isRetired[identifier]) revert RetiredNeedsRuling(identifier);
        PendingRebind memory p = pendingRebind[identifier];
        if (p.newAccount == address(0)) revert NoPendingRebind(identifier);
        if (block.timestamp < p.readyAt) revert RebindNotReady(p.readyAt);
        if (!isAdapter[p.adapter]) revert AdapterNotActive(p.adapter);
        if (allowlistOnly && !isTestAccount[p.newAccount]) revert NotTestAccount(p.newAccount);
        if (identifierToAccount[identifier] != p.oldAccount) revert RebindStale(identifier);
        bytes32 existing = accountToIdentifier[p.newAccount];
        if (existing != bytes32(0)) revert AccountAlreadyBound(p.newAccount, existing);
        delete pendingRebind[identifier];
        _move(identifier, p.oldAccount, p.newAccount);
    }

    /// @notice The bound account vetoes a pending rebind of its identifier
    ///         (an `execute` self-call signed by its High authority). Open while
    ///         paused. A claim on a retired identifier has no veto: the owner
    ///         rules on it (`RetiredNeedsRuling`).
    /// @dev    A bare veto here; decision 0080 P4 replaces it in the
    ///         production registry with an answer that carries a fresh proof
    ///         of the same passport.
    function cancelRebind(bytes32 identifier) external {
        if (isRetired[identifier]) revert RetiredNeedsRuling(identifier);
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
    ///         identifier is bound to now, or the account that retired it
    ///         (REBIND), or `account` (RELINK).
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
    /// @dev    The kind names the identifier derivation, not the circuits
    ///         version: an adapter for a new version keeps the kind. The delay
    ///         is the window to confirm that the provider did not change how
    ///         identifiers are derived; if it did, the adapter belongs in a new
    ///         registry, or one person could bind twice.
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
        if (block.timestamp > readyAt + ADAPTER_GRACE) revert AdapterProposalExpired(readyAt + ADAPTER_GRACE);
        delete adapterReadyAt[adapter];
        isAdapter[adapter] = true;
        emit AdapterActivated(adapter);
    }

    /// @notice Stop accepting an adapter's evidence at once: a removal only
    ///         narrows what binds, so it needs no timelock. Bindings it made
    ///         stay; rebinds it authorised that are still pending can no longer
    ///         be finalized.
    function removeAdapter(address adapter) external onlyOwner {
        if (!isAdapter[adapter]) revert AdapterNotActive(adapter);
        isAdapter[adapter] = false;
        emit AdapterRemoved(adapter);
    }

    /// @notice Rule on `claimant`'s claim to a retired identifier (decision
    ///         0080 P4). Awarding binds the identifier to the claimant, who
    ///         proved it in `requestRebind`, and lifts its retirement, which
    ///         leaves every other claim on it unawardable; the account that
    ///         retired it keeps its current binding. Refusing drops the claim.
    ///         An award waits for `REBIND_DELAY`, the retiring account's time
    ///         to answer with its evidence, and the checks of
    ///         `finalizeRebind`; a refusal may come at any time, paused or not.
    /// @dev    The owner cannot bind an identifier nobody proved: only the
    ///         claimant of a pending request, through an adapter still active.
    ///         It is the person the contract lacks: a holder locked out by a
    ///         relink, and a person claiming their own old passport for a
    ///         second account, look the same on chain.
    function ruleRetiredClaim(bytes32 identifier, address claimant, bool award) external onlyOwner {
        PendingRebind memory p = retiredClaims[identifier][claimant];
        if (p.newAccount == address(0)) revert NoPendingRebind(identifier);
        if (award && !isRetired[identifier]) revert NotRetired(identifier);
        address retiring = retiredBy[identifier];
        if (award) {
            if (paused) revert Paused();
            if (block.timestamp < p.readyAt) revert RebindNotReady(p.readyAt);
            if (!isAdapter[p.adapter]) revert AdapterNotActive(p.adapter);
            if (allowlistOnly && !isTestAccount[p.newAccount]) revert NotTestAccount(p.newAccount);
            bytes32 existing = accountToIdentifier[p.newAccount];
            if (existing != bytes32(0)) revert AccountAlreadyBound(p.newAccount, existing);
        }
        delete retiredClaims[identifier][claimant];
        if (award) {
            isRetired[identifier] = false;
            delete retiredBy[identifier];
            identifierToAccount[identifier] = p.newAccount;
            accountToIdentifier[p.newAccount] = identifier;
        }
        emit RetiredClaimRuled(identifier, retiring, p.newAccount, award);
    }

    // ── Internals ────────────────────────────────────────────────────────────

    /// @dev Every check of an account action, shared by the actions and the
    ///      `check` view. Returns the proven identifier and, for REBIND, the
    ///      account it is bound to now or, if retired, the account that retired
    ///      it (for RELINK, `account`).
    function _check(bytes32 action, address account, address adapter, bytes calldata evidence)
        private
        view
        returns (bytes32 identifier, address counterpart)
    {
        if (paused) revert Paused();
        if (account == address(0)) revert ZeroAddress();
        if (allowlistOnly && !isTestAccount[account]) revert NotTestAccount(account);
        if (action != BIND && action != REBIND && action != RELINK) revert UnknownAction(action);
        // Adapters are immutable; kind and scope were checked when it was added.
        if (!isAdapter[adapter]) revert AdapterNotActive(adapter);

        identifier = IIdentityEvidenceAdapter(adapter).verify(account, digest(action, account), evidence);
        if (identifier == bytes32(0)) revert ZeroIdentifier();
        bool retired = isRetired[identifier];
        if (retired && action != REBIND) revert RetiredIdentifier(identifier);

        bytes32 accountId = accountToIdentifier[account];
        address holder = retired ? retiredBy[identifier] : identifierToAccount[identifier];
        if (action == BIND) {
            if (accountId != bytes32(0)) revert AccountAlreadyBound(account, accountId);
            if (holder != address(0)) revert IdentifierAlreadyBound(identifier, holder);
        } else if (action == RELINK) {
            if (accountId == bytes32(0)) revert AccountNotBound(account);
            if (accountId == identifier) revert SameIdentifier(identifier);
            if (holder != address(0)) revert IdentifierAlreadyBound(identifier, holder);
            if (pendingRebind[accountId].newAccount != address(0)) revert RebindPending(accountId);
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
