// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title CofferdamHandleAnchor
/// @notice The on-chain anchor of Cofferdam's `@handles` (workspace decision
///         0086, rule 3). One record per `handleId` holds the handle key's
///         address (`owner`), a `serial` that rises with each fresh claim, and
///         the ERC-5564 scheme 1 stealth meta-address payers derive one-time
///         addresses from. No account, no inbox and no label in clear: events
///         carry `handleId` only.
///         - **Claim**: an unowned label that was never released, or released
///           at least `QUARANTINE` ago, is claimed with the registrar's and the
///           new owner's EIP-712 signatures; anyone may submit.
///         - **Owner changes** (`transferOwner` co-signed by the new key,
///           `setMetaAddress`, `release`), signed by the owner with the
///           record's nonce, wait `CHANGE_DELAY`; one is pending at a time and
///           the owner may `cancel` it.
///         - **`advance`** (owner, new owner and registrar together) applies at
///           once and clears any pending change; it does not clear a freeze.
///         - **The registrar** (hot keys on a Safe-owned list) claims unowned
///           labels and may `hold` (freeze) a record or `veto` its pending
///           change (cancel and freeze), each for `FREEZE_DURATION`. A frozen
///           record refuses every owner change except `advance`, and the Safe's
///           `rekey`; `unfreeze` takes the owner's and the registrar's
///           signatures.
///         - **The Safe** (the contract `owner`, two-step transfer) adds
///           registrars, `rekey`s and `forceRelease`s behind `SAFE_DELAY`, a
///           timelock kept here because a Safe has none of its own; removing a
///           registrar and lifting a freeze are immediate.
/// @dev    The anchor names no identity registry and no evidence adapter, and
///         reads none: 0086 keeps it outside the account generation, the
///         identity registry and the M3 freeze. On Base mainnet (chain 8453)
///         the constructor accepts only 0086's delays; the check is on the
///         chain id, so a fork of mainnet enforces it too.
contract CofferdamHandleAnchor is EIP712 {
    // ── Constants ────────────────────────────────────────────────────────────

    uint256 public constant BASE_MAINNET_CHAIN_ID = 8453;
    /// @notice Decision 0086's values, the only ones the constructor accepts on
    ///         Base mainnet: owner changes wait 72 hours, a hold or a veto
    ///         freezes for 14 days, a released label is quarantined for 365
    ///         days, and the Safe's timelock is 72 hours.
    uint256 public constant MAINNET_CHANGE_DELAY = 72 hours;
    uint256 public constant MAINNET_FREEZE_DURATION = 14 days;
    uint256 public constant MAINNET_QUARANTINE = 365 days;
    uint256 public constant MAINNET_SAFE_DELAY = 72 hours;
    /// @notice Bounds off mainnet, so a typo cannot lock a record for years.
    uint256 public constant MAX_DELAY = 30 days;
    uint256 public constant MAX_QUARANTINE = 730 days;
    /// @notice How long a scheduled Safe operation stays executable after its
    ///         delay; an older one must be scheduled again, with fresh notice.
    uint256 public constant SAFE_OP_GRACE = 7 days;
    /// @notice ERC-5564 scheme 1 (secp256k1 with view tags).
    uint256 public constant SCHEME_ID = 1;
    /// @notice Two 33-byte compressed secp256k1 keys, spending first.
    uint256 public constant META_ADDRESS_LENGTH = 66;

    /// @notice EIP-712 types (domain: name "Cofferdam Handle Anchor", version
    ///         "1", the chain id, this contract). `bytes` fields are hashed
    ///         with keccak256, as EIP-712 encodes them.
    /// @dev    Signed by a registrar; `nonce` is that registrar's, unordered.
    bytes32 public constant REGISTRAR_CLAIM_TYPEHASH =
        keccak256("RegistrarClaim(bytes32 handleId,address owner,uint256 serial,uint256 nonce,uint256 deadline)");
    /// @dev Signed by the new owner; `serial` is the record's next serial.
    bytes32 public constant OWNER_CLAIM_TYPEHASH =
        keccak256("OwnerClaim(bytes32 handleId,bytes metaAddress,uint256 serial)");
    /// @dev Signed by the owner and by `newOwner`; `nonce` is the record's.
    bytes32 public constant TRANSFER_OWNER_TYPEHASH =
        keccak256("TransferOwner(bytes32 handleId,address newOwner,bytes newMetaAddress,uint256 nonce,uint256 deadline)");
    bytes32 public constant SET_META_ADDRESS_TYPEHASH =
        keccak256("SetMetaAddress(bytes32 handleId,bytes newMetaAddress,uint256 nonce,uint256 deadline)");
    bytes32 public constant RELEASE_TYPEHASH = keccak256("Release(bytes32 handleId,uint256 nonce,uint256 deadline)");
    bytes32 public constant CANCEL_TYPEHASH = keccak256("Cancel(bytes32 handleId,uint256 nonce,uint256 deadline)");
    /// @dev Signed by the owner, by `newOwner` and by a registrar, over the
    ///      same struct; `nonce` is the record's.
    bytes32 public constant ADVANCE_TYPEHASH =
        keccak256("Advance(bytes32 handleId,address newOwner,bytes newMetaAddress,uint256 nonce,uint256 deadline)");
    /// @dev Signed by the owner and by a registrar; `nonce` is the record's.
    bytes32 public constant UNFREEZE_TYPEHASH = keccak256("Unfreeze(bytes32 handleId,uint256 nonce,uint256 deadline)");
    /// @dev Signed by a registrar; `nonce` is that registrar's. A renewal is a
    ///      hold on a frozen record.
    bytes32 public constant HOLD_TYPEHASH = keccak256("Hold(bytes32 handleId,uint256 nonce,uint256 deadline)");
    /// @dev Signed by a registrar; `changeNonce` names the pending change (the
    ///      record nonce it was queued with), `nonce` is the registrar's.
    bytes32 public constant VETO_TYPEHASH =
        keccak256("Veto(bytes32 handleId,uint256 changeNonce,uint256 nonce,uint256 deadline)");

    // ── Immutables ───────────────────────────────────────────────────────────

    /// @notice Seconds an owner change waits between queue and apply.
    uint256 public immutable CHANGE_DELAY;
    /// @notice Seconds a hold or a veto freezes a record.
    uint256 public immutable FREEZE_DURATION;
    /// @notice Seconds a released label waits before it can be claimed again.
    uint256 public immutable QUARANTINE;
    /// @notice Seconds between scheduling and executing a timelocked Safe operation.
    uint256 public immutable SAFE_DELAY;

    // ── Records ──────────────────────────────────────────────────────────────

    enum ChangeKind {
        None,
        TransferOwner,
        SetMetaAddress,
        Release
    }

    struct Record {
        /// @dev The handle key's address; zero while unowned (never claimed, or released).
        address owner;
        /// @dev Rises with each fresh claim; kept through a release.
        uint32 serial;
        /// @dev The nonce the next owner-signed struct must carry; never resets.
        uint64 nonce;
        /// @dev Frozen while `block.timestamp < frozenUntil`.
        uint48 frozenUntil;
        /// @dev When the last release took effect; zero while owned or never released.
        uint48 releasedAt;
        /// @dev When the pending change may be applied.
        uint48 pendingReadyAt;
        ChangeKind pendingKind;
        /// @dev The last release waived the quarantine (`forceRelease`).
        bool quarantineWaived;
        /// @dev The record nonce the pending change was queued with.
        uint64 pendingNonce;
        address pendingOwner;
        bytes metaAddress;
        bytes pendingMetaAddress;
    }

    mapping(bytes32 => Record) private _records;

    // ── Admin state ──────────────────────────────────────────────────────────

    /// @notice The Cofferdam Safe.
    address public owner;
    address public pendingOwner;

    mapping(address => bool) public isRegistrar;
    /// @notice Registrar nonces already used (unordered: the relayer batches
    ///         claims with random delays, so they land out of order).
    mapping(address => mapping(uint256 => bool)) public registrarNonceUsed;

    enum SafeOpKind {
        None,
        AddRegistrar,
        Rekey,
        ForceRelease
    }

    /// @notice When a scheduled Safe operation may be executed; 0 when none.
    mapping(bytes32 => uint256) public safeOpReadyAt;

    // ── Events ───────────────────────────────────────────────────────────────

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event RegistrarAdded(address indexed registrar);
    event RegistrarRemoved(address indexed registrar);

    event Claimed(bytes32 indexed handleId, address indexed owner, uint256 serial, bytes metaAddress, address registrar);
    event ChangeQueued(
        bytes32 indexed handleId, ChangeKind kind, uint256 nonce, uint256 readyAt, address newOwner, bytes newMetaAddress
    );
    event ChangeCancelled(bytes32 indexed handleId, uint256 nonce);
    event ChangeVetoed(bytes32 indexed handleId, uint256 nonce, address registrar);
    event OwnerChanged(bytes32 indexed handleId, address indexed previousOwner, address indexed newOwner, bytes metaAddress);
    event MetaAddressChanged(bytes32 indexed handleId, bytes metaAddress);
    event Advanced(bytes32 indexed handleId, address indexed previousOwner, address indexed newOwner, bytes metaAddress, address registrar);
    event Released(bytes32 indexed handleId, uint256 serial, bool quarantined);
    event Frozen(bytes32 indexed handleId, uint256 frozenUntil, address registrar);
    event Unfrozen(bytes32 indexed handleId, address by);
    event Rekeyed(bytes32 indexed handleId, address indexed previousOwner, address indexed newOwner, uint256 serial, bytes metaAddress);

    event SafeOpScheduled(bytes32 indexed opId, SafeOpKind kind, bytes32 indexed handleId, uint256 readyAt, bytes args);
    event SafeOpCancelled(bytes32 indexed opId);
    event SafeOpExecuted(bytes32 indexed opId);

    // ── Errors ───────────────────────────────────────────────────────────────

    error NotOwner();
    error NotPendingOwner();
    error ZeroAddress();
    error ZeroHandle();
    error DelayTooLong(uint256 delay, uint256 maximum);
    error ZeroFreeze();
    error MainnetDelayMismatch(uint256 changeDelay, uint256 freezeDuration, uint256 quarantine, uint256 safeDelay);
    error BadMetaAddress();
    error Expired(uint256 deadline);
    error NotRegistrar(address signer);
    error RegistrarNonceUsed(address registrar, uint256 nonce);
    error WrongSigner(address expected, address recovered);
    error AlreadyOwned(bytes32 handleId);
    error NotOwned(bytes32 handleId);
    error UnknownHandle(bytes32 handleId);
    error InQuarantine(uint256 until);
    error RecordFrozen(uint256 until);
    error NotFrozen(bytes32 handleId);
    error ChangePending(uint256 nonce);
    error NoPendingChange(bytes32 handleId);
    error WrongChange(uint256 pending, uint256 named);
    error ChangeNotReady(uint256 readyAt);
    error SameOwner(address owner);
    error RegistrarAlreadyListed(address registrar);
    error RegistrarNotListed(address registrar);
    error SafeOpAlreadyScheduled(bytes32 opId, uint256 readyAt);
    error SafeOpNotScheduled(bytes32 opId);
    error SafeOpNotReady(uint256 readyAt);
    error SafeOpExpired(uint256 expiredAt);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /// @param _owner The Cofferdam Safe (a throwaway Safe on a test deploy), owner from the first block.
    /// @param changeDelay Owner changes' wait; 72 hours on Base mainnet.
    /// @param freezeDuration A hold's or a veto's freeze, never 0; 14 days on Base mainnet.
    /// @param quarantine A released label's wait; 365 days on Base mainnet.
    /// @param safeDelay The Safe's timelock; 72 hours on Base mainnet.
    /// @param initialRegistrars Listed from deployment, visible in the constructor arguments.
    constructor(
        address _owner,
        uint256 changeDelay,
        uint256 freezeDuration,
        uint256 quarantine,
        uint256 safeDelay,
        address[] memory initialRegistrars
    ) EIP712("Cofferdam Handle Anchor", "1") {
        if (_owner == address(0)) revert ZeroAddress();
        if (block.chainid == BASE_MAINNET_CHAIN_ID) {
            if (
                changeDelay != MAINNET_CHANGE_DELAY || freezeDuration != MAINNET_FREEZE_DURATION
                    || quarantine != MAINNET_QUARANTINE || safeDelay != MAINNET_SAFE_DELAY
            ) revert MainnetDelayMismatch(changeDelay, freezeDuration, quarantine, safeDelay);
        }
        if (changeDelay > MAX_DELAY) revert DelayTooLong(changeDelay, MAX_DELAY);
        if (freezeDuration > MAX_DELAY) revert DelayTooLong(freezeDuration, MAX_DELAY);
        if (safeDelay > MAX_DELAY) revert DelayTooLong(safeDelay, MAX_DELAY);
        if (quarantine > MAX_QUARANTINE) revert DelayTooLong(quarantine, MAX_QUARANTINE);
        if (freezeDuration == 0) revert ZeroFreeze();
        CHANGE_DELAY = changeDelay;
        FREEZE_DURATION = freezeDuration;
        QUARANTINE = quarantine;
        SAFE_DELAY = safeDelay;
        owner = _owner;
        emit OwnershipTransferred(address(0), _owner);
        for (uint256 i = 0; i < initialRegistrars.length; i++) {
            _addRegistrar(initialRegistrars[i]);
        }
    }

    // ── Claim ────────────────────────────────────────────────────────────────

    /// @notice Claim an unowned label for `handleOwner`. The label must never
    ///         have been released, or released at least `QUARANTINE` ago (or
    ///         by a `forceRelease` that waived it). The registrar signs
    ///         `RegistrarClaim` over the next serial; the new owner signs
    ///         `OwnerClaim` over the meta-address and that serial. Anyone may
    ///         submit.
    function claim(
        bytes32 handleId,
        address handleOwner,
        bytes calldata metaAddress,
        uint256 registrarNonce,
        uint256 deadline,
        bytes calldata registrarSig,
        bytes calldata ownerSig
    ) external {
        if (handleId == bytes32(0)) revert ZeroHandle();
        if (handleOwner == address(0)) revert ZeroAddress();
        _checkMetaAddress(metaAddress);
        _checkDeadline(deadline);
        Record storage r = _records[handleId];
        if (r.owner != address(0)) revert AlreadyOwned(handleId);
        if (r.releasedAt != 0 && !r.quarantineWaived) {
            uint256 until = uint256(r.releasedAt) + QUARANTINE;
            if (block.timestamp < until) revert InQuarantine(until);
        }
        uint256 serial = uint256(r.serial) + 1;

        address registrar = _recover(
            keccak256(abi.encode(REGISTRAR_CLAIM_TYPEHASH, handleId, handleOwner, serial, registrarNonce, deadline)),
            registrarSig
        );
        _useRegistrarNonce(registrar, registrarNonce);
        _expect(handleOwner, keccak256(abi.encode(OWNER_CLAIM_TYPEHASH, handleId, keccak256(metaAddress), serial)), ownerSig);

        r.owner = handleOwner;
        r.serial = uint32(serial);
        r.metaAddress = metaAddress;
        r.releasedAt = 0;
        r.quarantineWaived = false;
        emit Claimed(handleId, handleOwner, serial, metaAddress, registrar);
    }

    // ── Owner changes (queued, `CHANGE_DELAY`) ───────────────────────────────

    /// @notice Queue a move of the record to `newOwner` and `newMetaAddress`
    ///         (an epoch advance or a rotation, the slow path), signed by the
    ///         owner and co-signed by the new key over `TransferOwner`.
    function transferOwner(
        bytes32 handleId,
        address newOwner,
        bytes calldata newMetaAddress,
        uint256 deadline,
        bytes calldata ownerSig,
        bytes calldata newOwnerSig
    ) external {
        Record storage r = _queueable(handleId, deadline);
        if (newOwner == address(0)) revert ZeroAddress();
        if (newOwner == r.owner) revert SameOwner(newOwner);
        _checkMetaAddress(newMetaAddress);
        uint256 nonce = r.nonce;
        bytes32 structHash =
            keccak256(abi.encode(TRANSFER_OWNER_TYPEHASH, handleId, newOwner, keccak256(newMetaAddress), nonce, deadline));
        _expect(r.owner, structHash, ownerSig);
        _expect(newOwner, structHash, newOwnerSig);
        _queue(handleId, r, ChangeKind.TransferOwner, newOwner, newMetaAddress);
    }

    /// @notice Queue a new meta-address under the same handle key.
    function setMetaAddress(bytes32 handleId, bytes calldata newMetaAddress, uint256 deadline, bytes calldata ownerSig)
        external
    {
        Record storage r = _queueable(handleId, deadline);
        _checkMetaAddress(newMetaAddress);
        _expect(
            r.owner,
            keccak256(abi.encode(SET_META_ADDRESS_TYPEHASH, handleId, keccak256(newMetaAddress), r.nonce, deadline)),
            ownerSig
        );
        _queue(handleId, r, ChangeKind.SetMetaAddress, address(0), newMetaAddress);
    }

    /// @notice Queue the release of the label. Once applied the record has no
    ///         owner and the label is quarantined for `QUARANTINE`.
    function release(bytes32 handleId, uint256 deadline, bytes calldata ownerSig) external {
        Record storage r = _queueable(handleId, deadline);
        _expect(r.owner, keccak256(abi.encode(RELEASE_TYPEHASH, handleId, r.nonce, deadline)), ownerSig);
        _queue(handleId, r, ChangeKind.Release, address(0), "");
    }

    /// @notice The owner withdraws the pending change, at once.
    /// @dev    ASSUMPTION(0086 rule 3): a cancel is not an "owner change", so it
    ///         stays open while the record is frozen; it only narrows what
    ///         happens to the record.
    function cancel(bytes32 handleId, uint256 deadline, bytes calldata ownerSig) external {
        _checkDeadline(deadline);
        Record storage r = _owned(handleId);
        if (r.pendingKind == ChangeKind.None) revert NoPendingChange(handleId);
        _expect(r.owner, keccak256(abi.encode(CANCEL_TYPEHASH, handleId, r.nonce, deadline)), ownerSig);
        r.nonce++;
        uint256 cancelled = r.pendingNonce;
        _clearPending(r);
        emit ChangeCancelled(handleId, cancelled);
    }

    /// @notice Apply the pending change once `CHANGE_DELAY` has passed and the
    ///         record is not frozen. Anyone may call it; the authorisation
    ///         happened when it was queued.
    function applyChange(bytes32 handleId) external {
        Record storage r = _owned(handleId);
        ChangeKind kind = r.pendingKind;
        if (kind == ChangeKind.None) revert NoPendingChange(handleId);
        if (block.timestamp < r.pendingReadyAt) revert ChangeNotReady(r.pendingReadyAt);
        _notFrozen(r);
        if (kind == ChangeKind.Release) {
            _release(handleId, r, true);
            return;
        }
        if (kind == ChangeKind.TransferOwner) {
            address previous = r.owner;
            r.owner = r.pendingOwner;
            r.metaAddress = r.pendingMetaAddress;
            _clearPending(r);
            emit OwnerChanged(handleId, previous, r.owner, r.metaAddress);
        } else {
            r.metaAddress = r.pendingMetaAddress;
            _clearPending(r);
            emit MetaAddressChanged(handleId, r.metaAddress);
        }
    }

    // ── The immediate advance ────────────────────────────────────────────────

    /// @notice Move the record to `newOwner` and `newMetaAddress` at once, with
    ///         the owner's, the new owner's and a registrar's signatures over
    ///         one `Advance` struct. Clears any pending change. Open while
    ///         frozen. The serial does not change.
    function advance(
        bytes32 handleId,
        address newOwner,
        bytes calldata newMetaAddress,
        uint256 deadline,
        bytes calldata ownerSig,
        bytes calldata newOwnerSig,
        bytes calldata registrarSig
    ) external {
        _checkDeadline(deadline);
        Record storage r = _owned(handleId);
        if (newOwner == address(0)) revert ZeroAddress();
        if (newOwner == r.owner) revert SameOwner(newOwner);
        _checkMetaAddress(newMetaAddress);
        bytes32 structHash =
            keccak256(abi.encode(ADVANCE_TYPEHASH, handleId, newOwner, keccak256(newMetaAddress), r.nonce, deadline));
        _expect(r.owner, structHash, ownerSig);
        _expect(newOwner, structHash, newOwnerSig);
        address registrar = _recover(structHash, registrarSig);
        if (!isRegistrar[registrar]) revert NotRegistrar(registrar);

        r.nonce++;
        if (r.pendingKind != ChangeKind.None) {
            emit ChangeCancelled(handleId, r.pendingNonce);
            _clearPending(r);
        }
        address previous = r.owner;
        r.owner = newOwner;
        r.metaAddress = newMetaAddress;
        // ASSUMPTION(0086 q15): `advance` does not clear a freeze; only
        // `unfreeze` (owner and registrar), the Safe's `liftFreeze` or `rekey`,
        // or the freeze's lapse does.
        emit Advanced(handleId, previous, newOwner, newMetaAddress, registrar);
    }

    // ── Freezes ──────────────────────────────────────────────────────────────

    /// @notice A registrar freezes an owned record for `FREEZE_DURATION` from
    ///         now (the plane signs only after a High ceremony of the identity
    ///         that holds the handle). A hold on a frozen record renews it.
    function hold(bytes32 handleId, uint256 registrarNonce, uint256 deadline, bytes calldata registrarSig) external {
        _checkDeadline(deadline);
        Record storage r = _owned(handleId);
        address registrar =
            _recover(keccak256(abi.encode(HOLD_TYPEHASH, handleId, registrarNonce, deadline)), registrarSig);
        _useRegistrarNonce(registrar, registrarNonce);
        _freeze(handleId, r, registrar);
    }

    /// @notice A registrar cancels the pending change named by `changeNonce`
    ///         and freezes the record for `FREEZE_DURATION`.
    function veto(bytes32 handleId, uint256 changeNonce, uint256 registrarNonce, uint256 deadline, bytes calldata registrarSig)
        external
    {
        _checkDeadline(deadline);
        Record storage r = _owned(handleId);
        if (r.pendingKind == ChangeKind.None) revert NoPendingChange(handleId);
        if (r.pendingNonce != changeNonce) revert WrongChange(r.pendingNonce, changeNonce);
        address registrar = _recover(
            keccak256(abi.encode(VETO_TYPEHASH, handleId, changeNonce, registrarNonce, deadline)), registrarSig
        );
        _useRegistrarNonce(registrar, registrarNonce);
        _clearPending(r);
        emit ChangeVetoed(handleId, changeNonce, registrar);
        _freeze(handleId, r, registrar);
    }

    /// @notice Lift a freeze with the owner's and a registrar's signatures over
    ///         `Unfreeze`.
    /// @dev    ASSUMPTION(0086 q15): `unfreeze` is signed by the owner and the
    ///         registrar. When the plane may sign it (a rotation to a new
    ///         phrase, a hold with no veto, never after a veto under the same
    ///         phrase) is the plane's rule; the contract cannot tell phrases
    ///         apart.
    function unfreeze(bytes32 handleId, uint256 deadline, bytes calldata ownerSig, bytes calldata registrarSig) external {
        _checkDeadline(deadline);
        Record storage r = _owned(handleId);
        if (r.frozenUntil <= block.timestamp) revert NotFrozen(handleId);
        bytes32 structHash = keccak256(abi.encode(UNFREEZE_TYPEHASH, handleId, r.nonce, deadline));
        _expect(r.owner, structHash, ownerSig);
        address registrar = _recover(structHash, registrarSig);
        if (!isRegistrar[registrar]) revert NotRegistrar(registrar);
        r.nonce++;
        r.frozenUntil = 0;
        emit Unfrozen(handleId, registrar);
    }

    // ── Views ────────────────────────────────────────────────────────────────

    /// @notice The whole record of `handleId`.
    function recordOf(bytes32 handleId) external view returns (Record memory) {
        return _records[handleId];
    }

    /// @notice What a Cofferdam payer reads: the owner, the serial, the
    ///         meta-address, and whether to derive to it now. `derivable` is
    ///         false while the record is unowned, frozen or has a pending
    ///         change (0086 rule 3).
    function resolve(bytes32 handleId)
        external
        view
        returns (address handleOwner, uint256 serial, bytes memory metaAddress, bool derivable)
    {
        Record storage r = _records[handleId];
        handleOwner = r.owner;
        serial = r.serial;
        metaAddress = r.metaAddress;
        derivable = handleOwner != address(0) && r.frozenUntil <= block.timestamp && r.pendingKind == ChangeKind.None;
    }

    /// @notice The ERC-5564 scheme id and stealth meta-address of `handleId`
    ///         (empty while unowned).
    function stealthMetaAddressOf(bytes32 handleId) external view returns (uint256 schemeId, bytes memory metaAddress) {
        return (SCHEME_ID, _records[handleId].metaAddress);
    }

    function isFrozen(bytes32 handleId) external view returns (bool) {
        return _records[handleId].frozenUntil > block.timestamp;
    }

    /// @notice The first time `handleId` can be claimed: 0 for a label never
    ///         released (or released with the quarantine waived), the end of its
    ///         quarantine otherwise, `type(uint256).max` while owned.
    function claimableAt(bytes32 handleId) external view returns (uint256) {
        Record storage r = _records[handleId];
        if (r.owner != address(0)) return type(uint256).max;
        if (r.releasedAt == 0 || r.quarantineWaived) return 0;
        return uint256(r.releasedAt) + QUARANTINE;
    }

    /// @notice The record nonce the next owner-signed struct must carry.
    function nonceOf(bytes32 handleId) external view returns (uint256) {
        return _records[handleId].nonce;
    }

    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ── The Safe ─────────────────────────────────────────────────────────────

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

    /// @notice Immediate: a removal only narrows who may sign, so it needs no
    ///         timelock. Signatures it made and that were not yet submitted
    ///         stop working with it.
    function removeRegistrar(address registrar) external onlyOwner {
        if (!isRegistrar[registrar]) revert RegistrarNotListed(registrar);
        isRegistrar[registrar] = false;
        emit RegistrarRemoved(registrar);
    }

    /// @notice Immediate: lift a freeze (a stolen registrar key's, or a hold set by mistake).
    function liftFreeze(bytes32 handleId) external onlyOwner {
        Record storage r = _records[handleId];
        if (r.frozenUntil <= block.timestamp) revert NotFrozen(handleId);
        r.frozenUntil = 0;
        emit Unfrozen(handleId, msg.sender);
    }

    // ASSUMPTION(0086 rule 3): the Safe's 72-hour timelock lives in this
    // contract (a Safe has none of its own). Each operation is scheduled with
    // its arguments, executable from `SAFE_DELAY` later for `SAFE_OP_GRACE`,
    // and cancellable by the Safe meanwhile.

    function scheduleAddRegistrar(address registrar) external onlyOwner {
        if (registrar == address(0)) revert ZeroAddress();
        if (isRegistrar[registrar]) revert RegistrarAlreadyListed(registrar);
        _schedule(addRegistrarOpId(registrar), SafeOpKind.AddRegistrar, bytes32(0), abi.encode(registrar));
    }

    function executeAddRegistrar(address registrar) external onlyOwner {
        _consume(addRegistrarOpId(registrar));
        _addRegistrar(registrar);
    }

    /// @notice Schedule a move of `handleId` to `newOwner` and `newMetaAddress`,
    ///         also for a frozen or released record (0086 rule 3, question 3).
    /// @dev    ASSUMPTION(0086 q16): no owner brake: the record's owner cannot
    ///         cancel a scheduled rekey, since a phrase thief would use one to
    ///         block recovery. Its control is the Safe's signers and this
    ///         timelock; the event below is what the owner's app shows.
    function scheduleRekey(bytes32 handleId, address newOwner, bytes calldata newMetaAddress) external onlyOwner {
        _checkRekey(handleId, newOwner, newMetaAddress);
        _schedule(
            rekeyOpId(handleId, newOwner, newMetaAddress), SafeOpKind.Rekey, handleId, abi.encode(newOwner, newMetaAddress)
        );
    }

    /// @notice Apply a scheduled rekey: the new owner and meta-address, no
    ///         pending change, no freeze. On a released record it is a fresh
    ///         holder, so the serial rises and the quarantine ends.
    function executeRekey(bytes32 handleId, address newOwner, bytes calldata newMetaAddress) external onlyOwner {
        _consume(rekeyOpId(handleId, newOwner, newMetaAddress));
        _checkRekey(handleId, newOwner, newMetaAddress);
        Record storage r = _records[handleId];
        address previous = r.owner;
        if (previous == address(0)) {
            // ASSUMPTION(0086 rule 3): a rekey of a released record hands the
            // label to a holder again, which 0086 rule 8 reads as a change of
            // hands: the serial rises, so contacts confirm before paying.
            r.serial++;
            r.releasedAt = 0;
            r.quarantineWaived = false;
        }
        if (r.pendingKind != ChangeKind.None) {
            emit ChangeCancelled(handleId, r.pendingNonce);
            _clearPending(r);
        }
        r.owner = newOwner;
        r.metaAddress = newMetaAddress;
        r.frozenUntil = 0;
        emit Rekeyed(handleId, previous, newOwner, r.serial, newMetaAddress);
    }

    /// @notice Schedule the release of an owned record (a lost phrase after an
    ///         identity proof, a court order, a reserved-name breach). With
    ///         `quarantine` false the label can be claimed at once, for its
    ///         rightful holder.
    function scheduleForceRelease(bytes32 handleId, bool quarantine) external onlyOwner {
        _owned(handleId);
        _schedule(forceReleaseOpId(handleId, quarantine), SafeOpKind.ForceRelease, handleId, abi.encode(quarantine));
    }

    function executeForceRelease(bytes32 handleId, bool quarantine) external onlyOwner {
        _consume(forceReleaseOpId(handleId, quarantine));
        Record storage r = _owned(handleId);
        _release(handleId, r, quarantine);
    }

    /// @notice Withdraw a scheduled operation.
    function cancelSafeOp(bytes32 opId) external onlyOwner {
        if (safeOpReadyAt[opId] == 0) revert SafeOpNotScheduled(opId);
        delete safeOpReadyAt[opId];
        emit SafeOpCancelled(opId);
    }

    function addRegistrarOpId(address registrar) public pure returns (bytes32) {
        return keccak256(abi.encode(SafeOpKind.AddRegistrar, registrar));
    }

    function rekeyOpId(bytes32 handleId, address newOwner, bytes calldata newMetaAddress) public pure returns (bytes32) {
        return keccak256(abi.encode(SafeOpKind.Rekey, handleId, newOwner, newMetaAddress));
    }

    function forceReleaseOpId(bytes32 handleId, bool quarantine) public pure returns (bytes32) {
        return keccak256(abi.encode(SafeOpKind.ForceRelease, handleId, quarantine));
    }

    // ── Internals ────────────────────────────────────────────────────────────

    function _owned(bytes32 handleId) private view returns (Record storage r) {
        r = _records[handleId];
        if (r.owner == address(0)) revert NotOwned(handleId);
    }

    /// @dev An owned, unfrozen record with no pending change, and a live deadline.
    function _queueable(bytes32 handleId, uint256 deadline) private view returns (Record storage r) {
        _checkDeadline(deadline);
        r = _owned(handleId);
        _notFrozen(r);
        if (r.pendingKind != ChangeKind.None) revert ChangePending(r.pendingNonce);
    }

    function _queue(bytes32 handleId, Record storage r, ChangeKind kind, address newOwner, bytes memory newMetaAddress)
        private
    {
        uint64 nonce = r.nonce;
        r.nonce = nonce + 1;
        uint256 readyAt = block.timestamp + CHANGE_DELAY;
        r.pendingKind = kind;
        r.pendingNonce = nonce;
        r.pendingReadyAt = uint48(readyAt);
        r.pendingOwner = newOwner;
        r.pendingMetaAddress = newMetaAddress;
        emit ChangeQueued(handleId, kind, nonce, readyAt, newOwner, newMetaAddress);
    }

    function _clearPending(Record storage r) private {
        r.pendingKind = ChangeKind.None;
        r.pendingNonce = 0;
        r.pendingReadyAt = 0;
        r.pendingOwner = address(0);
        delete r.pendingMetaAddress;
    }

    function _release(bytes32 handleId, Record storage r, bool quarantined) private {
        r.owner = address(0);
        delete r.metaAddress;
        _clearPending(r);
        r.frozenUntil = 0;
        r.releasedAt = uint48(block.timestamp);
        r.quarantineWaived = !quarantined;
        emit Released(handleId, r.serial, quarantined);
    }

    function _freeze(bytes32 handleId, Record storage r, address registrar) private {
        uint256 until = block.timestamp + FREEZE_DURATION;
        r.frozenUntil = uint48(until);
        emit Frozen(handleId, until, registrar);
    }

    function _notFrozen(Record storage r) private view {
        if (r.frozenUntil > block.timestamp) revert RecordFrozen(r.frozenUntil);
    }

    function _checkRekey(bytes32 handleId, address newOwner, bytes calldata newMetaAddress) private view {
        if (_records[handleId].serial == 0) revert UnknownHandle(handleId);
        if (newOwner == address(0)) revert ZeroAddress();
        _checkMetaAddress(newMetaAddress);
    }

    function _schedule(bytes32 opId, SafeOpKind kind, bytes32 handleId, bytes memory args) private {
        uint256 pending = safeOpReadyAt[opId];
        if (pending != 0 && block.timestamp <= pending + SAFE_OP_GRACE) revert SafeOpAlreadyScheduled(opId, pending);
        uint256 readyAt = block.timestamp + SAFE_DELAY;
        safeOpReadyAt[opId] = readyAt;
        emit SafeOpScheduled(opId, kind, handleId, readyAt, args);
    }

    function _consume(bytes32 opId) private {
        uint256 readyAt = safeOpReadyAt[opId];
        if (readyAt == 0) revert SafeOpNotScheduled(opId);
        if (block.timestamp < readyAt) revert SafeOpNotReady(readyAt);
        if (block.timestamp > readyAt + SAFE_OP_GRACE) revert SafeOpExpired(readyAt + SAFE_OP_GRACE);
        delete safeOpReadyAt[opId];
        emit SafeOpExecuted(opId);
    }

    function _addRegistrar(address registrar) private {
        if (registrar == address(0)) revert ZeroAddress();
        if (isRegistrar[registrar]) revert RegistrarAlreadyListed(registrar);
        isRegistrar[registrar] = true;
        emit RegistrarAdded(registrar);
    }

    function _useRegistrarNonce(address registrar, uint256 nonce) private {
        if (!isRegistrar[registrar]) revert NotRegistrar(registrar);
        if (registrarNonceUsed[registrar][nonce]) revert RegistrarNonceUsed(registrar, nonce);
        registrarNonceUsed[registrar][nonce] = true;
    }

    function _recover(bytes32 structHash, bytes calldata sig) private view returns (address) {
        return ECDSA.recover(_hashTypedDataV4(structHash), sig);
    }

    function _expect(address expected, bytes32 structHash, bytes calldata sig) private view {
        address recovered = _recover(structHash, sig);
        if (recovered != expected) revert WrongSigner(expected, recovered);
    }

    function _checkDeadline(uint256 deadline) private view {
        if (block.timestamp > deadline) revert Expired(deadline);
    }

    /// @dev 66 bytes: two compressed secp256k1 keys, each prefixed 0x02 or 0x03.
    ///      Whether each is a point on the curve is the SDK's check.
    function _checkMetaAddress(bytes calldata m) private pure {
        if (m.length != META_ADDRESS_LENGTH) revert BadMetaAddress();
        if ((m[0] != 0x02 && m[0] != 0x03) || (m[33] != 0x02 && m[33] != 0x03)) revert BadMetaAddress();
    }
}
