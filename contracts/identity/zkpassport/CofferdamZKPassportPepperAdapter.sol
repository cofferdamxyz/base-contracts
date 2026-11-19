// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {IIdentityEvidenceAdapter} from "../IIdentityEvidenceAdapter.sol";
import {IZKPassportHelper} from "./IZKPassportRootVerifier.sol";
import {
    IZKPassportProofVerifier,
    IZKPassportRootRegistry,
    IZKPassportRootVerifierState,
    IZKPassportSubVerifier
} from "./IZKPassportDirect.sol";
import {ZKPassportSubVerifierChecks as Checks} from "./ZKPassportSubVerifierChecks.sol";

/// @title CofferdamZKPassportPepperAdapter
/// @notice The production evidence adapter of decision 0080's pepper (P1,
///         ruled 2026-11-18): a ZKPassport chip proof whose identifier is
///         salted under Cofferdam's own OPRF key, made by Cofferdam's in-app
///         prover with ZKPassport's unchanged circuits.
///         ZKPassport's `SubVerifier` accepts salted proofs only under its
///         global OPRF key ("Per-service OPRF key overrides are not supported
///         for now"), so `RootVerifier.verify` refuses ours. This adapter
///         calls the outer circuit's verifier itself and repeats every other
///         check the sub-verifier makes, with the key check turned to
///         Cofferdam's pinned key hash.
///
///         Every check of `RootVerifier.verify` and `SubVerifier.verify`
///         (zkpassport-packages 97576ab), and where it is made here:
///         1. `RootVerifier` not paused: `_checkLive`.
///         2. A sub-verifier registered for the version: `_checkLive`.
///         3. The sub-verifier not paused: `_checkLive`.
///         4. An outer verifier registered for the proof's vkey hash:
///            stricter here. The verifiers are pinned per vkey hash at
///            deployment (`outerVerifier`), and `_checkLive` also requires
///            the live sub-verifier to still list that same verifier, so a
///            verifier ZKPassport withdraws or swaps fails closed.
///         5. The certificate registry root valid at the proof's date:
///            `_checkRoots`, through `RootVerifier.rootRegistry()` as
///            `RootVerifier` passes it.
///         6. The circuit registry root valid at the proof's date: `_checkRoots`.
///         7. The proof's date within the validity: `verify`, with
///            `DateUtils.isDateValid` ported unchanged and `VALIDITY` pinned.
///         8. Domain and scope: `verify`, against hashes computed at
///            deployment from `DOMAIN` and the pinned scope.
///         9. The committed inputs against the parameter commitments:
///            `verify`, with `_verifyCommittedInputs` ported.
///         10. The verification method verifiable (`isVerifiable`: 100, 101,
///             200, 201): narrowed here to 100, the eMRTD chip. 200 to 299
///             are refused by ruling S7. 101 (Aadhaar) passes ZKPassport only
///             with a face match signed by ZKPassport's own app
///             (`FaceMatch.isGenuine` pins its app IDs), which needs both the
///             hand-off and FaceMatch the initial release ruled out; 102 and
///             103 are not verifiable at all. Ruled by the founder on
///             2026-11-19 ("only passport with chips for now"). S7's 100 to
///             199 stays the ceiling, and a later adapter can widen within it.
///         11. A device-attested method needs a valid attested-ID section,
///             any other must carry none: no device-attested method is
///             accepted, and `_screenSections` admits only the age, expiry
///             and bind sections, so an attested-ID section never passes.
///         12. Aadhaar's face match: not needed, 101 is refused (10).
///         13. The attestation revocation root, for a device-attested method
///             or Aadhaar: not needed, neither is accepted.
///         14. Mock identifier types only in dev mode, and only the four
///             types: the type must be `SALTED` (1), and dev mode does not
///             exist here.
///         15. The OPRF key hash equal to ZKPassport's global key: replaced by
///             equality with `OPRF_KEY_HASH`, Cofferdam's key. ZKPassport's
///             global key is refused at deployment, so this adapter never
///             accepts proofs salted under it.
///         16. The outer proof itself: `verify` calls the pinned verifier
///             with the proof and every public input, as the sub-verifier does.
///         17. The identifier read from the public inputs: the same index.
///
///         What `ZKPassportEvidenceAdapter` adds on top stays: the helper
///         pinned and checked on every call; the bound account, chain and
///         action digest; exactly one bind section; the minimum age and the
///         document expiry as exact committed lower bounds, with no upper
///         bound; nothing disclosed.
///
///         The identifier kind is `keccak256(abi.encode("zkpassport-
///         identifier-v1", SALTED, OPRF_KEY_HASH))`, the kind
///         `ZKPassportEvidenceAdapter` gives salted proofs under the same key:
///         the identifier is the same whichever contract checks the proof, so
///         if ZKPassport accepts a per-service key later, an adapter through
///         `RootVerifier` replaces this one behind the registry's timelock,
///         without a new generation.
/// @dev    Trust kept in ZKPassport: the roots (their registries and oracle),
///         the helper's decoding (pinned) and the outer verifiers (pinned).
///         Their admin can stop this adapter (a pause, a withdrawn verifier, a
///         swapped helper or sub-verifier without our verifier) but cannot
///         make it accept a proof of another verifier.
///         `evidence` is `abi.encode(bytes32 vkeyHash, bytes proof,
///         bytes32[] publicInputs, bytes committedInputs)`, as for
///         `ZKPassportEvidenceAdapter`. Public inputs of a 0.23.0 outer proof:
///         [0] certificate registry root, [1] circuit registry root, [2] proof
///         date, [3] scope, [4] subscope, [5..n-4) parameter commitments, then
///         identifier type, identifier, OPRF key hash, verification method.
contract CofferdamZKPassportPepperAdapter is IIdentityEvidenceAdapter {
    /// @notice ZKPassport's verifier on Base mainnet; required on chain 8453.
    address public constant CANONICAL_ROOT_VERIFIER = 0x1D000001000EFD9a6371f4d90bB8920D5431c0D8;
    uint256 public constant BASE_MAINNET_CHAIN_ID = 8453;
    /// @notice ZKPassport's global OPRF key hash on Base mainnet (the 0.23.0
    ///         sub-verifier's `globalOPRFPubKeyHash`, read 2026-11-19); never pinned.
    bytes32 public constant ZKPASSPORT_GLOBAL_OPRF_KEY_HASH =
        0x029ad69ef5e692aa43cd3635002a473d72b412d10741d2cba30700df1e895334;
    string public constant DOMAIN = "cofferdam.xyz";
    /// @notice Ceiling on `VALIDITY`.
    uint256 public constant MAX_VALIDITY = 1 days;
    /// @notice Ceiling on `EXPIRY_MARGIN`.
    uint256 public constant MAX_EXPIRY_MARGIN = 5 * 365 days;
    /// @notice The first circuits version whose outer proof ends with the
    ///         verification method (0.23.0); older versions are refused.
    bytes32 public constant MIN_VERSION = bytes32(uint256(0x0000001700000000) << 192);
    /// @notice ZKPassport's salted identifier type, the only one accepted.
    uint8 public constant SALTED = 1;
    /// @notice The eMRTD chip, the only verification method accepted (see 10 above).
    uint256 public constant ICAO_CHIP = 100;
    /// @notice ZKPassport's registry ids in `RootRegistry`.
    bytes32 public constant CERTIFICATE_REGISTRY = bytes32(uint256(1));
    bytes32 public constant CIRCUIT_REGISTRY = bytes32(uint256(2));

    /// @dev Committed-input section types admitted; every other is refused.
    uint8 private constant AGE = 1;
    uint8 private constant EXPIRY_DATE = 3;
    uint8 private constant BIND = 8;
    /// @dev Public inputs before the parameter commitments, and after them.
    uint256 private constant LEADING_INPUTS = 5;
    uint256 private constant TRAILING_INPUTS = 4;

    IZKPassportRootVerifierState public immutable ROOT_VERIFIER;
    /// @notice The version's helper at deployment; it decodes the bound
    ///         account, chain and digest, so it is pinned.
    IZKPassportHelper public immutable HELPER;
    /// @notice Circuits version as ZKPassport encodes it (0.23.0 is
    ///         `0x000000170000` padded); at least `MIN_VERSION`.
    bytes32 public immutable VERSION;
    uint256 public immutable VALIDITY;
    /// @notice Cofferdam's OPRF public key hash, `Poseidon2(pk.x, pk.y)` as the
    ///         circuit outputs it: the generation's pepper (P8).
    bytes32 public immutable OPRF_KEY_HASH;
    /// @notice Minimum age the proof must prove exactly; 0 checks none.
    uint8 public immutable MIN_AGE;
    /// @notice Seconds the document must stay valid after the bind; 0 checks none.
    uint256 public immutable EXPIRY_MARGIN;

    bytes32 private immutable _identifierKind;
    bytes32 private immutable _scopeId;
    bytes32 private immutable _domainHash;
    bytes32 private immutable _scopeHash;
    string private _scope;

    /// @notice The outer-proof verifier pinned per verification-key hash; set
    ///         once, at deployment.
    mapping(bytes32 vkeyHash => address verifier) public outerVerifier;
    /// @notice The pinned verification-key hashes, in deployment order.
    bytes32[] private _vkeyHashes;

    event OuterVerifierPinned(bytes32 indexed vkeyHash, address indexed verifier);

    error ZeroAddress();
    error NotCanonicalVerifier(address got);
    error UnsupportedVersion(bytes32 version);
    error NoSubVerifier(bytes32 version);
    error ForeignSubVerifier(address subVerifier);
    error EmptyScope();
    error BadValidity(uint256 validity);
    error BadOprfKeyHash();
    error GlobalOprfKeyRefused(bytes32 keyHash);
    error BadMinAge(uint8 minAge);
    error BadExpiryMargin(uint256 margin);
    error NoOuterVerifiers();
    error LengthMismatch();
    error DuplicateVerificationKey(bytes32 vkeyHash);
    error OuterVerifierMismatch(bytes32 vkeyHash, address expected, address got);
    error HelperMismatch(address expected, address got);

    error MalformedEvidence();
    error WrongIdentifierType(uint256 expected, uint256 got);
    error WrongOprfKey(bytes32 expected, bytes32 got);
    error VerificationMethodRefused(uint256 method);
    error ZeroIdentifier();
    error VerifierPaused(address verifier);
    error UnknownVerificationKey(bytes32 vkeyHash);
    error OuterVerifierWithdrawn(bytes32 vkeyHash);
    error ProofDateInvalid(uint256 proofDate);
    error WrongScope();
    error InvalidCertificateRoot();
    error InvalidCircuitRoot();
    error CommitmentMismatch();
    error ProofInvalid();
    error WrongBoundAccount(address expected, address got);
    error WrongBoundChain(uint256 expected, uint256 got);
    error WrongBoundDigest();
    error AgeNotProven(uint8 minAge);
    error ExpiryNotProven(uint256 earliest);
    error SectionRefused(uint8 sectionType);
    error DuplicateSection(uint8 sectionType);
    error DisclosureRefused(uint8 sectionType);
    error MalformedCommittedInputs();
    error BindSectionCount(uint256 count);

    /// @param rootVerifier ZKPassport's `RootVerifier`; must be canonical on Base mainnet.
    /// @param helper The helper `rootVerifier` names for `version` now; checked here.
    /// @param version The circuits version the proofs must be made with, 0.23.0 or later.
    /// @param scope_ The ZKPassport scope (the generation's own, never reused).
    /// @param validity Seconds a proof stays usable after its date, at most `MAX_VALIDITY`.
    /// @param oprfKeyHash Cofferdam's OPRF key hash; never 0, never ZKPassport's global key.
    /// @param minAge The age the proof must prove (18 for Cofferdam); 0 checks none.
    /// @param expiryMargin Seconds the document must stay valid after the bind; 0 checks none.
    /// @param vkeyHashes_ The outer circuits' verification-key hashes for `version`.
    /// @param outerVerifiers Their verifiers, as the version's sub-verifier lists them now.
    constructor(
        address rootVerifier,
        address helper,
        bytes32 version,
        string memory scope_,
        uint256 validity,
        bytes32 oprfKeyHash,
        uint8 minAge,
        uint256 expiryMargin,
        bytes32[] memory vkeyHashes_,
        address[] memory outerVerifiers
    ) {
        if (rootVerifier == address(0)) revert ZeroAddress();
        if (block.chainid == BASE_MAINNET_CHAIN_ID && rootVerifier != CANONICAL_ROOT_VERIFIER) {
            revert NotCanonicalVerifier(rootVerifier);
        }
        if (uint256(version) < uint256(MIN_VERSION)) revert UnsupportedVersion(version);
        IZKPassportRootVerifierState root = IZKPassportRootVerifierState(rootVerifier);
        address registered = root.getHelper(version);
        if (helper == address(0) || registered != helper) revert HelperMismatch(registered, helper);
        address sub = root.getSubVerifier(version);
        if (sub == address(0)) revert NoSubVerifier(version);
        if (IZKPassportSubVerifier(sub).rootVerifier() != rootVerifier) revert ForeignSubVerifier(sub);
        if (bytes(scope_).length == 0) revert EmptyScope();
        if (validity == 0 || validity > MAX_VALIDITY) revert BadValidity(validity);
        if (oprfKeyHash == bytes32(0)) revert BadOprfKeyHash();
        if (oprfKeyHash == ZKPASSPORT_GLOBAL_OPRF_KEY_HASH || oprfKeyHash == IZKPassportSubVerifier(sub).globalOPRFPubKeyHash())
        {
            revert GlobalOprfKeyRefused(oprfKeyHash);
        }
        if (minAge > 100) revert BadMinAge(minAge);
        if (expiryMargin > MAX_EXPIRY_MARGIN) revert BadExpiryMargin(expiryMargin);

        if (vkeyHashes_.length == 0) revert NoOuterVerifiers();
        if (vkeyHashes_.length != outerVerifiers.length) revert LengthMismatch();
        for (uint256 i = 0; i < vkeyHashes_.length; i++) {
            bytes32 h = vkeyHashes_[i];
            address v = outerVerifiers[i];
            if (v == address(0)) revert ZeroAddress();
            if (outerVerifier[h] != address(0)) revert DuplicateVerificationKey(h);
            address live = IZKPassportSubVerifier(sub).proofVerifiers(h);
            if (live != v) revert OuterVerifierMismatch(h, v, live);
            outerVerifier[h] = v;
            _vkeyHashes.push(h);
            emit OuterVerifierPinned(h, v);
        }

        ROOT_VERIFIER = root;
        HELPER = IZKPassportHelper(helper);
        VERSION = version;
        VALIDITY = validity;
        OPRF_KEY_HASH = oprfKeyHash;
        MIN_AGE = minAge;
        EXPIRY_MARGIN = expiryMargin;
        _scope = scope_;
        _identifierKind = keccak256(abi.encode("zkpassport-identifier-v1", SALTED, oprfKeyHash));
        _scopeId = keccak256(abi.encode(DOMAIN, scope_));
        _domainHash = Checks.scopeHash(DOMAIN);
        _scopeHash = Checks.scopeHash(scope_);
    }

    function scope() external view returns (string memory) {
        return _scope;
    }

    /// @notice The pinned verification-key hashes; `outerVerifier` gives each one's verifier.
    function vkeyHashes() external view returns (bytes32[] memory) {
        return _vkeyHashes;
    }

    /// @inheritdoc IIdentityEvidenceAdapter
    function identifierKind() external view returns (bytes32) {
        return _identifierKind;
    }

    /// @inheritdoc IIdentityEvidenceAdapter
    function scopeId() external view returns (bytes32) {
        return _scopeId;
    }

    /// @notice The `custom_data` string a proof for `digest` must carry.
    function customData(bytes32 digest) public pure returns (string memory) {
        return Strings.toHexString(uint256(digest), 32);
    }

    /// @inheritdoc IIdentityEvidenceAdapter
    function verify(address account, bytes32 digest, bytes calldata evidence)
        external
        view
        returns (bytes32 identifier)
    {
        (bytes32 vkeyHash, bytes memory proof, bytes32[] memory publicInputs, bytes memory committedInputs) =
            abi.decode(evidence, (bytes32, bytes, bytes32[], bytes));
        uint256 n = publicInputs.length;
        // At least one parameter commitment: the bind section's.
        if (n < LEADING_INPUTS + 1 + TRAILING_INPUTS) revert MalformedEvidence();
        uint256 t = n - TRAILING_INPUTS;

        // The trailing inputs: the type, the key and the method first, as they are cheap.
        uint256 idType = uint256(publicInputs[t]);
        if (idType != SALTED) revert WrongIdentifierType(SALTED, idType);
        if (publicInputs[t + 2] != OPRF_KEY_HASH) revert WrongOprfKey(OPRF_KEY_HASH, publicInputs[t + 2]);
        uint256 method = uint256(publicInputs[t + 3]);
        if (method != ICAO_CHIP) revert VerificationMethodRefused(method);
        identifier = publicInputs[t + 1];
        if (identifier == bytes32(0)) revert ZeroIdentifier();

        address verifier = _checkLive(vkeyHash);

        uint256 proofDate = uint256(publicInputs[2]);
        // A future date first, so a date near 2^256 is refused by name, not by an overflow.
        if (proofDate > block.timestamp || !Checks.isDateValid(proofDate, VALIDITY)) revert ProofDateInvalid(proofDate);
        if (publicInputs[3] != _domainHash || publicInputs[4] != _scopeHash) revert WrongScope();
        _checkRoots(publicInputs[0], publicInputs[1], proofDate);
        if (!Checks.committedInputsMatch(publicInputs, LEADING_INPUTS, t, committedInputs)) revert CommitmentMismatch();
        _screenSections(committedInputs);

        if (!IZKPassportProofVerifier(verifier).verify(proof, publicInputs)) revert ProofInvalid();

        IZKPassportHelper.BoundData memory bound = HELPER.getBoundData(committedInputs);
        if (bound.senderAddress != account) revert WrongBoundAccount(account, bound.senderAddress);
        if (bound.chainId != block.chainid) revert WrongBoundChain(block.chainid, bound.chainId);
        if (keccak256(bytes(bound.customData)) != keccak256(bytes(customData(digest)))) revert WrongBoundDigest();

        if (MIN_AGE != 0 && !HELPER.isAgeAboveOrEqual(MIN_AGE, committedInputs)) revert AgeNotProven(MIN_AGE);
        if (EXPIRY_MARGIN != 0) _checkExpiry(committedInputs);
    }

    /// @dev ZKPassport's emergency stops and registrations, read on every call:
    ///      both pauses, the version's sub-verifier, the pinned verifier still
    ///      listed by it, and the pinned helper still registered.
    function _checkLive(bytes32 vkeyHash) private view returns (address verifier) {
        verifier = outerVerifier[vkeyHash];
        if (verifier == address(0)) revert UnknownVerificationKey(vkeyHash);
        if (ROOT_VERIFIER.paused()) revert VerifierPaused(address(ROOT_VERIFIER));
        address sub = ROOT_VERIFIER.getSubVerifier(VERSION);
        if (sub == address(0)) revert NoSubVerifier(VERSION);
        if (IZKPassportSubVerifier(sub).paused()) revert VerifierPaused(sub);
        if (IZKPassportSubVerifier(sub).proofVerifiers(vkeyHash) != verifier) revert OuterVerifierWithdrawn(vkeyHash);
        address helper = ROOT_VERIFIER.getHelper(VERSION);
        if (helper != address(HELPER)) revert HelperMismatch(address(HELPER), helper);
    }

    /// @dev Both registry roots valid at the proof's date, in the root
    ///      registry `RootVerifier` hands its sub-verifiers.
    function _checkRoots(bytes32 certificateRoot, bytes32 circuitRoot, uint256 proofDate) private view {
        IZKPassportRootRegistry registry = IZKPassportRootRegistry(ROOT_VERIFIER.rootRegistry());
        if (!registry.isRootValid(CERTIFICATE_REGISTRY, certificateRoot, proofDate)) revert InvalidCertificateRoot();
        if (!registry.isRootValid(CIRCUIT_REGISTRY, circuitRoot, proofDate)) revert InvalidCircuitRoot();
    }

    /// @dev The expiry section is `[3][0x0010][minDate:8][maxDate:8]`, dates in
    ///      seconds, its upper bound already checked zero by `_screenSections`.
    ///      The helper only answers for the exact committed bound, so the bound
    ///      is read here and the helper confirms it.
    function _checkExpiry(bytes memory ci) private view {
        uint256 earliest = block.timestamp + EXPIRY_MARGIN;
        (bool found, uint256 start) = _section(ci, EXPIRY_DATE);
        if (!found) revert ExpiryNotProven(earliest);
        uint256 minDate;
        for (uint256 j = 0; j < 8; j++) {
            minDate = (minDate << 8) | uint8(ci[start + j]);
        }
        if (minDate < earliest || !HELPER.isExpiryDateAfterOrEqual(minDate, ci)) revert ExpiryNotProven(earliest);
    }

    /// @dev The data offset of the section of `wanted` type. Sections were
    ///      walked and bounded by `_screenSections` already.
    function _section(bytes memory ci, uint8 wanted) private pure returns (bool, uint256) {
        uint256 i = 0;
        while (i + 3 <= ci.length) {
            uint256 len = (uint256(uint8(ci[i + 1])) << 8) | uint256(uint8(ci[i + 2]));
            if (uint8(ci[i]) == wanted) return (true, i + 3);
            i += 3 + len;
        }
        return (false, 0);
    }

    /// @dev Walk the committed inputs, `[type:1][length:2][data:length]` per
    ///      section. Only the age, expiry and bind sections are admitted, each
    ///      at most once and the bind exactly once; the age and the expiry
    ///      carry a lower bound only (an upper bound would close a range on
    ///      the value). Everything else, disclosure, inclusion and exclusion
    ///      lists, sanctions, face match and attested ID, is refused.
    function _screenSections(bytes memory ci) private pure {
        bool age;
        bool expiry;
        uint256 binds;
        uint256 i = 0;
        while (i < ci.length) {
            if (i + 3 > ci.length) revert MalformedCommittedInputs();
            uint8 sectionType = uint8(ci[i]);
            uint256 len = (uint256(uint8(ci[i + 1])) << 8) | uint256(uint8(ci[i + 2]));
            if (i + 3 + len > ci.length) revert MalformedCommittedInputs();
            if (sectionType == AGE) {
                if (age) revert DuplicateSection(AGE);
                age = true;
                if (len != 2) revert MalformedCommittedInputs();
                if (uint8(ci[i + 4]) != 0) revert DisclosureRefused(AGE);
            } else if (sectionType == EXPIRY_DATE) {
                if (expiry) revert DuplicateSection(EXPIRY_DATE);
                expiry = true;
                if (len != 16) revert MalformedCommittedInputs();
                for (uint256 j = 0; j < 8; j++) {
                    if (uint8(ci[i + 11 + j]) != 0) revert DisclosureRefused(EXPIRY_DATE);
                }
            } else if (sectionType == BIND) {
                binds++;
            } else {
                revert SectionRefused(sectionType);
            }
            i += 3 + len;
        }
        if (binds != 1) revert BindSectionCount(binds);
    }
}
