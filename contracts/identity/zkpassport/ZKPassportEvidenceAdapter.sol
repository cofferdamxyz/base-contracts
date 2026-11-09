// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {IIdentityEvidenceAdapter} from "../IIdentityEvidenceAdapter.sol";
import {IZKPassportHelper, IZKPassportRootVerifier} from "./IZKPassportRootVerifier.sol";

/// @title ZKPassportEvidenceAdapter
/// @notice Checks a ZKPassport compressed-EVM proof on-chain through
///         ZKPassport's `RootVerifier` (decision 0080, ruling T5) for
///         `CofferdamIdentityRegistry`.
///         - The service configuration is pinned here, never taken from the
///           caller: circuits version, domain `cofferdam.xyz`, scope, a short
///           validity and `devMode` false.
///         - The identifier type is pinned (non-salted or salted, never the
///           mock types or none); a salted adapter also pins the OPRF key the
///           identifiers were derived under, so a key rotation cannot mint a
///           second identifier for one person in the same registry.
///         - The proof's bound data must name the account (`user_address`),
///           this chain (`chain`) and the registry's action digest
///           (`custom_data`, as the lowercase `0x`-prefixed hex string of the
///           32 bytes, 66 characters), decoded by the version's helper. The
///           helper is pinned at deployment: if ZKPassport's admin swaps it,
///           every proof fails until a new adapter passes the registry's
///           timelock. Their sub-verifier cannot be pinned this way.
///         - Exactly one bind section, so the helper cannot pick among several.
///         - The proof must prove the pinned minimum age, and a document expiry
///           at least `EXPIRY_MARGIN` after the bind (decision 0080, 5: an
///           expired document cannot open an account next to its renewal);
///           neither is stored. It must disclose nothing, because calldata is
///           public: no document bytes, no nationality or issuing-country
///           inclusion, no birth-date range, and no upper bound on age or
///           expiry (a range that closes reveals the value).
/// @dev    `evidence` is `abi.encode(bytes32 vkeyHash, bytes proof,
///         bytes32[] publicInputs, bytes committedInputs)`, the fields of
///         SDK 0.19.3's `getSolidityVerifierParameters` that come from the
///         proof. Public inputs of an outer proof: [0] certificate registry
///         root, [1] circuit registry root, [2] proof date, [3] scope, [4]
///         subscope, [5, n-3) parameter commitments, [n-3] identifier type,
///         [n-2] identifier, [n-1] OPRF key hash. `RootVerifier` checks the
///         committed inputs against the parameter commitments and the scopes
///         against the service configuration.
contract ZKPassportEvidenceAdapter is IIdentityEvidenceAdapter {
    /// @notice ZKPassport's verifier on Base mainnet; required on chain 8453.
    address public constant CANONICAL_ROOT_VERIFIER = 0x1D000001000EFD9a6371f4d90bB8920D5431c0D8;
    uint256 public constant BASE_MAINNET_CHAIN_ID = 8453;
    string public constant DOMAIN = "cofferdam.xyz";
    bool public constant DEV_MODE = false;
    /// @notice Ceiling on `VALIDITY`: a proof older than this never binds.
    uint256 public constant MAX_VALIDITY = 1 days;

    /// @notice ZKPassport's identifier types: 0 non-salted, 1 salted, 2 and 3
    ///         their mocks, 4 none. Only 0 and 1 are accepted.
    uint8 public constant NON_SALTED = 0;
    uint8 public constant SALTED = 1;

    /// @notice Committed-input section types this adapter refuses: they put
    ///         document bytes, a nationality or an issuing country in calldata.
    uint8 private constant DISCLOSE = 0;
    uint8 private constant AGE = 1;
    uint8 private constant BIRTHDATE = 2;
    uint8 private constant EXPIRY_DATE = 3;
    uint8 private constant BIND = 8;
    uint8 private constant NATIONALITY_INCLUSION = 4;
    uint8 private constant ISSUING_COUNTRY_INCLUSION = 6;

    IZKPassportRootVerifier public immutable ROOT_VERIFIER;
    /// @notice The version's helper when this adapter was deployed; it decides
    ///         the bound account, chain and digest, so it is pinned.
    IZKPassportHelper public immutable HELPER;
    /// @notice Circuits version as ZKPassport encodes it: three big-endian
    ///         uint16 parts, then zeros (0.21.1 is `0x000000150001` padded).
    bytes32 public immutable VERSION;
    uint256 public immutable VALIDITY;
    uint8 public immutable IDENTIFIER_TYPE;
    /// @notice The OPRF key hash salted identifiers must carry; 0 for non-salted.
    bytes32 public immutable OPRF_KEY_HASH;
    /// @notice Minimum age the proof must prove; 0 checks none. The proof's
    ///         lower bound must be exactly this (the helper's comparison).
    uint8 public immutable MIN_AGE;
    /// @notice Seconds the document must stay valid after the bind; 0 checks
    ///         none. The proof's committed lower bound on the expiry date must
    ///         be at least `block.timestamp + EXPIRY_MARGIN`, with no upper bound.
    uint256 public immutable EXPIRY_MARGIN;
    /// @notice Ceiling on `EXPIRY_MARGIN`.
    uint256 public constant MAX_EXPIRY_MARGIN = 5 * 365 days;

    bytes32 private immutable _identifierKind;
    bytes32 private immutable _scopeId;
    string private _scope;

    error ZeroAddress();
    error NotCanonicalVerifier(address got);
    error ZeroVersion();
    error EmptyScope();
    error BadValidity(uint256 validity);
    error BadIdentifierType(uint8 identifierType);
    error BadOprfKeyHash();
    error BadMinAge(uint8 minAge);
    error MalformedEvidence();
    error WrongIdentifierType(uint256 expected, uint256 got);
    error WrongOprfKey(bytes32 expected, bytes32 got);
    error ProofInvalid();
    error IdentifierMismatch(bytes32 verified, bytes32 publicInput);
    error HelperMismatch(address expected, address got);
    error WrongBoundAccount(address expected, address got);
    error WrongBoundChain(uint256 expected, uint256 got);
    error WrongBoundDigest();
    error AgeNotProven(uint8 minAge);
    error BadExpiryMargin(uint256 margin);
    error ExpiryNotProven(uint256 earliest);
    error DisclosureRefused(uint8 sectionType);
    error MalformedCommittedInputs();
    error BindSectionCount(uint256 count);

    /// @param rootVerifier ZKPassport's `RootVerifier`; must be canonical on Base mainnet.
    /// @param helper The helper `rootVerifier` names for `version` now; checked here.
    /// @param version The circuits version the proofs must be made with.
    /// @param scope_ The ZKPassport scope, for example `cofferdam-zkp-test-1` (T1).
    /// @param validity Seconds a proof stays usable after its date, at most `MAX_VALIDITY`.
    /// @param identifierType `NON_SALTED` or `SALTED`.
    /// @param oprfKeyHash Required for salted identifiers, 0 otherwise.
    /// @param minAge The age the proof must prove (18 for Cofferdam); 0 checks none.
    /// @param expiryMargin Seconds the document must stay valid after the bind; 0 checks none.
    constructor(
        address rootVerifier,
        address helper,
        bytes32 version,
        string memory scope_,
        uint256 validity,
        uint8 identifierType,
        bytes32 oprfKeyHash,
        uint8 minAge,
        uint256 expiryMargin
    ) {
        if (rootVerifier == address(0)) revert ZeroAddress();
        if (block.chainid == BASE_MAINNET_CHAIN_ID && rootVerifier != CANONICAL_ROOT_VERIFIER) {
            revert NotCanonicalVerifier(rootVerifier);
        }
        if (version == bytes32(0)) revert ZeroVersion();
        if (helper == address(0) || IZKPassportRootVerifier(rootVerifier).getHelper(version) != helper) {
            revert HelperMismatch(IZKPassportRootVerifier(rootVerifier).getHelper(version), helper);
        }
        if (bytes(scope_).length == 0) revert EmptyScope();
        if (validity == 0 || validity > MAX_VALIDITY) revert BadValidity(validity);
        if (identifierType != NON_SALTED && identifierType != SALTED) revert BadIdentifierType(identifierType);
        if ((identifierType == SALTED) != (oprfKeyHash != bytes32(0))) revert BadOprfKeyHash();
        if (minAge > 100) revert BadMinAge(minAge);
        if (expiryMargin > MAX_EXPIRY_MARGIN) revert BadExpiryMargin(expiryMargin);

        ROOT_VERIFIER = IZKPassportRootVerifier(rootVerifier);
        HELPER = IZKPassportHelper(helper);
        VERSION = version;
        VALIDITY = validity;
        IDENTIFIER_TYPE = identifierType;
        OPRF_KEY_HASH = oprfKeyHash;
        MIN_AGE = minAge;
        EXPIRY_MARGIN = expiryMargin;
        _scope = scope_;
        _identifierKind = keccak256(abi.encode("zkpassport-identifier-v1", identifierType, oprfKeyHash));
        _scopeId = keccak256(abi.encode(DOMAIN, scope_));
    }

    function scope() external view returns (string memory) {
        return _scope;
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
        if (n < 8) revert MalformedEvidence();

        uint256 idType = uint256(publicInputs[n - 3]);
        if (idType != IDENTIFIER_TYPE) revert WrongIdentifierType(IDENTIFIER_TYPE, idType);
        if (IDENTIFIER_TYPE == SALTED && publicInputs[n - 1] != OPRF_KEY_HASH) {
            revert WrongOprfKey(OPRF_KEY_HASH, publicInputs[n - 1]);
        }

        IZKPassportRootVerifier.ProofVerificationParams memory params = IZKPassportRootVerifier.ProofVerificationParams({
            version: VERSION,
            proofVerificationData: IZKPassportRootVerifier.ProofVerificationData({
                vkeyHash: vkeyHash,
                proof: proof,
                publicInputs: publicInputs
            }),
            committedInputs: committedInputs,
            serviceConfig: IZKPassportRootVerifier.ServiceConfig({
                validityPeriodInSeconds: VALIDITY,
                domain: DOMAIN,
                scope: _scope,
                devMode: DEV_MODE
            })
        });
        (bool valid, bytes32 uniqueIdentifier, address helper) = ROOT_VERIFIER.verify(params);
        if (!valid) revert ProofInvalid();
        if (uniqueIdentifier != publicInputs[n - 2]) revert IdentifierMismatch(uniqueIdentifier, publicInputs[n - 2]);

        // Fail closed when ZKPassport swaps the helper of this version.
        if (helper != address(HELPER) || ROOT_VERIFIER.getHelper(VERSION) != address(HELPER)) {
            revert HelperMismatch(address(HELPER), helper);
        }
        _screenSections(committedInputs);

        IZKPassportHelper.BoundData memory bound = HELPER.getBoundData(committedInputs);
        if (bound.senderAddress != account) revert WrongBoundAccount(account, bound.senderAddress);
        if (bound.chainId != block.chainid) revert WrongBoundChain(block.chainid, bound.chainId);
        if (keccak256(bytes(bound.customData)) != keccak256(bytes(customData(digest)))) revert WrongBoundDigest();

        if (MIN_AGE != 0 && !HELPER.isAgeAboveOrEqual(MIN_AGE, committedInputs)) revert AgeNotProven(MIN_AGE);
        if (EXPIRY_MARGIN != 0) _checkExpiry(committedInputs);
        return uniqueIdentifier;
    }

    /// @dev The expiry section is `[3][0x0010][minDate:8][maxDate:8]`, dates in
    ///      seconds. The helper only answers for the exact committed bound, so
    ///      the bound is read here and the helper confirms it.
    function _checkExpiry(bytes memory ci) private view {
        uint256 earliest = block.timestamp + EXPIRY_MARGIN;
        (bool found, uint256 start, uint256 len) = _section(ci, EXPIRY_DATE);
        if (!found || len != 16) revert ExpiryNotProven(earliest);
        uint256 minDate;
        uint256 maxDate;
        for (uint256 j = 0; j < 8; j++) {
            minDate = (minDate << 8) | uint8(ci[start + j]);
            maxDate = (maxDate << 8) | uint8(ci[start + 8 + j]);
        }
        if (maxDate != 0 || minDate < earliest || !HELPER.isExpiryDateAfterOrEqual(minDate, ci)) {
            revert ExpiryNotProven(earliest);
        }
    }

    /// @dev The first section of `wanted` type: its data offset and length.
    function _section(bytes memory ci, uint8 wanted) private pure returns (bool, uint256, uint256) {
        uint256 i = 0;
        while (i + 3 <= ci.length) {
            uint256 len = (uint256(uint8(ci[i + 1])) << 8) | uint256(uint8(ci[i + 2]));
            if (uint8(ci[i]) == wanted) {
                if (i + 3 + len > ci.length) revert MalformedCommittedInputs();
                return (true, i + 3, len);
            }
            i += 3 + len;
        }
        return (false, 0, 0);
    }

    /// @dev Walk the committed inputs, `[type:1][length:2][data:length]` per
    ///      section: exactly one bind section, and nothing that discloses.
    function _screenSections(bytes memory ci) private pure {
        uint256 binds = 0;
        uint256 i = 0;
        while (i < ci.length) {
            if (i + 3 > ci.length) revert MalformedCommittedInputs();
            uint8 sectionType = uint8(ci[i]);
            uint256 len = (uint256(uint8(ci[i + 1])) << 8) | uint256(uint8(ci[i + 2]));
            if (i + 3 + len > ci.length) revert MalformedCommittedInputs();
            if (
                sectionType == DISCLOSE || sectionType == BIRTHDATE || sectionType == NATIONALITY_INCLUSION
                    || sectionType == ISSUING_COUNTRY_INCLUSION
            ) revert DisclosureRefused(sectionType);
            // An upper bound turns a predicate into a range that can close on the value.
            if (sectionType == AGE && (len != 2 || uint8(ci[i + 4]) != 0)) revert DisclosureRefused(sectionType);
            if (sectionType == EXPIRY_DATE) {
                if (len != 16) revert MalformedCommittedInputs();
                for (uint256 j = 0; j < 8; j++) {
                    if (uint8(ci[i + 11 + j]) != 0) revert DisclosureRefused(sectionType);
                }
            }
            if (sectionType == BIND) binds++;
            i += 3 + len;
        }
        if (binds != 1) revert BindSectionCount(binds);
    }
}
