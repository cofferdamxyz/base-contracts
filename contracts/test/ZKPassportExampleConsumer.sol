// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IZKPassportHelper, IZKPassportRootVerifier} from "../identity/zkpassport/IZKPassportRootVerifier.sol";

/// @notice The scope check of ZKPassport's helper, which the example calls and
///         `ZKPassportEvidenceAdapter` leaves to `RootVerifier.verify`.
interface IZKPassportHelperScopes {
    function verifyScopes(bytes32[] calldata publicInputs, string calldata domain, string calldata scope)
        external
        view
        returns (bool);
}

/// @title ZKPassportExampleConsumer
/// @notice Test only: the consumer ZKPassport's dashboard offers as its on-chain
///         verification example, check for check, with its constants taken at
///         deployment and Cofferdam's interface declarations in place of
///         ZKPassport's imports. `scripts/identity-bind.ts` runs a real bound
///         proof through it beside the adapter on a fork of Base mainnet, as a
///         reference: both must accept it and return the same identifier.
///         Never deployed on a public network.
contract ZKPassportExampleConsumer {
    IZKPassportRootVerifier public immutable zkPassportVerifier;
    string internal domain;
    string internal scope;
    uint256 public immutable VALIDITY_PERIOD_SECONDS;
    uint8 public immutable MIN_AGE;

    error ZeroAddress();
    error InvalidProof();
    error DevModeNotAllowed();
    error InvalidScope();
    error InvalidBoundAddress();
    error InvalidBoundChainId();
    error InvalidValidityPeriod();
    error InvalidAge();

    constructor(address verifier, string memory domain_, string memory scope_, uint256 validity, uint8 minAge) {
        require(verifier != address(0), ZeroAddress());
        zkPassportVerifier = IZKPassportRootVerifier(verifier);
        domain = domain_;
        scope = scope_;
        VALIDITY_PERIOD_SECONDS = validity;
        MIN_AGE = minAge;
    }

    function verify(IZKPassportRootVerifier.ProofVerificationParams calldata params) public view returns (bytes32) {
        // uniqueIdentifier is stable for the same user, domain and scope
        (bool verified, bytes32 uniqueIdentifier, address helperAddress) = zkPassportVerifier.verify(params);
        require(verified, InvalidProof());

        // Dev mode accepts mock proofs and must stay off
        require(!params.serviceConfig.devMode, DevModeNotAllowed());

        // The proof must have been generated for this app and use case
        require(
            IZKPassportHelperScopes(helperAddress).verifyScopes(params.proofVerificationData.publicInputs, domain, scope),
            InvalidScope()
        );

        // The proof must be bound to the wallet sending this transaction
        IZKPassportHelper helper = IZKPassportHelper(helperAddress);
        IZKPassportHelper.BoundData memory boundData = helper.getBoundData(params.committedInputs);
        require(boundData.senderAddress == msg.sender, InvalidBoundAddress());
        require(boundData.chainId == block.chainid, InvalidBoundChainId());

        require(params.serviceConfig.validityPeriodInSeconds == VALIDITY_PERIOD_SECONDS, InvalidValidityPeriod());

        require(helper.isAgeAboveOrEqual(MIN_AGE, params.committedInputs), InvalidAge());

        return uniqueIdentifier;
    }
}
