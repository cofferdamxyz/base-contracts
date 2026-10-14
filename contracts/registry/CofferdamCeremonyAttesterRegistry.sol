// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {SelfAttesterRegistry} from "../self/SelfAttesterRegistry.sol";

/// @title CofferdamCeremonyAttesterRegistry
/// @notice Allow-list of the keys that co-sign Cofferdam passkey ceremonies
///         (decision 0016): the first High on a Partner or Managed account
///         (`CofferdamAccount4337.enrollFirstHigh`) and the pre-High Partner
///         re-key (`replacePartnerAuthority`). The plane signs only inside a
///         ceremony on `id.cofferdam.xyz` or in the Cofferdam app opened for
///         that account. No account function accepts the attestation alone,
///         and once High exists it has no path into the account.
/// @dev    The same owner / two-step transfer / add-remove shape and EIP-191
///         `verifyAttesterSig` as `SelfAttesterRegistry`, deployed separately
///         so the ceremony key and the Self bind key never share a list.
///         Owner is the Cofferdam Inc. Safe on mainnet. Removing every attester
///         pauses first-High upgrades and Partner recoveries only.
contract CofferdamCeremonyAttesterRegistry is SelfAttesterRegistry {
    constructor(address _initialOwner, address[] memory _initialAttesters)
        SelfAttesterRegistry(_initialOwner, _initialAttesters)
    {}
}
